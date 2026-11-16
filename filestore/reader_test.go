package filestore

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/tally"
)

// mutateFile applies f to the bytes of name in dir.
func mutateFile(t *testing.T, dir, name string, f func([]byte) []byte) {
	t.Helper()
	path := filepath.Join(dir, name)
	b, err := os.ReadFile(path) // #nosec G304 -- a test's own file
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, f(b))
}

// A Reader over a sound log verifies it exactly as the Store does.
func TestAReaderVerifiesASoundLog(t *testing.T) {
	dir := writeVectorLog(t)
	r, err := OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := tally.Verify(t.Context(), r, verifiers(t), tally.WithRequireFullyAttested())
	if err != nil || !rep.OK() || rep.Size != 5 {
		t.Fatalf("Verify = %v, %+v; want OK with 5 leaves", err, rep)
	}
}

// Each way stored bytes can break SPEC §3 is a MalformedRecord violation at
// the first leaf not verified, with Size the verified prefix: never the
// error that means "could not verify" (RS-04, #93). The log is records.json in
// segment 0, then the header-only segment 5.
//
// Seen failing with the MalformedError conversion removed from Verify's
// record loop: every case then returns an error instead of a report.
func TestFormatViolationsAreReported(t *testing.T) {
	_, frameAt := fiveRecords(t)
	seg0, seg5 := segmentName(0), segmentName(5)
	rename := func(from, to string) func(t *testing.T, dir string) {
		return func(t *testing.T, dir string) {
			t.Helper()
			if err := os.Rename(filepath.Join(dir, from), filepath.Join(dir, to)); err != nil {
				t.Fatal(err)
			}
		}
	}
	mutate := func(name string, f func([]byte) []byte) func(t *testing.T, dir string) {
		return func(t *testing.T, dir string) {
			t.Helper()
			mutateFile(t, dir, name, f)
		}
	}
	cases := []struct {
		name   string
		break_ func(t *testing.T, dir string)
		at     uint64 // the violation's leaf, which is also Size
	}{
		{"the genesis segment's magic", mutate(seg0, func(b []byte) []byte { b[0] ^= 1; return b }), 0},
		{"a later segment's version", mutate(seg5, func(b []byte) []byte { b[8] = 2; return b }), 5},
		{"a header cut off", mutate(seg5, func(b []byte) []byte { return b[:20] }), 5},
		{"a name that differs from first_seq", rename(seg5, segmentName(6)), 5},
		{"a name in uppercase", rename(seg5, "000000000000000A.tlog"), 5},
		{"another log_id", mutate(seg5, func(b []byte) []byte { b[12] ^= 1; return b }), 5},
		{"a broken prev_hash", mutate(seg5, func(b []byte) []byte { b[segmentHeaderLen-1] ^= 1; return b }), 5},
		{"a CRC mismatch", mutate(seg0, func(b []byte) []byte { b[frameAt[2]+6] ^= 1; return b }), 2},
		{"a frame over the ceiling", mutate(seg0, func(b []byte) []byte {
			binary.BigEndian.PutUint32(b[frameAt[3]:], tally.MaxRecordLen+1)
			return b
		}), 3},
		{"a short tail in the last segment", mutate(seg5, func(b []byte) []byte { return append(b, 0, 0) }), 5},
		{"a short frame in an earlier segment", mutate(seg0, func(b []byte) []byte { return b[:len(b)-1] }), 4},
	}
	ran := 0
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ran++
			dir := writeVectorLog(t)
			c.break_(t, dir)
			r, err := OpenReader(dir)
			if err != nil {
				t.Fatal(err)
			}
			rep, err := tally.Verify(t.Context(), r, verifiers(t))
			if err != nil {
				t.Fatalf("Verify = %v; want a report", err)
			}
			if rep.OK() || rep.Size != c.at || !slices.ContainsFunc(rep.Failures, func(f tally.Failure) bool {
				return f.Kind == tally.MalformedRecord && f.Seq == c.at
			}) {
				t.Fatalf("Verify = %+v; want MalformedRecord at leaf %d and Size %d", rep, c.at, c.at)
			}
		})
	}
	if ran != len(cases) || ran == 0 {
		t.Fatalf("ran %d cases, want %d", ran, len(cases))
	}
}

// A malformed checkpoints file is a violation too, and the checkpoints before
// the bad frame still count.
//
// Seen failing with the MalformedError conversion removed from Verify's
// checkpoint loop.
func TestAMalformedCheckpointsFileIsReported(t *testing.T) {
	dir := writeVectorLog(t)
	s := mustOpen(t, dir)
	if err := s.PutCheckpoint(t.Context(), vectorCheckpoint(t)); err != nil { // a second one
		t.Fatal(err)
	}
	_ = s.Close()
	mutateFile(t, dir, checkpointsName, func(b []byte) []byte { b[len(b)-6] ^= 1; return b })

	r, err := OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := tally.Verify(t.Context(), r, verifiers(t))
	if err != nil {
		t.Fatalf("Verify = %v; want a report", err)
	}
	if rep.OK() || rep.AttestedSize != 5 || !slices.ContainsFunc(rep.Failures, func(f tally.Failure) bool {
		return f.Kind == tally.MalformedRecord && strings.HasPrefix(f.Note, "checkpoints: ")
	}) {
		t.Fatalf("Verify = %+v; want a checkpoints MalformedRecord, the first checkpoint still matched", rep)
	}
}

// An IO failure is still Verify's error, never a report (RS-04).
//
// Seen failing with isFormat made to accept every error.
func TestAnIOErrorIsNotAViolation(t *testing.T) {
	dir := writeVectorLog(t)
	fsys := newRecFS()
	r, err := openReader(fsys, dir)
	if err != nil {
		t.Fatal(err)
	}
	// Learn where the segment is opened, then fail exactly that open.
	fsys.reset(-1)
	if _, err = tally.Verify(t.Context(), r, verifiers(t)); err != nil {
		t.Fatal(err)
	}
	at := slices.Index(fsys.ops, "read "+segmentName(0))
	if at < 0 {
		t.Fatalf("no read of segment 0 in %q", fsys.ops)
	}
	fsys.reset(at)
	rep, err := tally.Verify(t.Context(), r, verifiers(t))
	if !errors.Is(err, errInjected) || rep != nil {
		t.Fatalf("Verify = %+v, %v; want the injected IO error", rep, err)
	}
}

// A Reader never writes: no lock, no recovery, nothing created, written,
// renamed or removed, even over a log that the Store would recover.
//
// Seen failing with the Reader built on Open instead of openReader.
func TestAReaderNeverWrites(t *testing.T) {
	dir := writeVectorLog(t)
	mutateFile(t, dir, segmentName(5), func(b []byte) []byte { return append(b, 1, 2, 3) })
	before := snap(t, dir)
	fsys := newRecFS()
	r, err := openReader(fsys, dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tally.Verify(t.Context(), r, verifiers(t)); err != nil {
		t.Fatal(err)
	}
	for _, op := range fsys.ops {
		verb := op[:strings.IndexByte(op, ' ')]
		if verb != "read" && verb != "readdir" && verb != "stat" && verb != "close" {
			t.Errorf("a Reader did %q", op)
		}
	}
	if !maps(snap(t, dir), before) {
		t.Error("reading changed the directory")
	}
}
