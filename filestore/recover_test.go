package filestore

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/JonasBorgesLM/tally"
)

// snapshot is every file in a directory except the lock, by name.
type snapshot map[string][]byte

func snap(t *testing.T, dir string) snapshot {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	s := snapshot{}
	for _, e := range entries {
		if e.Name() == lockName {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name())) // #nosec G304 -- a test's own file
		if err != nil {
			t.Fatal(err)
		}
		s[e.Name()] = b
	}
	return s
}

func (s snapshot) quarantined() map[string][]byte {
	q := map[string][]byte{}
	for name, b := range s {
		if strings.HasPrefix(name, "quarantine-") {
			q[name] = b
		}
	}
	return q
}

func writeFile(t *testing.T, name string, b []byte) {
	t.Helper()
	if err := os.WriteFile(name, b, 0o600); err != nil { // #nosec G703 -- a test's own file
		t.Fatal(err)
	}
}

// fiveRecords writes records.json to a new log, with no checkpoint, and
// returns the directory and the byte offset where each frame starts, plus the
// end of the last one.
func fiveRecords(t *testing.T) (dir string, frameAt []int64) {
	t.Helper()
	dir = logDir(t)
	s := mustOpen(t, dir)
	if err := s.AppendBatch(context.Background(), records(vectorBodies(t), 0)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	off := int64(segmentHeaderLen)
	for _, b := range vectorBodies(t) {
		frameAt = append(frameAt, off)
		off += int64(frameOverhead + len(b))
	}
	return dir, append(frameAt, off)
}

// Each tail state of SPEC §3.3 on the last segment: a short or bad tail is
// moved, byte for byte, to a quarantine file named for the segment and the
// offset, the segment is truncated to its last good frame, and Recovered
// counts the bytes (RF-20). A bad middle refuses to open and changes nothing.
//
// Seen failing with the quarantine write removed from recoverTail, with the
// bad-middle check in classify reduced to "bad tail", with the scan for a
// frame after a cut-off one removed (Open accepted the changed length), and
// with the zero-length check removed from readFrame (4096 zeros read as 512
// frames: nothing recovered, 517 records).
func TestTailStates(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(b []byte, frameAt []int64) []byte
		keep   int // records left; -1 means Open must refuse
	}{
		{"clean", func(b []byte, _ []int64) []byte { return b }, 5},
		{"short: cut inside the CRC", func(b []byte, _ []int64) []byte { return b[:len(b)-1] }, 4},
		{"short: cut inside the length", func(b []byte, at []int64) []byte { return b[:at[4]+2] }, 4},
		{"short: cut inside the body", func(b []byte, at []int64) []byte { return b[:at[4]+10] }, 4},
		{"short: a stray byte after the last frame", func(b []byte, _ []int64) []byte { return append(b, 0) }, 5},
		{"short: a length and nothing more", func(b []byte, _ []int64) []byte { return binary.BigEndian.AppendUint32(b, 40) }, 5},
		{"bad tail: a flipped bit in the last frame", func(b []byte, _ []int64) []byte { b[len(b)-6] ^= 1; return b }, 4},
		{"bad middle: a flipped bit in an earlier frame", func(b []byte, at []int64) []byte { b[at[2]+6] ^= 1; return b }, -1},
		{"bad middle: a length over the ceiling at the tail", func(b []byte, _ []int64) []byte {
			return binary.BigEndian.AppendUint32(b, tally.MaxRecordLen+1)
		}, -1},
		// A length changed to run past the end, with acknowledged frames after
		// it: not a torn write, and truncating would drop them (A-02, #127).
		{"bad middle: a length running past the end, frames after it", func(b []byte, at []int64) []byte {
			binary.BigEndian.PutUint32(b[at[2]:], uint32(len(b))) // #nosec G115 -- a small test file
			return b
		}, -1},
		// Zeros past the last frame, as a crash can leave: a zero length with the
		// CRC of nothing is not a frame (#127).
		{"short: zeros after the last frame", func(b []byte, _ []int64) []byte { return append(b, make([]byte, 4096)...) }, 5},
		{"short: zeros, then a cut-off frame", func(b []byte, at []int64) []byte {
			return append(append(b, make([]byte, 64)...), b[at[0]:at[0]+10]...)
		}, 5},
	}
	ran := 0
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ran++
			dir, frameAt := fiveRecords(t)
			seg0 := filepath.Join(dir, segmentName(0))
			orig, err := os.ReadFile(seg0) // #nosec G304 -- a test's own file
			if err != nil {
				t.Fatal(err)
			}
			mutated := c.mutate(slices.Clone(orig), frameAt)
			writeFile(t, seg0, mutated)
			before := snap(t, dir)

			s, err := Open(context.Background(), dir)
			if c.keep < 0 {
				if err == nil {
					_ = s.Close()
					t.Fatal("Open accepted a bad middle")
				}
				if after := snap(t, dir); !maps(after, before) {
					t.Error("a refused Open changed the directory")
				}
				return
			}
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer func() { _ = s.Close() }()

			end := frameAt[c.keep]
			after := snap(t, dir)
			if !bytes.Equal(after[segmentName(0)], mutated[:end]) {
				t.Errorf("segment is %d bytes, want the %d before the bad tail", len(after[segmentName(0)]), end)
			}
			q := after.quarantined()
			removed := mutated[end:]
			if len(removed) == 0 {
				if len(q) != 0 || s.Recovered() != 0 {
					t.Errorf("a clean tail quarantined %v, Recovered %d", q, s.Recovered())
				}
				return
			}
			want := fmt.Sprintf("quarantine-%016x-%016x.bin", 0, end)
			if len(q) != 1 || !bytes.Equal(q[want], removed) {
				t.Errorf("quarantine %v, want %s holding the %d removed bytes", keys(q), want, len(removed))
			}
			if s.Recovered() != int64(len(removed)) {
				t.Errorf("Recovered = %d, want %d", s.Recovered(), len(removed))
			}
			n := 0
			for _, err := range s.Records(context.Background(), 0) {
				if err != nil {
					t.Fatal(err)
				}
				n++
			}
			if n != c.keep {
				t.Errorf("%d records after recovery, want %d", n, c.keep)
			}
		})
	}
	if ran != len(cases) || ran == 0 {
		t.Fatalf("ran %d cases, want %d", ran, len(cases))
	}
}

func maps(a, b snapshot) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if !bytes.Equal(v, b[k]) {
			return false
		}
	}
	return true
}

func keys(m map[string][]byte) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	slices.Sort(ks)
	return ks
}

// Recovery never truncates below the last stored checkpoint: when the record
// it would remove is one the checkpoint covers, or the log already lacks one,
// Open refuses and changes nothing (RF-20, SPEC §3.3, T-22). A tail past the
// checkpoint is still recovered.
//
// Seen failing with the floor check removed from load.
func TestNeverBelowTheLastCheckpoint(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(b []byte, frameAt []int64) []byte
		refused bool
	}{
		{"a bad tail in a covered record", func(b []byte, _ []int64) []byte { b[len(b)-6] ^= 1; return b }, true},
		{"a short tail in a covered record", func(b []byte, _ []int64) []byte { return b[:len(b)-1] }, true},
		{"a covered record missing, ending cleanly", func(b []byte, at []int64) []byte { return b[:at[4]] }, true},
		{"a short tail past the checkpoint", func(b []byte, _ []int64) []byte { return append(b, 0, 0) }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir, frameAt := fiveRecords(t)
			s := mustOpen(t, dir)
			if err := s.PutCheckpoint(context.Background(), vectorCheckpoint(t)); err != nil { // size 5
				t.Fatal(err)
			}
			_ = s.Close()
			seg0 := filepath.Join(dir, segmentName(0))
			b, err := os.ReadFile(seg0) // #nosec G304 -- a test's own file
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, seg0, c.mutate(b, frameAt))
			before := snap(t, dir)

			s, err = Open(context.Background(), dir)
			if !c.refused {
				if err != nil {
					t.Fatalf("Open: %v", err)
				}
				_ = s.Close()
				return
			}
			if !errors.Is(err, errBelowCheckpoint) {
				t.Fatalf("Open = %v, want errBelowCheckpoint", err)
			}
			if !maps(snap(t, dir), before) {
				t.Error("a refused Open changed the directory")
			}
		})
	}
}

// A crash while creating a segment leaves it shorter than its header. It
// holds no record, so it is quarantined whole and removed, and the log goes
// on from the previous segment, verifying (SPEC §3, §3.3).
//
// Seen failing with the tailNoHeader case removed from classify.
func TestAPartialSegmentHeaderIsQuarantined(t *testing.T) {
	for _, keep := range []int{0, 30, segmentHeaderLen - 1} {
		t.Run(fmt.Sprint(keep), func(t *testing.T) {
			dir := writeVectorLog(t) // segments 0 and 5, segment 5 header only
			seg5 := filepath.Join(dir, segmentName(5))
			b, err := os.ReadFile(seg5) // #nosec G304 -- a test's own file
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, seg5, b[:keep])

			s := mustOpen(t, dir)
			after := snap(t, dir)
			if _, ok := after[segmentName(5)]; ok {
				t.Error("the partial segment is still there")
			}
			q := after.quarantined()
			want := fmt.Sprintf("quarantine-%016x-%016x.bin", 5, 0)
			if len(q) != 1 || !bytes.Equal(q[want], b[:keep]) {
				t.Errorf("quarantine %v, want %s holding %d bytes", keys(q), want, keep)
			}
			if s.Recovered() != int64(keep) {
				t.Errorf("Recovered = %d, want %d", s.Recovered(), keep)
			}
			_ = s.Close()

			// The log goes on, and verifies whole.
			s = mustOpen(t, dir)
			l, err := tally.Open(context.Background(), s, signer(t), tally.WithCheckpointEvery(0, 0))
			if err != nil {
				t.Fatalf("tally.Open: %v", err)
			}
			if _, err = l.Append(context.Background(), event("after")); err != nil {
				t.Fatal(err)
			}
			if err = l.Close(); err != nil {
				t.Fatal(err)
			}
			s = mustOpen(t, dir)
			defer func() { _ = s.Close() }()
			rep, err := tally.Verify(context.Background(), s, verifiers(t), tally.WithRequireFullyAttested())
			if err != nil || !rep.OK() || rep.Size != 6 {
				t.Fatalf("Verify = %v, %+v; want OK with 6 leaves", err, rep)
			}
		})
	}
}

// A partial genesis segment, with nothing else, leaves an empty log; a
// partial genesis beside a checkpoints file is refused, since no checkpoint
// is written before the genesis is durable.
func TestAPartialGenesis(t *testing.T) {
	dir := logDir(t)
	s := mustOpen(t, dir)
	_ = s.Close()
	writeFile(t, filepath.Join(dir, segmentName(0)), []byte("TALLYL"))

	s = mustOpen(t, dir)
	if s.Recovered() != 6 || len(snap(t, dir).quarantined()) != 1 {
		t.Fatalf("Recovered = %d, quarantine %v", s.Recovered(), keys(snap(t, dir).quarantined()))
	}
	if err := s.AppendBatch(context.Background(), records(vectorBodies(t)[:1], 0)); err != nil {
		t.Fatalf("a new genesis after recovery: %v", err)
	}
	_ = s.Close()

	dir = writeVectorLog(t)
	if err := os.Remove(filepath.Join(dir, segmentName(5))); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, segmentName(0)), []byte("TALLYL"))
	if _, err := Open(context.Background(), dir); err == nil {
		t.Fatal("Open accepted a partial genesis beside a checkpoints file")
	}
}

// The checkpoints file's tail is recovered as a segment's is (SPEC §3.4): a
// partial header removes it, a short tail is quarantined, a bad middle
// refuses.
func TestCheckpointsFileTail(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(b []byte) []byte
		left    int // checkpoints left; -1 means Open must refuse
		removed bool
	}{
		{"a partial header", func(b []byte) []byte { return b[:4] }, 0, true},
		{"a short tail", func(b []byte) []byte { return b[:len(b)-3] }, 1, false},
		{"a bad tail", func(b []byte) []byte { b[len(b)-6] ^= 1; return b }, 1, false},
		{"a bad middle", func(b []byte) []byte { b[checkpointsHeaderLen+6] ^= 1; return b }, -1, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := writeVectorLog(t)
			s := mustOpen(t, dir)
			if err := s.PutCheckpoint(context.Background(), vectorCheckpoint(t)); err != nil { // a second one
				t.Fatal(err)
			}
			_ = s.Close()
			name := filepath.Join(dir, checkpointsName)
			b, err := os.ReadFile(name) // #nosec G304 -- a test's own file
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, name, c.mutate(b))

			s, err = Open(context.Background(), dir)
			if c.left < 0 {
				if err == nil {
					_ = s.Close()
					t.Fatal("Open accepted a bad middle in the checkpoints file")
				}
				return
			}
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer func() { _ = s.Close() }()
			n := 0
			for _, err := range s.Checkpoints(context.Background()) {
				if err != nil {
					t.Fatal(err)
				}
				n++
			}
			if n != c.left {
				t.Errorf("%d checkpoints after recovery, want %d", n, c.left)
			}
			if _, ok := snap(t, dir)[checkpointsName]; ok == c.removed {
				t.Errorf("checkpoints file present = %v, want %v", ok, !c.removed)
			}
			if len(snap(t, dir).quarantined()) != 1 {
				t.Errorf("quarantine %v, want one file", keys(snap(t, dir).quarantined()))
			}
			// A checkpoint can be stored again.
			if err := s.PutCheckpoint(context.Background(), vectorCheckpoint(t)); err != nil {
				t.Errorf("PutCheckpoint after recovery: %v", err)
			}
		})
	}
}

// A second recovery at the same offset does not overwrite the first one's
// quarantine: both are preserved (RF-20).
//
// Seen failing with the retry on fs.ErrExist removed from writeQuarantine.
func TestQuarantineNeverOverwrites(t *testing.T) {
	dir, _ := fiveRecords(t)
	seg0 := filepath.Join(dir, segmentName(0))
	b, err := os.ReadFile(seg0) // #nosec G304 -- a test's own file
	if err != nil {
		t.Fatal(err)
	}
	end := int64(len(b))
	first := filepath.Join(dir, quarantineName(segmentName(0), end, 0))
	writeFile(t, first, []byte("an earlier recovery"))
	writeFile(t, seg0, append(b, 1, 2, 3))

	s := mustOpen(t, dir)
	_ = s.Close()
	q := snap(t, dir).quarantined()
	if string(q[filepath.Base(first)]) != "an earlier recovery" {
		t.Error("the earlier quarantine was changed")
	}
	if !bytes.Equal(q[quarantineName(segmentName(0), end, 1)], []byte{1, 2, 3}) {
		t.Errorf("quarantine %v, want the new bytes under the -1 name", keys(q))
	}
}

// The quarantine is durable, file and directory, before any byte is removed
// (RF-20): a crash in between leaves the bytes in both places, never in
// neither.
//
// Seen failing with the truncation moved before writeQuarantine.
func TestQuarantineIsDurableBeforeTruncating(t *testing.T) {
	dir, _ := fiveRecords(t)
	seg0 := filepath.Join(dir, segmentName(0))
	b, err := os.ReadFile(seg0) // #nosec G304 -- a test's own file
	if err != nil {
		t.Fatal(err)
	}
	end := int64(len(b))
	writeFile(t, seg0, append(b, 9, 9))

	r := newRecFS()
	s := mustOpen(t, dir, withFS(r))
	_ = s.Close()
	q := quarantineName(segmentName(0), end, 0)
	seg := segmentName(0)
	idx := func(op string) int {
		i := slices.Index(r.ops, op)
		if i < 0 {
			t.Fatalf("no %q in %q", op, r.ops)
		}
		return i
	}
	order := []string{"create " + q, "write " + q, "sync " + q, "sync log", "truncate " + seg}
	for i := 1; i < len(order); i++ {
		if idx(order[i-1]) > idx(order[i]) {
			t.Errorf("%q came after %q: %q", order[i-1], order[i], r.ops)
		}
	}
	if i := slices.Index(r.ops[idx("truncate "+seg):], "sync "+seg); i < 0 {
		t.Errorf("the truncated segment is never synced: %q", r.ops)
	}
}

// A fault at any operation of a recovery fails Open or leaves it done, and
// no byte is ever lost: whatever the segment no longer holds is in a
// quarantine file (RF-20).
func TestAFaultDuringRecoveryLosesNothing(t *testing.T) {
	setup := func(t *testing.T) (dir string, mutated []byte) {
		t.Helper()
		dir, _ = fiveRecords(t)
		seg0 := filepath.Join(dir, segmentName(0))
		b, err := os.ReadFile(seg0) // #nosec G304 -- a test's own file
		if err != nil {
			t.Fatal(err)
		}
		b[len(b)-6] ^= 1 // a bad tail: the last frame is quarantined
		writeFile(t, seg0, b)
		return dir, b
	}

	dir, _ := setup(t)
	r := newRecFS()
	s := mustOpen(t, dir, withFS(r))
	_ = s.Close()
	total := len(r.ops)

	ran := 0
	for i := range total {
		t.Run(fmt.Sprintf("%d %s", i, r.ops[i]), func(t *testing.T) {
			ran++
			dir, mutated := setup(t)
			fr := newRecFS()
			fr.reset(i)
			s, err := Open(context.Background(), dir, withFS(fr))
			if err == nil {
				_ = s.Close()
			}
			after := snap(t, dir)
			seg := after[segmentName(0)]
			if !bytes.HasPrefix(mutated, seg) {
				t.Fatalf("the segment is no longer a prefix of what it held")
			}
			lost := mutated[len(seg):]
			if len(lost) == 0 {
				return
			}
			for _, q := range after.quarantined() {
				if bytes.Equal(q, lost) {
					return
				}
			}
			t.Errorf("fault at %q: %d bytes removed and in no quarantine file", fr.ops[len(fr.ops)-1], len(lost))
		})
	}
	if ran != total || ran == 0 {
		t.Fatalf("ran %d faults, want %d", ran, total)
	}
}

type recoveredObserver struct{ got []int64 }

func (*recoveredObserver) Batch(int, time.Duration)      {}
func (*recoveredObserver) AnchorPublish(error, uint64)   {}
func (*recoveredObserver) DiskSpace(uint64)              {}
func (*recoveredObserver) ClockRegression(time.Duration) {}
func (*recoveredObserver) Poisoned(error)                {}
func (o *recoveredObserver) Recovered(n int64)           { o.got = append(o.got, n) }

// tally.Open reports a filestore's recovery through Observer.Recovered, once,
// and not at all when nothing was recovered (RF-20).
//
// Seen failing with the RecoveryReporter check removed from tally.Open.
func TestTallyOpenReportsRecovery(t *testing.T) {
	open := func(dir string) []int64 {
		t.Helper()
		o := &recoveredObserver{}
		l, err := tally.Open(context.Background(), mustOpen(t, dir), signer(t),
			tally.WithObserver(o), tally.WithCheckpointEvery(0, 0))
		if err != nil {
			t.Fatalf("tally.Open: %v", err)
		}
		if err := l.Close(); err != nil {
			t.Fatal(err)
		}
		return o.got
	}
	dir, _ := fiveRecords(t)
	if got := open(dir); len(got) != 0 {
		t.Errorf("a clean open reported %v", got)
	}
	seg0 := filepath.Join(dir, segmentName(0))
	appendToFile(t, seg0, []byte{7, 7, 7})
	if got := open(dir); !slices.Equal(got, []int64{3}) {
		t.Errorf("Recovered calls %v, want [3]", got)
	}
}
