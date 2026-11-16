package filestore

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/JonasBorgesLM/tally"
)

func event(id string) tally.Event {
	return tally.Event{
		ID:         tally.EventID(id),
		OccurredAt: time.Unix(1_700_000_000, 0),
		Actor:      tally.System(),
		Action:     "user.login",
		Outcome:    tally.OutcomeSuccess,
	}
}

// appendEvents opens a Log over a filestore in dir, appends n events named
// from prefix, and closes it, which signs a closed checkpoint.
func appendEvents(t *testing.T, dir, prefix string, n int, opts ...Option) {
	t.Helper()
	ctx := context.Background()
	l, err := tally.Open(ctx, mustOpen(t, dir, opts...), signer(t), tally.WithCheckpointEvery(4, 0))
	if err != nil {
		t.Fatalf("tally.Open: %v", err)
	}
	for i := range n {
		if _, err := l.Append(ctx, event(fmt.Sprintf("%s-%d", prefix, i))); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// A Log written through filestore, closed, reopened and written again,
// verifies whole and fully attested, across rotated segments (RF-01, SPEC §7).
func TestALogRoundTripsAndVerifies(t *testing.T) {
	dir := logDir(t)
	appendEvents(t, dir, "a", 13, WithSegmentSize(512))
	appendEvents(t, dir, "b", 7, WithSegmentSize(512))

	s := mustOpen(t, dir)
	defer func() { _ = s.Close() }()
	rep, err := tally.Verify(context.Background(), s, verifiers(t), tally.WithRequireFullyAttested())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !rep.OK() || rep.Size != 21 {
		t.Fatalf("Verify: OK=%v Size=%d Failures=%v, want OK and 21 leaves", rep.OK(), rep.Size, rep.Failures)
	}
	if firsts := segmentFirsts(t, dir); len(firsts) < 3 {
		t.Fatalf("segments %v: the test meant to cross several boundaries", firsts)
	}
}

// Every segment boundary f > 0 carries a stored checkpoint of size f
// (ADR-0019), so the segment set starting there is verifiable (SPEC §7 step 7).
//
// Seen failing with rotation moved into AppendBatch, by size.
func TestEveryBoundaryHasACheckpointOfItsSize(t *testing.T) {
	dir := logDir(t)
	appendEvents(t, dir, "a", 25, WithSegmentSize(400))

	s := mustOpen(t, dir)
	defer func() { _ = s.Close() }()
	sizes := map[uint64]bool{}
	for cp, err := range s.Checkpoints(context.Background()) {
		if err != nil {
			t.Fatal(err)
		}
		sizes[checkpointSize(t, cp)] = true
	}
	checked := 0
	for _, f := range segmentFirsts(t, dir) {
		if f == 0 {
			continue
		}
		checked++
		if !sizes[f] {
			t.Errorf("segment %s has no checkpoint of size %d", segmentName(f), f)
		}
	}
	if checked < 2 {
		t.Fatalf("checked %d boundaries; the test meant to cross several", checked)
	}
}

// A segment over its size is not rotated by AppendBatch, only by the next
// PutCheckpoint; and a segment holding no frame is never rotated.
//
// Seen failing with the guard on a frameless segment removed: the heartbeat
// then tries to create segment 5 again.
func TestRotationOnlyAtACheckpoint(t *testing.T) {
	ctx := context.Background()
	dir := logDir(t)
	bodies := vectorBodies(t)
	s := mustOpen(t, dir, WithSegmentSize(1))
	defer func() { _ = s.Close() }()

	if err := s.AppendBatch(ctx, records(bodies, 0)); err != nil {
		t.Fatal(err)
	}
	if got := segmentFirsts(t, dir); !slices.Equal(got, []uint64{0}) {
		t.Fatalf("after AppendBatch, segments %v, want [0]", got)
	}
	cp := vectorCheckpoint(t)
	if err := s.PutCheckpoint(ctx, cp); err != nil {
		t.Fatal(err)
	}
	if got := segmentFirsts(t, dir); !slices.Equal(got, []uint64{0, 5}) {
		t.Fatalf("after PutCheckpoint, segments %v, want [0 5]", got)
	}
	// A heartbeat over the same head: the last segment holds no frame.
	if err := s.PutCheckpoint(ctx, cp); err != nil {
		t.Fatalf("a second checkpoint with nothing new: %v", err)
	}
	if got := segmentFirsts(t, dir); !slices.Equal(got, []uint64{0, 5}) {
		t.Fatalf("after a heartbeat, segments %v, want [0 5]", got)
	}
}

// The order of operations is what makes each call durable on return (RF-01,
// ADR-0009): a new file's contents are synced, then its directory, before it
// is relied on; appended records are synced before AppendBatch returns.
//
// Seen failing with the directory fsync removed from createFile, and with
// the Sync removed from AppendBatch.
func TestDurabilityOrder(t *testing.T) {
	ctx := context.Background()
	r := newRecFS()
	dir := logDir(t)
	s := mustOpen(t, dir, withFS(r), WithSegmentSize(1))
	defer func() { _ = s.Close() }()
	bodies := vectorBodies(t)
	cp := vectorCheckpoint(t)

	const seg0, seg5, cps = "0000000000000000.tlog", "0000000000000005.tlog", "checkpoints.tlc"
	steps := []struct {
		name string
		call func() error
		want []string
	}{
		{"genesis", func() error { return s.AppendBatch(ctx, records(bodies[:1], 0)) }, []string{
			"create " + seg0, "write " + seg0, "sync " + seg0, "read log", "sync log", "close log",
			"write " + seg0, "sync " + seg0,
		}},
		{"entries", func() error { return s.AppendBatch(ctx, records(bodies[1:], 1)) }, []string{
			"write " + seg0, "sync " + seg0,
		}},
		{"first checkpoint, rotating", func() error { return s.PutCheckpoint(ctx, cp) }, []string{
			"create " + cps, "write " + cps, "sync " + cps, "read log", "sync log", "close log",
			"create " + seg5, "write " + seg5, "sync " + seg5, "read log", "sync log", "close log",
			"close " + seg0,
		}},
		{"next checkpoint", func() error { return s.PutCheckpoint(ctx, cp) }, []string{
			"write " + cps, "sync " + cps,
		}},
	}
	for _, st := range steps {
		r.reset(-1)
		if err := st.call(); err != nil {
			t.Fatalf("%s: %v", st.name, err)
		}
		if !slices.Equal(r.ops, st.want) {
			t.Errorf("%s:\n got  %q\n want %q", st.name, r.ops, st.want)
		}
	}
}

// A fault at any operation of a write is returned, and is final: the next
// write returns an error without touching the filesystem (ADR-0009).
//
// Seen failing with s.fail replaced by a plain return of the error.
func TestAFaultIsFinal(t *testing.T) {
	ctx := context.Background()
	bodies := vectorBodies(t)
	cp := vectorCheckpoint(t)

	// The operations of: genesis, entries, a rotating checkpoint.
	calls := func(s *Store) []func() error {
		return []func() error{
			func() error { return s.AppendBatch(ctx, records(bodies[:1], 0)) },
			func() error { return s.AppendBatch(ctx, records(bodies[1:], 1)) },
			func() error { return s.PutCheckpoint(ctx, cp) },
		}
	}
	r := newRecFS()
	s := mustOpen(t, logDir(t), withFS(r), WithSegmentSize(1))
	r.reset(-1)
	for _, c := range calls(s) {
		if err := c(); err != nil {
			t.Fatal(err)
		}
	}
	total := len(r.ops)
	_ = s.Close()

	ran := 0
	for i := range total {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			ran++
			r := newRecFS()
			s, err := Open(ctx, logDir(t), withFS(r), WithSegmentSize(1))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = s.Close() }()
			r.reset(i)
			for _, c := range calls(s) {
				if err = c(); err != nil {
					break
				}
			}
			if !errors.Is(err, errInjected) {
				t.Fatalf("fault at %q: err = %v, want the injected fault", r.ops[i], err)
			}
			before := len(r.ops)
			if err := s.AppendBatch(ctx, records(bodies[:1], 0)); err == nil {
				t.Fatal("a write after the fault succeeded")
			}
			if len(r.ops) != before {
				t.Errorf("a write after the fault touched the filesystem: %q", r.ops[before:])
			}
		})
	}
	if ran != total || ran == 0 {
		t.Fatalf("ran %d faults, want %d", ran, total)
	}
}

// Files are created 0600 and the directory 0700 (RS-10); an existing
// directory others can access is refused unless explicitly relaxed (RS-15).
//
// Seen failing with the permission check removed from prepareDir.
func TestPermissions(t *testing.T) {
	dir := logDir(t)
	appendEvents(t, dir, "a", 1)

	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o700 {
		t.Errorf("directory mode %04o, want 0700", perm)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("files %v, want a segment, the checkpoints file and the lock", entries)
	}
	for _, e := range entries {
		info, ierr := e.Info()
		if ierr != nil {
			t.Fatal(ierr)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s mode %04o, want 0600", e.Name(), perm)
		}
	}

	if err = os.Chmod(dir, 0o755); err != nil { // #nosec G302 -- the looser mode under test
		t.Fatal(err)
	}
	if _, err = Open(context.Background(), dir); !errors.Is(err, ErrLoosePermissions) {
		t.Fatalf("Open on a 0755 directory = %v, want ErrLoosePermissions", err)
	}
	s, err := Open(context.Background(), dir, WithLoosePermissions())
	if err != nil {
		t.Fatalf("Open with WithLoosePermissions: %v", err)
	}
	_ = s.Close()
}

// The genesis segment is created with O_EXCL: a file planted at its name is
// an error, never appended to or overwritten (RS-10).
//
// Seen failing with O_EXCL removed from createFile.
func TestGenesisIsCreatedExclusively(t *testing.T) {
	dir := logDir(t)
	s := mustOpen(t, dir)
	defer func() { _ = s.Close() }()
	planted := filepath.Join(dir, segmentName(0))
	if err := os.WriteFile(planted, []byte("planted"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := s.AppendBatch(context.Background(), records(vectorBodies(t)[:1], 0))
	if !errors.Is(err, fs.ErrExist) {
		t.Fatalf("AppendBatch over a planted genesis = %v, want fs.ErrExist", err)
	}
	if got, _ := os.ReadFile(planted); string(got) != "planted" { // #nosec G304 -- a test's own file
		t.Errorf("the planted file was changed to %q", got)
	}
}

// A second Open of one directory fails with tally.ErrLocked, and succeeds once
// the first is closed (RS-09).
func TestSecondOpenIsLocked(t *testing.T) {
	dir := logDir(t)
	first := mustOpen(t, dir)
	if _, err := Open(context.Background(), dir); !errors.Is(err, tally.ErrLocked) {
		t.Fatalf("second Open = %v, want tally.ErrLocked", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	again := mustOpen(t, dir)
	_ = again.Close()
}

// After Close, every call returns tally.ErrClosed, and Close is idempotent.
func TestClose(t *testing.T) {
	ctx := context.Background()
	s := mustOpen(t, logDir(t))
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("second Close = %v", err)
	}
	if err := s.AppendBatch(ctx, records(vectorBodies(t)[:1], 0)); !errors.Is(err, tally.ErrClosed) {
		t.Errorf("AppendBatch after Close = %v", err)
	}
	if err := s.PutCheckpoint(ctx, vectorCheckpoint(t)); !errors.Is(err, tally.ErrClosed) {
		t.Errorf("PutCheckpoint after Close = %v", err)
	}
	for _, err := range s.Records(ctx, 0) {
		if !errors.Is(err, tally.ErrClosed) {
			t.Errorf("Records after Close = %v", err)
		}
	}
}

// writeVectorLog writes records.json and the checkpoint of checkpoints.json
// to a new directory, rotating at the checkpoint, and returns the directory.
func writeVectorLog(t *testing.T) string {
	t.Helper()
	dir := logDir(t)
	s := mustOpen(t, dir, WithSegmentSize(1))
	if err := s.AppendBatch(context.Background(), records(vectorBodies(t), 0)); err != nil {
		t.Fatal(err)
	}
	if err := s.PutCheckpoint(context.Background(), vectorCheckpoint(t)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}

func appendToFile(t *testing.T, name string, b []byte) {
	t.Helper()
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_APPEND, 0) // #nosec G304 -- a test's own file
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// A frame's length is checked against the ceiling before the body is
// allocated or read (RS-05): a length of 4 GiB in a tiny file is refused as
// too long, not attempted and found short.
//
// Seen failing with the ceiling check removed from readFrame: the error is
// then errShortFrame, after allocating 4 GiB.
func TestFrameLengthIsCheckedBeforeAllocating(t *testing.T) {
	huge := binary.BigEndian.AppendUint32(nil, 0xFFFFFFFF)
	huge = append(huge, "not 4 GiB"...)

	t.Run("on Open, the last segment", func(t *testing.T) {
		dir := writeVectorLog(t)
		appendToFile(t, filepath.Join(dir, segmentName(5)), huge)
		if _, err := Open(context.Background(), dir); !errors.Is(err, errFrameTooLong) {
			t.Fatalf("Open = %v, want errFrameTooLong", err)
		}
	})
	t.Run("in Records, an earlier segment", func(t *testing.T) {
		dir := writeVectorLog(t)
		// Rewrite segment 0 as its header and a huge frame.
		seg0 := filepath.Join(dir, segmentName(0))
		b, err := os.ReadFile(seg0) // #nosec G304 -- a test's own file
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(seg0, append(b[:segmentHeaderLen:segmentHeaderLen], huge...), 0o600); err != nil { // #nosec G703 -- a test's own file
			t.Fatal(err)
		}
		s := mustOpen(t, dir)
		defer func() { _ = s.Close() }()
		var got error
		for _, err := range s.Records(context.Background(), 0) {
			got = err
		}
		if !errors.Is(got, errFrameTooLong) {
			t.Fatalf("Records = %v, want errFrameTooLong", got)
		}
	})
	t.Run("in Checkpoints", func(t *testing.T) {
		dir := writeVectorLog(t)
		appendToFile(t, filepath.Join(dir, checkpointsName), huge)
		if _, err := Open(context.Background(), dir); !errors.Is(err, errFrameTooLong) {
			t.Fatalf("Open = %v, want errFrameTooLong", err)
		}
	})
}

// Until recovery exists (#34), Open refuses a log whose last segment does not
// end on a complete, valid frame, rather than appending after bad bytes.
func TestOpenRefusesABadTail(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(b []byte) []byte
		want   error
	}{
		{"cut by one byte", func(b []byte) []byte { return b[:len(b)-1] }, errShortFrame},
		{"a stray byte", func(b []byte) []byte { return append(b, 0) }, errShortFrame},
		{"a flipped bit", func(b []byte) []byte { b[len(b)-5] ^= 1; return b }, errFrameCRC},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := logDir(t)
			s := mustOpen(t, dir)
			if err := s.AppendBatch(context.Background(), records(vectorBodies(t), 0)); err != nil {
				t.Fatal(err)
			}
			_ = s.Close()
			seg0 := filepath.Join(dir, segmentName(0))
			b, err := os.ReadFile(seg0) // #nosec G304 -- a test's own file
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(seg0, c.mutate(b), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(context.Background(), dir); !errors.Is(err, c.want) {
				t.Fatalf("Open = %v, want %v", err, c.want)
			}
		})
	}
}

// A segment name with uppercase hex digits is an error, not a foreign file
// to skip, so that renaming cannot hide a segment (SPEC §3).
func TestUppercaseSegmentNameIsAnError(t *testing.T) {
	dir := writeVectorLog(t)
	if err := os.Rename(filepath.Join(dir, segmentName(5)), filepath.Join(dir, "000000000000000A.tlog")); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), dir); err == nil {
		t.Fatal("Open accepted a segment named in uppercase")
	}
}

// Records checks that each segment continues the previous one: a header
// whose prev_hash is not the previous segment's last leaf ends the read with
// an error, and Verify never reports it as intact (RS-04).
//
// Seen failing with the continuity check removed from segmentRead.run.
func TestRecordsChecksSegmentContinuity(t *testing.T) {
	dir := writeVectorLog(t)
	seg5 := filepath.Join(dir, segmentName(5))
	b, err := os.ReadFile(seg5) // #nosec G304 -- a test's own file
	if err != nil {
		t.Fatal(err)
	}
	b[segmentHeaderLen-1] ^= 1                          // the last byte of prev_hash
	if err = os.WriteFile(seg5, b, 0o600); err != nil { // #nosec G703 -- a test's own file
		t.Fatal(err)
	}
	s := mustOpen(t, dir)
	defer func() { _ = s.Close() }()
	rep, err := tally.Verify(context.Background(), s, verifiers(t))
	if err == nil {
		t.Fatalf("Verify over a broken boundary returned a report: OK=%v, want an error", rep.OK())
	}
	if !bytes.Contains([]byte(err.Error()), []byte("does not continue")) {
		t.Errorf("Verify error = %v, want the continuity failure", err)
	}
}
