package filestore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/internal/note"
)

// prunable writes a log of 25 entries over many segments, with a checkpoint
// every 4 entries, and returns the directory and its stored checkpoints.
func prunable(t *testing.T) (string, []tally.SignedCheckpoint) {
	t.Helper()
	dir := logDir(t)
	appendEvents(t, dir, "a", 25, WithSegmentSize(800))
	s := mustOpen(t, dir)
	defer func() { _ = s.Close() }()
	var cps []tally.SignedCheckpoint
	for cp, err := range s.Checkpoints(context.Background()) {
		if err != nil {
			t.Fatal(err)
		}
		cps = append(cps, cp)
	}
	if firsts := segmentFirsts(t, dir); len(firsts) < 4 {
		t.Fatalf("segments %v: the test needs several", firsts)
	}
	return dir, cps
}

// midSegment returns a stored checkpoint whose size is inside a segment, not
// at a boundary, with at least two segments wholly below it.
func midSegment(t *testing.T, dir string, cps []tally.SignedCheckpoint) (cp tally.SignedCheckpoint, size uint64) {
	t.Helper()
	firsts := segmentFirsts(t, dir)
	for _, c := range cps {
		n := checkpointSize(t, c)
		below := 0
		for i := 0; i+1 < len(firsts) && firsts[i+1] <= n; i++ {
			below++
		}
		if below >= 2 && !slices.Contains(firsts, n) && n < firsts[len(firsts)-1] {
			return c, n
		}
	}
	t.Fatalf("no checkpoint inside a segment among %d; segments %v", len(cps), firsts)
	return nil, 0
}

// Prune removes the segments wholly below the checkpoint and keeps the one
// holding record size-1, which the checkpoint crosses (RF-14).
//
// Seen failing with the condition changed to "the segment starts below size",
// which removes the partial segment too.
func TestPruneKeepsThePartialSegment(t *testing.T) {
	ctx := context.Background()
	dir, cps := prunable(t)
	cp, size := midSegment(t, dir, cps)
	before := segmentFirsts(t, dir)

	s := mustOpen(t, dir)
	defer func() { _ = s.Close() }()
	removed, err := s.Prune(ctx, cp, verifiers(t))
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	after := segmentFirsts(t, dir)
	if removed == 0 || !slices.Equal(after, before[removed:]) {
		t.Fatalf("removed %d: segments %v -> %v", removed, before, after)
	}
	if after[0] > size-1 || (len(after) > 1 && after[1] <= size-1) {
		t.Errorf("first segment %v does not hold record %d", after, size-1)
	}

	marker, err := os.ReadFile(filepath.Join(dir, pruneMarkerName)) // #nosec G304 -- a test's own file
	if err != nil || !bytes.Equal(marker, cp) {
		t.Errorf("prune marker = %q, %v; want the checkpoint", marker, err)
	}
	fi, err := os.Stat(filepath.Join(dir, pruneMarkerName))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("prune marker mode %v, %v; want 0600", fi.Mode().Perm(), err)
	}
}

// A checkpoint whose signature does not verify, or which does not agree with
// the stored log, prunes nothing (RS-20).
//
// Seen failing with the Verify call removed from Prune, and with
// ErrPruneRefused dropped from the refusal of a checkpoint of another log.
func TestPruneRefusesAnUntrustedCheckpoint(t *testing.T) {
	dir, cps := prunable(t)
	cp, _ := midSegment(t, dir, cps)

	// The same text, signed by another key with the log's name.
	otherSkey, _, err := note.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{7}, 32)), "example.com/log")
	if err != nil {
		t.Fatal(err)
	}
	other, err := note.NewSigner(otherSkey)
	if err != nil {
		t.Fatal(err)
	}
	text := cp[:bytes.Index(cp, []byte("\n\n"))+1]
	forged, err := note.Sign(text, other)
	if err != nil {
		t.Fatal(err)
	}
	// A valid checkpoint from another log signed by the same key.
	elsewhere, otherCps := prunable(t)
	foreign, _ := midSegment(t, elsewhere, otherCps)

	tampered := slices.Clone(cp)
	tampered[len(tampered)-3] ^= 1

	cases := []struct {
		name string
		cp   tally.SignedCheckpoint
		want error
	}{
		{"a signature by an unknown key", tally.SignedCheckpoint(forged), tally.ErrUntrustedStart},
		{"a tampered signature", tampered, tally.ErrUntrustedStart},
		{"a checkpoint of another log", foreign, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := snap(t, dir)
			s := mustOpen(t, dir)
			defer func() { _ = s.Close() }()
			removed, err := s.Prune(t.Context(), c.cp, verifiers(t))
			if !errors.Is(err, ErrPruneRefused) || (c.want != nil && !errors.Is(err, c.want)) {
				t.Fatalf("Prune = %d, %v; want ErrPruneRefused (%v)", removed, err, c.want)
			}
			if removed != 0 || !maps(snap(t, dir), before) {
				t.Error("a refused Prune changed the directory")
			}
		})
	}
}

// After a prune the log verifies from the checkpoint, and from its own
// stored checkpoints, which include one at or above the new first segment.
// Without any trusted checkpoint it is PrunedWithoutTrustedCheckpoint (SPEC
// §7 step 7): the prune marker is not evidence.
func TestAPrunedLogVerifiesOnlyWithATrustedCheckpoint(t *testing.T) {
	ctx := context.Background()
	dir, cps := prunable(t)
	cp, _ := midSegment(t, dir, cps)
	s := mustOpen(t, dir)
	if _, err := s.Prune(ctx, cp, verifiers(t)); err != nil {
		t.Fatalf("Prune: %v", err)
	}

	for _, c := range []struct {
		name string
		opts []tally.VerifyOption
	}{
		{"from the checkpoint", []tally.VerifyOption{tally.FromCheckpoint(cp)}},
		{"from the stored checkpoints", nil},
	} {
		rep, err := tally.Verify(ctx, s, verifiers(t), c.opts...)
		if err != nil || !rep.OK() {
			t.Errorf("%s: Verify = %v, %+v; want OK", c.name, err, rep)
		}
	}
	_ = s.Close()

	if err := os.Remove(filepath.Join(dir, checkpointsName)); err != nil {
		t.Fatal(err)
	}
	s = mustOpen(t, dir)
	defer func() { _ = s.Close() }()
	rep, err := tally.Verify(ctx, s, verifiers(t))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.OK() || !slices.ContainsFunc(rep.Failures, func(f tally.Failure) bool {
		return f.Kind == tally.PrunedWithoutTrustedCheckpoint
	}) {
		t.Fatalf("Verify = %+v, want PrunedWithoutTrustedCheckpoint", rep.Failures)
	}
}

// A Log reopens a pruned store and goes on appending, and the log verifies
// from the checkpoint it was pruned at.
//
// Seen failing with the pruned-start branch removed from tally's load.
func TestALogReopensAPrunedStore(t *testing.T) {
	ctx := context.Background()
	dir, cps := prunable(t)
	cp, _ := midSegment(t, dir, cps)
	s := mustOpen(t, dir)
	if _, err := s.Prune(ctx, cp, verifiers(t)); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	_ = s.Close()

	appendEvents(t, dir, "b", 6, WithSegmentSize(400))

	s = mustOpen(t, dir)
	defer func() { _ = s.Close() }()
	rep, err := tally.Verify(ctx, s, verifiers(t), tally.FromCheckpoint(cp), tally.WithRequireFullyAttested())
	if err != nil || !rep.OK() || rep.Size != 32 {
		t.Fatalf("Verify = %v, %+v; want OK with 32 leaves", err, rep)
	}
}

// A checkpoint below the second segment prunes nothing and writes no marker.
func TestPruneBelowTheFirstBoundaryIsANoOp(t *testing.T) {
	dir, cps := prunable(t)
	firsts := segmentFirsts(t, dir)
	var low tally.SignedCheckpoint
	for _, cp := range cps {
		if checkpointSize(t, cp) < firsts[1] {
			low = cp
			break
		}
	}
	if low == nil {
		t.Fatalf("no checkpoint below %d", firsts[1])
	}
	s := mustOpen(t, dir)
	defer func() { _ = s.Close() }()
	removed, err := s.Prune(context.Background(), low, verifiers(t))
	if err != nil || removed != 0 {
		t.Fatalf("Prune = %d, %v; want 0, nil", removed, err)
	}
	if _, err := os.Stat(filepath.Join(dir, pruneMarkerName)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a no-op prune wrote a marker: %v", err)
	}
}

// The marker is durable before any segment is removed, and the segments go
// oldest first, so a crash at any point leaves a contiguous log. A fault at
// every operation leaves a log that verifies from the checkpoint.
//
// Seen failing with the marker written after the removals.
func TestPruneOrderAndFaults(t *testing.T) {
	dir, cps := prunable(t)
	cp, _ := midSegment(t, dir, cps)

	r := newRecFS()
	s := mustOpen(t, dir, withFS(r))
	r.reset(-1)
	if _, err := s.Prune(t.Context(), cp, verifiers(t)); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	ops := slices.Clone(r.ops)
	marker := slices.Index(ops, "rename "+pruneMarkerName+".tmp "+pruneMarkerName)
	firstRemove := slices.IndexFunc(ops, func(op string) bool {
		_, ok, _ := parseSegmentName(op[min(len(op), len("remove ")):])
		return len(op) > 7 && op[:7] == "remove " && ok
	})
	if marker < 0 || firstRemove < 0 || marker > firstRemove || !slices.Contains(ops[marker:firstRemove], "sync log") {
		t.Fatalf("the marker is not durable before the first segment is removed: %q", ops)
	}

	ran := 0
	for i := range ops {
		t.Run(fmt.Sprintf("%d %s", i, ops[i]), func(t *testing.T) {
			ran++
			dir, cps := prunable(t)
			cp, _ := midSegment(t, dir, cps)
			fr := newRecFS()
			s, err := Open(t.Context(), dir, withFS(fr))
			if err != nil {
				t.Fatal(err)
			}
			fr.reset(i)
			_, _ = s.Prune(t.Context(), cp, verifiers(t)) // the fault may or may not be reached
			_ = s.Close()

			s = mustOpen(t, dir)
			defer func() { _ = s.Close() }()
			rep, err := tally.Verify(t.Context(), s, verifiers(t), tally.FromCheckpoint(cp))
			if err != nil || !rep.OK() {
				t.Fatalf("after a fault: Verify = %v, %+v", err, rep)
			}
		})
	}
	if ran != len(ops) || ran == 0 {
		t.Fatalf("ran %d faults, want %d", ran, len(ops))
	}
}
