package filestore

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/internal/merkle"
)

// sameTree checks that pruned answers, for every size, leaf and old size it
// still holds, what whole answers, and ErrPruned below its start. It returns
// how many sizes it checked.
func sameTree(t *testing.T, whole, pruned *merkle.Tree) int {
	t.Helper()
	if pruned.Size() != whole.Size() {
		t.Fatalf("pruned tree has %d leaves, the whole %d", pruned.Size(), whole.Size())
	}
	start, checked := pruned.Start(), 0
	for n := max(start, 1); n <= whole.Size(); n++ {
		want, _ := whole.Root(n)
		if got, err := pruned.Root(n); err != nil || got != want {
			t.Fatalf("root of %d after pruning to %d: %v", n, start, err)
		}
		for i := range n {
			got, err := pruned.InclusionProof(i, n)
			if i < start {
				if !errors.Is(err, merkle.ErrPruned) {
					t.Fatalf("inclusion of pruned leaf %d: %v", i, err)
				}
				continue
			}
			w, _ := whole.InclusionProof(i, n)
			if err != nil || !slices.Equal(got, w) {
				t.Fatalf("inclusion of %d in %d after pruning to %d: %v", i, n, start, err)
			}
		}
		for m := start; m <= n; m++ {
			if m == 0 {
				continue
			}
			got, err := pruned.ConsistencyProof(m, n)
			w, _ := whole.ConsistencyProof(m, n)
			if err != nil || !slices.Equal(got, w) {
				t.Fatalf("consistency %d -> %d after pruning to %d: %v", m, n, start, err)
			}
		}
		checked++
	}
	return checked
}

// After a prune, and after a second one that no longer has the first one's
// leaves, the stored range and the leaves left give every root, inclusion
// proof and consistency proof the whole log gave, from the first leaf kept
// on (#59).
//
// Negative control: with Prune writing no range, the first tree after the
// prune failed with errNoTree. Verified by hand, restored before committing.
func TestProofsReachAcrossAPrunedRange(t *testing.T) {
	ctx := context.Background()
	dir, cps := prunable(t)
	cp, _ := midSegment(t, dir, cps)

	s := mustOpen(t, dir)
	defer func() { _ = s.Close() }()
	whole, err := s.tree(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}

	checked := 0
	for i, c := range []tally.SignedCheckpoint{cp, cps[len(cps)-1]} {
		removed, err := s.Prune(ctx, c, verifiers(t))
		if err != nil || removed == 0 {
			t.Fatalf("prune %d: removed %d, %v", i+1, removed, err)
		}
		first := segmentFirsts(t, dir)[0]
		pruned, err := s.tree(ctx, first)
		if err != nil {
			t.Fatalf("prune %d: %v", i+1, err)
		}
		if pruned.Start() != first {
			t.Fatalf("prune %d: the range starts at %d, the log at %d", i+1, pruned.Start(), first)
		}
		checked += sameTree(t, whole, pruned)
	}
	if checked == 0 {
		t.Fatal("no size was checked")
	}
}

// A log a v0.1 writer pruned has no range and has lost the leaves one needs:
// it is pruned further without one, and has no tree, which says why.
func TestALogPrunedWithoutARangeStillPrunes(t *testing.T) {
	ctx := context.Background()
	dir, cps := prunable(t)
	cp, _ := midSegment(t, dir, cps)
	s := mustOpen(t, dir)
	defer func() { _ = s.Close() }()
	if _, err := s.Prune(ctx, cp, verifiers(t)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, pruneRangeName)); err != nil {
		t.Fatal(err)
	}
	if removed, err := s.Prune(ctx, cps[len(cps)-1], verifiers(t)); err != nil || removed == 0 {
		t.Fatalf("second prune: removed %d, %v", removed, err)
	}
	if _, err := os.Stat(filepath.Join(dir, pruneRangeName)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a range was written for leaves it could not see: %v", err)
	}
	if _, err := s.tree(ctx, segmentFirsts(t, dir)[0]); !errors.Is(err, errNoTree) {
		t.Errorf("tree = %v, want errNoTree", err)
	}
}

// The range file is read strictly (RS-04, RS-05): only what
// encodePruneRange writes decodes, and nothing else panics.
//
// This test found the decoder writing base64 into 32 bytes: a 44-character
// line with no padding decodes to 33, and "base64 without padding" panicked.
func TestPruneRangeDecodesOnlyItsOwnEncoding(t *testing.T) {
	h := [32]byte{1, 2, 3}
	good := encodePruneRange(5, [][32]byte{h, h}) // 5 = 4 + 1: two subtrees
	if start, prefix, err := decodePruneRange(good); err != nil || start != 5 || len(prefix) != 2 || prefix[0] != h {
		t.Fatalf("round trip: %d %d %v", start, len(prefix), err)
	}
	bad := map[string][]byte{
		"another header":         bytes.Replace(good, []byte("tally"), []byte("tallx"), 1),
		"start 0":                encodePruneRange(0, nil),
		"one hash too few":       encodePruneRange(5, [][32]byte{h}),
		"one hash too many":      encodePruneRange(5, [][32]byte{h, h, h}),
		"no final newline":       good[:len(good)-1],
		"a blank line":           append(slices.Clone(good), '\n'),
		"a leading zero":         bytes.Replace(good, []byte("\n5\n"), []byte("\n05\n"), 1),
		"a signed start":         bytes.Replace(good, []byte("\n5\n"), []byte("\n+5\n"), 1),
		"base64 without padding": bytes.Replace(good, []byte("=\n"), []byte("A\n"), 1),
		"url-safe base64 hash":   bytes.Replace(good, []byte("AQID"), []byte("AQI_"), 1),
		"a CRLF line":            bytes.Replace(good, []byte("\n5\n"), []byte("\r\n5\n"), 1),
		"nothing":                nil,
		"a hash of 33 bytes":     bytes.Replace(good, good[len(good)-45:], []byte("AQIDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"), 1),
		"a hash of 31 bytes":     bytes.Replace(good, good[len(good)-45:], []byte("AQIDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n"), 1),
	}
	for name, data := range bad {
		if _, _, err := decodePruneRange(data); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	if len(bad) != 14 {
		t.Fatalf("checked %d malformed files, want 14", len(bad))
	}
}

// prunedAt prunes a fresh prunable log at a checkpoint inside a segment and
// returns its directory and its range file's path.
func prunedAt(t *testing.T) (dir, rangePath string) {
	t.Helper()
	dir, cps := prunable(t)
	cp, _ := midSegment(t, dir, cps)
	s := mustOpen(t, dir)
	if _, err := s.Prune(context.Background(), cp, verifiers(t)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	return dir, filepath.Join(dir, pruneRangeName)
}

// A pruned.range the host plants on a log v0.1 pruned, whose checkpoints carry
// no root, is never signed over (audit A2-03): with no signed root at or above
// its start to check it, the writer treats the tree as unknown and keeps
// signing tally-chain/v1, with no tlog-checkpoint.
//
// Negative control: with load adopting any stored range, the writer signed a
// tally-heartbeat/v1 note, and a tlog-checkpoint, over the planted prefix.
// Verified by hand, restored before committing.
func TestAPlantedRangeIsNeverSignedOver(t *testing.T) {
	ctx := context.Background()
	dir, rangePath := prunedAt(t)
	good, err := os.ReadFile(rangePath) // #nosec G304 -- a test's own file
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(rangePath); err != nil { // as a log v0.1 pruned
		t.Fatal(err)
	}
	appendEvents(t, dir, "c", 3) // no tree: tally-chain/v1 checkpoints
	start, prefix, err := decodePruneRange(good)
	if err != nil {
		t.Fatal(err)
	}
	for i := range prefix {
		prefix[i] = [32]byte{byte(i + 1), 0xAA}
	}
	if err = os.WriteFile(rangePath, encodePruneRange(start, prefix), 0o600); err != nil {
		t.Fatal(err)
	}

	tlogs := func() int {
		r, rerr := OpenReader(dir)
		if rerr != nil {
			t.Fatal(rerr)
		}
		n := 0
		for c, cerr := range r.Checkpoints(ctx) {
			if cerr != nil {
				t.Fatal(cerr)
			}
			if isTlog(c) {
				n++
			}
		}
		return n
	}
	before := tlogs() // the v0.2 writer's, from before the range was removed

	l, err := tally.Open(ctx, mustOpen(t, dir), signer(t), tally.WithCheckpointEvery(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = l.Append(ctx, event("d-0")); err != nil {
		t.Fatal(err)
	}
	cp, err := l.Checkpoint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(cp, []byte("\ntally-chain/v1\n")) {
		t.Fatalf("the writer signed over a planted range:\n%s", cp)
	}
	if after := tlogs(); after != before {
		t.Fatalf("%d tlog-checkpoints were stored over a planted range", after-before)
	}
}

// A range changed after the prune is refused when the writer reopens: its
// last stored checkpoint's root does not match the tree the range gives
// (audit A2-04).
//
// Negative control: with load's root comparison removed, Open accepted the
// tampered range. Verified by hand, restored before committing.
func TestATamperedRangeIsRefusedOnReopen(t *testing.T) {
	dir, rangePath := prunedAt(t)
	good, err := os.ReadFile(rangePath) // #nosec G304 -- a test's own file
	if err != nil {
		t.Fatal(err)
	}
	start, prefix, err := decodePruneRange(good)
	if err != nil {
		t.Fatal(err)
	}
	prefix[0][0] ^= 1
	if err = os.WriteFile(rangePath, encodePruneRange(start, prefix), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = tally.Open(context.Background(), mustOpen(t, dir), signer(t)); !errors.Is(err, tally.ErrStoredCheckpointMismatch) {
		t.Fatalf("Open over a tampered range: %v, want ErrStoredCheckpointMismatch", err)
	}
}

// A range that starts below the first segment stands for leaves that are
// gone and not in it: a further prune refuses rather than extend it (SPEC
// §3.6, audit A2-04).
//
// Negative control: with treeUpTo's start-below-first check removed, Prune
// was still refused, by internal/merkle ("no compact range of 25 in a tree of
// 9"), a reason no operator could act on; the test requires the one that
// names the range. Verified by hand, restored before committing.
func TestPruneRefusesARangeBelowTheFirstSegment(t *testing.T) {
	ctx := context.Background()
	dir, rangePath := prunedAt(t)
	good, err := os.ReadFile(rangePath) // #nosec G304 -- a test's own file
	if err != nil {
		t.Fatal(err)
	}
	start, _, err := decodePruneRange(good)
	if err != nil {
		t.Fatal(err)
	}
	if start < 2 {
		t.Fatalf("the prune kept records from %d; the test needs a range to move below", start)
	}
	low := uint64(1) // one hash, any value: the start alone is what is refused
	if err = os.WriteFile(rangePath, encodePruneRange(low, [][32]byte{{0xBB}}), 0o600); err != nil {
		t.Fatal(err)
	}
	s := mustOpen(t, dir)
	defer func() { _ = s.Close() }()
	var newest tally.SignedCheckpoint
	for c, err := range s.Checkpoints(ctx) {
		if err != nil {
			t.Fatal(err)
		}
		if !isTlog(c) {
			newest = c
		}
	}
	before, err := os.ReadFile(rangePath) // #nosec G304 -- a test's own file
	if err != nil {
		t.Fatal(err)
	}
	removed, err := s.Prune(ctx, newest, verifiers(t))
	if err == nil || !strings.Contains(err.Error(), "below the log's first record") {
		t.Fatalf("a prune over a range below the first segment: removed %d, %v; want a refusal naming the range", removed, err)
	}
	after, err := os.ReadFile(rangePath) // #nosec G304 -- a test's own file
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("the refused prune rewrote the range")
	}
}
