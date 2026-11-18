package filestore

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
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
