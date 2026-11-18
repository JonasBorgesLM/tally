package tally_test

import (
	"context"
	"fmt"
	"iter"
	"testing"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/internal/merkle"
	"github.com/JonasBorgesLM/tally/tallytest"
)

// prunedView serves a store's records from `from` on, as a pruned store
// does, and the compact range below rangeAt as its stored range.
type prunedView struct {
	tally.Store
	from    uint64
	rangeAt uint64
	hashes  [][32]byte
	noRange bool
}

func (p prunedView) Records(ctx context.Context, fromSeq uint64) iter.Seq2[tally.Record, error] {
	return p.Store.Records(ctx, max(fromSeq, p.from))
}

func (p prunedView) CompactRange(context.Context) (start uint64, hashes [][32]byte, ok bool, err error) {
	if p.noRange {
		return 0, nil, false, nil
	}
	return p.rangeAt, p.hashes, true, nil
}

func (prunedView) Close() error { return nil }

// leafTree is the whole tree of a store's stored leaves.
func leafTree(t *testing.T, s tally.Source) *merkle.Tree {
	t.Helper()
	bs := bodies(t, s)
	leaves := make([][32]byte, 0, len(bs))
	for _, b := range bs {
		leaves = append(leaves, tally.LeafHash(b))
	}
	tree, err := merkle.NewTree(0, nil, leaves)
	if err != nil {
		t.Fatal(err)
	}
	return tree
}

func rootAfterClose(t *testing.T, l *tally.Log) ([32]byte, bool) {
	t.Helper()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return tally.TreeRootForTest(l)
}

// The Log keeps the Merkle root of every leaf it holds (#60): from a new log,
// across a reopen, and after more appends.
//
// Negative control: with chainState.add no longer appending to the tree, the
// log had no root after the first close, its range still empty. Verified by
// hand, restored before committing.
func TestTheLogKeepsTheTreeRoot(t *testing.T) {
	ctx := context.Background()
	mem := tallytest.NewMemStore()
	for round := range 3 {
		l, err := tally.Open(ctx, keepOpen{mem}, testOrigin, tally.WithCheckpointEvery(0, 0))
		if err != nil {
			t.Fatal(err)
		}
		for i := range 7 {
			if _, err = l.Append(ctx, event(fmt.Sprintf("r%d-%d", round, i))); err != nil {
				t.Fatal(err)
			}
		}
		got, ok := rootAfterClose(t, l)
		whole := leafTree(t, mem)
		want, _ := whole.Root(whole.Size())
		if !ok || got != want {
			t.Fatalf("round %d: the log's root %x (known %v), the stored leaves' %x", round, got, ok, want)
		}
	}
}

// A pruned store's range gives the Log the same root as the whole log had:
// a range at the first stored record, and one above it as a crash during a
// prune leaves. Without a range the tree is unknown, and a range below the
// first record is refused.
func TestTheLogStartsTheTreeFromAStoredRange(t *testing.T) {
	ctx := context.Background()
	mem := tallytest.NewMemStore()
	l := open(t, keepOpen{mem}, tally.WithCheckpointEvery(0, 0))
	for i := range 20 {
		if _, err := l.Append(ctx, event(fmt.Sprintf("e%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	whole := leafTree(t, mem)
	want, _ := whole.Root(whole.Size())
	rangeAt := func(n uint64) [][32]byte {
		h, err := whole.CompactRange(n)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}

	ran := 0
	for _, c := range []struct{ from, at uint64 }{{5, 5}, {8, 8}, {5, 9}, {13, 16}} {
		v := prunedView{Store: mem, from: c.from, rangeAt: c.at, hashes: rangeAt(c.at)}
		l2, err := tally.Open(ctx, v, testOrigin, tally.WithCheckpointEvery(0, 0))
		if err != nil {
			t.Fatalf("records from %d, range at %d: %v", c.from, c.at, err)
		}
		if got, ok := rootAfterClose(t, l2); !ok || got != want {
			t.Fatalf("records from %d, range at %d: root %x (known %v), want %x", c.from, c.at, got, ok, want)
		}
		ran++
	}
	if ran != 4 {
		t.Fatalf("ran %d cases, want 4", ran)
	}

	l3, err := tally.Open(ctx, prunedView{Store: mem, from: 5, noRange: true}, testOrigin, tally.WithCheckpointEvery(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := rootAfterClose(t, l3); ok {
		t.Error("a pruned log without a range has a root")
	}
	if _, err := tally.Open(ctx, prunedView{Store: mem, from: 8, rangeAt: 5, hashes: rangeAt(5)}, testOrigin); err == nil {
		t.Error("a range below the first stored record was accepted")
	}
}
