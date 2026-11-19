package tally

import (
	"bytes"
	"context"
	"fmt"
	"iter"
	"testing"
	"time"

	"github.com/JonasBorgesLM/tally/internal/merkle"
)

// This file is an internal test because it reads the Merkle root the writer
// keeps (#60), which nothing exported carries yet. It reads it after Close,
// once the writer has stopped.

func treeEvent(id string) Event {
	return Event{ID: EventID(id), OccurredAt: time.Unix(1, 0), Actor: System(),
		Action: "user.login", Outcome: OutcomeSuccess}
}

// rootAfterClose closes l and returns the root it kept, false if unknown.
func rootAfterClose(t *testing.T, l *Log) ([32]byte, bool) {
	t.Helper()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if l.head.tree == nil {
		return [32]byte{}, false
	}
	r, err := l.head.tree.Root()
	return r, err == nil
}

// leafTree is the whole tree of a source's stored leaves.
func leafTree(t *testing.T, s Source) *merkle.Tree {
	t.Helper()
	var leaves [][32]byte
	for r, err := range s.Records(context.Background(), 0) {
		if err != nil {
			t.Fatal(err)
		}
		leaves = append(leaves, LeafHash(r.Body))
	}
	tree, err := merkle.NewTree(0, nil, leaves)
	if err != nil {
		t.Fatal(err)
	}
	return tree
}

// prunedView serves a store's records from `from` on, as a pruned store
// does, and the compact range below rangeAt as its stored range.
type prunedView struct {
	*batchStore
	from    uint64
	rangeAt uint64
	hashes  [][32]byte
	noRange bool
}

func (p prunedView) Records(ctx context.Context, fromSeq uint64) iter.Seq2[Record, error] {
	return p.batchStore.Records(ctx, max(fromSeq, p.from))
}

func (p prunedView) CompactRange(context.Context) (start uint64, hashes [][32]byte, ok bool, err error) {
	if p.noRange {
		return 0, nil, false, nil
	}
	return p.rangeAt, p.hashes, true, nil
}

// The Log keeps the Merkle root of every leaf it holds (#60): from a new log,
// across a reopen, and after more appends.
//
// Negative control: with chainState.add no longer appending to the tree, the
// log had no root after the first close, its range still empty. Verified by
// hand, restored before committing.
func TestTheLogKeepsTheTreeRoot(t *testing.T) {
	ctx := context.Background()
	store := &batchStore{}
	for round := range 3 {
		l, err := Open(ctx, store, testSigner("example.com/log"), WithCheckpointEvery(0, 0))
		if err != nil {
			t.Fatal(err)
		}
		for i := range 7 {
			if _, err = l.Append(ctx, treeEvent(fmt.Sprintf("r%d-%d", round, i))); err != nil {
				t.Fatal(err)
			}
		}
		got, ok := rootAfterClose(t, l)
		whole := leafTree(t, store)
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
	signer := testSigner("example.com/log")
	store := &batchStore{}
	l, err := Open(ctx, store, signer, WithCheckpointEvery(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	for i := range 20 {
		if _, err = l.Append(ctx, treeEvent(fmt.Sprintf("e%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	whole := leafTree(t, store)
	want, _ := whole.Root(whole.Size())
	rangeAt := func(n uint64) [][32]byte {
		h, rerr := whole.CompactRange(n)
		if rerr != nil {
			t.Fatal(rerr)
		}
		return h
	}

	ran := 0
	for _, c := range []struct{ from, at uint64 }{{5, 5}, {8, 8}, {5, 9}, {13, 16}} {
		v := prunedView{batchStore: store, from: c.from, rangeAt: c.at, hashes: rangeAt(c.at)}
		l2, oerr := Open(ctx, v, signer, WithCheckpointEvery(0, 0))
		if oerr != nil {
			t.Fatalf("records from %d, range at %d: %v", c.from, c.at, oerr)
		}
		if got, ok := rootAfterClose(t, l2); !ok || got != want {
			t.Fatalf("records from %d, range at %d: root %x (known %v), want %x", c.from, c.at, got, ok, want)
		}
		ran++
	}
	if ran != 4 {
		t.Fatalf("ran %d cases, want 4", ran)
	}

	l3, err := Open(ctx, prunedView{batchStore: store, from: 5, noRange: true}, signer, WithCheckpointEvery(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := rootAfterClose(t, l3); ok {
		t.Error("a pruned log without a range has a root")
	}
	if _, err := Open(ctx, prunedView{batchStore: store, from: 8, rangeAt: 5, hashes: rangeAt(5)}, signer); err == nil {
		t.Error("a range below the first stored record was accepted")
	}
}

// A log pruned before ranges existed has no tree, so it cannot sign a root:
// its writer keeps signing tally-chain/v1 checkpoints, which verify as they
// did, and no tlog-checkpoint (#60). With a tree, the writer signs the pair.
//
// Negative control: with the writer signing the pair whatever the tree,
// Checkpoint on the log without a range returned a heartbeat note over a
// zero root. Verified by hand, restored before committing.
func TestALogWithoutATreeKeepsWritingV01Checkpoints(t *testing.T) {
	ctx := context.Background()
	signer := testSigner("example.com/log")
	store := &batchStore{}
	l, err := Open(ctx, store, signer, WithCheckpointEvery(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	for i := range 10 {
		if _, err = l.Append(ctx, treeEvent(fmt.Sprintf("e%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}

	l2, err := Open(ctx, prunedView{batchStore: store, from: 5, noRange: true}, signer, WithCheckpointEvery(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	cp, err := l2.Checkpoint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = l2.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(cp, []byte("\n"+bodyChainV1+"\n")) {
		t.Fatalf("without a tree, Checkpoint returned:\n%s\nwant a tally-chain/v1 checkpoint", cp)
	}

	l3, err := Open(ctx, store, signer, WithCheckpointEvery(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	cp, err = l3.Checkpoint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = l3.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(cp, []byte("\n"+bodyHeartbeatV1+"\n")) {
		t.Fatalf("with a tree, Checkpoint returned:\n%s\nwant a tally-heartbeat/v1 note", cp)
	}
}
