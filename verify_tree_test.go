package tally_test

import (
	"context"
	"encoding/base64"
	"errors"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/internal/merkle"
	"github.com/JonasBorgesLM/tally/internal/note"
	"github.com/JonasBorgesLM/tally/tallytest"
)

// The v0.2 bodies (ADR-0006's amendment, #60, SPEC §5.2): a tlog-checkpoint
// and a tally-heartbeat/v1 note, verified beside v0.1's tally-chain/v1.

func signText(t *testing.T, text string) tally.SignedCheckpoint {
	t.Helper()
	s, err := note.NewSigner(tallytest.TestSignerKey)
	if err != nil {
		t.Fatal(err)
	}
	cp, err := note.Sign([]byte(text), s)
	if err != nil {
		t.Fatal(err)
	}
	return cp
}

func b64(h [32]byte) string { return base64.StdEncoding.EncodeToString(h[:]) }

func tlogNote(t *testing.T, size uint64, root [32]byte) tally.SignedCheckpoint {
	t.Helper()
	return signText(t, "example.com/log\n"+strconv.FormatUint(size, 10)+"\n"+b64(root)+"\n")
}

func heartbeatNote(t *testing.T, size uint64, head, root [32]byte, at time.Time, state string) tally.SignedCheckpoint {
	t.Helper()
	return signText(t, "example.com/log\ntally-heartbeat/v1\n"+strconv.FormatUint(size, 10)+"\n"+
		b64(head)+"\n"+b64(root)+"\n"+at.UTC().Format("2006-01-02T15:04:05.000000000Z")+"\n"+state+"\n")
}

// treeOf is the whole tree of src's leaves, and each leaf.
func treeOf(t *testing.T, src *sliceSource) (tree *merkle.Tree, leaves [][32]byte) {
	t.Helper()
	leaves = make([][32]byte, 0, len(src.recs))
	for _, r := range src.recs {
		leaves = append(leaves, tally.LeafHash(r.Body))
	}
	tree, err := merkle.NewTree(0, nil, leaves)
	if err != nil {
		t.Fatal(err)
	}
	return tree, leaves
}

func rootAt(t *testing.T, tree *merkle.Tree, n uint64) [32]byte {
	t.Helper()
	r, err := tree.Root(n)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// later is a time after every leaf of an honestLog, whose events record the
// wall clock.
var later = time.Now().Add(time.Hour)

// A log with only v0.2 notes verifies and is attested by them, and a v0.1
// checkpoint beside them changes nothing.
func TestTheV02NotesAttestALog(t *testing.T) {
	src := honestLog(t, 8, 3)
	tree, leaves := treeOf(t, src)
	v1 := src.cps // this log's own tally-chain/v1 checkpoints, of 4 and 9
	src.cps = nil
	src.cps = append(src.cps, tlogNote(t, 4, rootAt(t, tree, 4)))
	if rep := verify(t, src, tally.WithRequireFullyAttested()); rep.OK() || rep.AttestedSize != 4 {
		t.Fatalf("a tlog-checkpoint of 4: attested %d, %v; want 4 and the tail unattested", rep.AttestedSize, kinds(rep))
	}
	src.cps = append(src.cps, heartbeatNote(t, 9, leaves[8], rootAt(t, tree, 9), later, "closed"))
	rep := verify(t, src, tally.WithRequireFullyAttested())
	if !rep.OK() || rep.AttestedSize != 9 {
		t.Fatalf("with a heartbeat note of 9: attested %d, %v", rep.AttestedSize, kinds(rep))
	}
	src.cps = append(src.cps, v1...)
	if rep := verify(t, src, tally.WithRequireFullyAttested()); !rep.OK() {
		t.Fatalf("with v0.1 checkpoints beside: %v", kinds(rep))
	}
}

// A root that is not the log's tree is a mismatch, from the host, and a fork
// from an anchor; in a heartbeat note too, where the head alone agrees. Two
// notes of one size with different roots are a fork whatever the log says.
//
// Negative controls, each verified by hand and restored before committing:
// with compareWithLeaf's root comparison removed, the wrong tlog-checkpoint
// verified clean, on the host and from an anchor; with forks' root rule
// removed, the two notes of 4 were only a CheckpointMismatch.
func TestAWrongRootIsCaught(t *testing.T) {
	src := honestLog(t, 8)
	tree, leaves := treeOf(t, src)
	src.cps = nil
	wrong := rootAt(t, tree, 5)

	cases := []struct {
		name string
		cp   tally.SignedCheckpoint
	}{
		{"tlog-checkpoint", tlogNote(t, 4, wrong)},
		{"heartbeat note, head right", heartbeatNote(t, 4, leaves[3], wrong, later, "open")},
	}
	for _, c := range cases {
		src.cps = []tally.SignedCheckpoint{c.cp}
		if rep := verify(t, src); !hasKind(rep, tally.CheckpointMismatch) {
			t.Errorf("%s on the host: %v, want CheckpointMismatch", c.name, kinds(rep))
		}
		src.cps = nil
		if rep := verify(t, src, tally.WithAnchor(anchorList{c.cp})); !hasKind(rep, tally.ForkDetected) {
			t.Errorf("%s from an anchor: %v, want ForkDetected", c.name, kinds(rep))
		}
	}
	src.cps = []tally.SignedCheckpoint{tlogNote(t, 4, rootAt(t, tree, 4)), heartbeatNote(t, 4, leaves[3], wrong, later, "open")}
	if rep := verify(t, src); !hasKind(rep, tally.ForkDetected) {
		t.Errorf("two notes of 4 with different roots: %v, want ForkDetected", kinds(rep))
	}
}

// A tlog-checkpoint carries no time: it neither feeds the heartbeat nor
// breaks the time order. Anchored heartbeat notes do feed it.
//
// Negative control: with heartbeatGaps reading tlog-checkpoints too, the
// anchored heartbeat note a minute old was a HeartbeatGap, its predecessor
// dated 1970. Verified by hand, restored before committing.
func TestOnlyTimedNotesFeedTheHeartbeat(t *testing.T) {
	src := honestLog(t, 4)
	tree, leaves := treeOf(t, src)
	src.cps = nil
	now := later.Add(time.Minute)
	hb := tally.WithHeartbeat(time.Hour, time.Minute, now)
	onlyTlog := anchorList{tlogNote(t, 5, rootAt(t, tree, 5))}
	if rep := verify(t, src, tally.WithAnchor(onlyTlog), hb); !hasKind(rep, tally.HeartbeatGap) {
		t.Errorf("only a tlog-checkpoint anchored: %v, want HeartbeatGap", kinds(rep))
	}
	timed := anchorList{tlogNote(t, 5, rootAt(t, tree, 5)), heartbeatNote(t, 5, leaves[4], rootAt(t, tree, 5), later, "open")}
	if rep := verify(t, src, tally.WithAnchor(timed), hb); !rep.OK() {
		t.Errorf("a heartbeat note anchored a minute ago: %v", kinds(rep))
	}
}

// A start must name a head: a tlog-checkpoint is refused as a start, and the
// heartbeat note of its size is accepted.
//
// Negative control: without the check, the tlog-checkpoint was accepted as a
// start with no error. Verified by hand, restored before committing.
func TestAStartNeedsAHead(t *testing.T) {
	src := honestLog(t, 6)
	tree, leaves := treeOf(t, src)
	src.cps = nil
	_, err := tally.Verify(context.Background(), src, testKeys(t), tally.FromCheckpoint(tlogNote(t, 4, rootAt(t, tree, 4))))
	if !errors.Is(err, tally.ErrUntrustedStart) {
		t.Fatalf("a tlog-checkpoint as the start: %v, want ErrUntrustedStart", err)
	}
	rep := verify(t, src, tally.FromCheckpoint(heartbeatNote(t, 4, leaves[3], rootAt(t, tree, 4), later, "open")))
	if !rep.OK() {
		t.Fatalf("the heartbeat note as the start: %v", kinds(rep))
	}
}

// rangedSource is a pruned source: records from `from` on, and the compact
// range below rangeAt, which the host wrote.
type rangedSource struct {
	*sliceSource
	rangeAt uint64
	hashes  [][32]byte
}

func (r rangedSource) CompactRange(context.Context) (start uint64, hashes [][32]byte, ok bool, err error) {
	return r.rangeAt, r.hashes, r.hashes != nil || r.rangeAt == 0, nil
}

// After a prune, a tlog-checkpoint is compared through the stored range: it
// attests the log when the range reproduces its root, and a false range
// shows as a mismatch. Without a range it is not compared, and attests
// nothing.
func TestAPrunedLogComparesRootsThroughItsRange(t *testing.T) {
	src := honestLog(t, 10)
	tree, _ := treeOf(t, src)
	pruned := &sliceSource{recs: slices.Clone(src.recs[5:])}
	rng, err := tree.CompactRange(5)
	if err != nil {
		t.Fatal(err)
	}
	cp := tlogNote(t, 8, rootAt(t, tree, 8))
	pruned.cps = []tally.SignedCheckpoint{cp}

	rep := verify(t, rangedSource{pruned, 5, rng})
	if !rep.OK() || rep.AttestedSize != 8 {
		t.Fatalf("with the range: attested %d, %v", rep.AttestedSize, kinds(rep))
	}
	falseRange := slices.Clone(rng)
	falseRange[0][0] ^= 1
	if rep := verify(t, rangedSource{pruned, 5, falseRange}); !hasKind(rep, tally.CheckpointMismatch) {
		t.Errorf("with a false range: %v, want CheckpointMismatch", kinds(rep))
	}
	if rep := verify(t, pruned); !hasKind(rep, tally.PrunedWithoutTrustedCheckpoint) || rep.AttestedSize != 0 {
		t.Errorf("without a range: attested %d, %v; want nothing attested", rep.AttestedSize, kinds(rep))
	}
}

// CheckpointSize reads the size of each body, which a Store's recovery floor
// (RF-20) and anchor.Dir's file names rely on.
func TestCheckpointSizeReadsEveryBody(t *testing.T) {
	var h [32]byte
	cases := map[string]tally.SignedCheckpoint{
		"tlog-checkpoint": tlogNote(t, 12, h),
		"heartbeat note":  heartbeatNote(t, 12, h, h, later, "open"),
		"tally-chain/v1":  signedCheckpoint(t, tallytest.TestSignerKey, "example.com/log", 12, h, later.UTC().Format("2006-01-02T15:04:05.000000000Z"), "open"),
	}
	for name, cp := range cases {
		if n, err := tally.CheckpointSize(cp); err != nil || n != 12 {
			t.Errorf("%s: size %d, %v; want 12", name, n, err)
		}
	}
	if len(cases) != 3 {
		t.Fatalf("checked %d bodies, want 3", len(cases))
	}
}
