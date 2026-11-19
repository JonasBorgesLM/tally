package tally_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/internal/note"
	"github.com/JonasBorgesLM/tally/tallytest"
)

// Witnesses (ADR-0021, #61): cosigned tlog-checkpoints, the witnessed size,
// and split view caught only where a verifier requires the witness.

// testWitness is a witness's key pair, generated from a fixed seed.
func testWitness(t *testing.T, seed byte) (*note.Cosigner, tally.Verifiers) {
	t.Helper()
	skey, vkey, err := note.GenerateCosignerKey(bytes.NewReader(bytes.Repeat([]byte{seed}, 32)), "witness.example")
	if err != nil {
		t.Fatal(err)
	}
	c, err := note.NewCosigner(skey)
	if err != nil {
		t.Fatal(err)
	}
	v, err := tally.NewVerifiers(vkey)
	if err != nil {
		t.Fatal(err)
	}
	return c, v
}

// cosign returns cp with w's cosignature appended.
func cosign(t *testing.T, w *note.Cosigner, cp tally.SignedCheckpoint) tally.SignedCheckpoint {
	t.Helper()
	text, _, ok := strings.Cut(string(cp), "\n\n")
	if !ok {
		t.Fatal("not a note")
	}
	line, err := note.Cosign([]byte(text+"\n"), w, time.Unix(1_790_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	return append(slices.Clone(cp), line...)
}

// tlogOfSize is src's tlog-checkpoint of size n.
func tlogOfSize(t *testing.T, src *sliceSource, n uint64) tally.SignedCheckpoint {
	t.Helper()
	for _, cp := range src.tlogs {
		if size, err := tally.CheckpointSize(cp); err == nil && size == n {
			return cp
		}
	}
	t.Fatalf("no tlog-checkpoint of size %d", n)
	return nil
}

// The witnessed size is the largest matched checkpoint the witness cosigned,
// and requiring it makes the rest UnwitnessedTail.
//
// Negative control: with Verify counting every checkpoint as cosigned, the
// log verified witnessed to 10 with only 7 cosigned, and the fork of
// TestSplitViewNeedsTheWitness verified clean. Verified by hand, restored
// before committing.
func TestTheWitnessedSize(t *testing.T) {
	w, wkeys := testWitness(t, 9)
	src := honestLog(t, 9, 3, 6) // tlog-checkpoints of 4, 7 and 10
	src.cps = append(src.cps, cosign(t, w, tlogOfSize(t, src, 7)))

	rep := verify(t, src, tally.WithWitnesses(wkeys, 1))
	if !rep.OK() || rep.WitnessedSize != 7 || rep.AttestedSize != 10 {
		t.Fatalf("witnessed %d, attested %d, %v; want 7 and 10", rep.WitnessedSize, rep.AttestedSize, kinds(rep))
	}
	rep = verify(t, src, tally.WithWitnesses(wkeys, 1), tally.WithRequireWitnessed())
	if !hasKind(rep, tally.UnwitnessedTail) || rep.Failures[0].Seq != 7 {
		t.Fatalf("required: %v, want UnwitnessedTail at 7", rep.Failures)
	}
	src.cps = append(src.cps, cosign(t, w, tlogOfSize(t, src, 10)))
	if rep := verify(t, src, tally.WithWitnesses(wkeys, 1), tally.WithRequireWitnessed()); !rep.OK() || rep.WitnessedSize != 10 {
		t.Fatalf("all witnessed: %d, %v", rep.WitnessedSize, kinds(rep))
	}
}

// T-09, split view: the host keeps one history for the witness and shows an
// auditor another, from the same genesis, signed with the log's key. Without
// a witness the fork verifies, which is T-09's residual; requiring the
// witness, it is UnwitnessedTail, and the honest history's cosigned
// checkpoint pasted into it is a mismatch.
func TestSplitViewNeedsTheWitness(t *testing.T) {
	w, wkeys := testWitness(t, 9)
	honest := fixedLog(t, testOrigin, ids("a", 0, 6), 6)
	fork := fixedLog(t, testOrigin, append(ids("a", 0, 3), ids("b", 3, 6)...), 6)
	toSrc := func(mem *tallytest.MemStore) *sliceSource {
		src := &sliceSource{}
		for r, err := range mem.Records(context.Background(), 0) {
			if err != nil {
				t.Fatal(err)
			}
			src.recs = append(src.recs, r)
		}
		for cp, err := range mem.Checkpoints(context.Background()) {
			if err != nil {
				t.Fatal(err)
			}
			if isTlog(cp) {
				src.tlogs = append(src.tlogs, cp)
			} else {
				src.cps = append(src.cps, cp)
			}
		}
		return src
	}
	h, f := toSrc(honest), toSrc(fork)
	witnessed := cosign(t, w, tlogOfSize(t, h, 7))
	h.cps = append(h.cps, witnessed)
	if rep := verify(t, h, tally.WithWitnesses(wkeys, 1), tally.WithRequireWitnessed()); !rep.OK() {
		t.Fatalf("the witnessed history: %v", kinds(rep))
	}
	if rep := verify(t, f, tally.WithRequireFullyAttested()); !rep.OK() {
		t.Fatalf("without a witness the fork should verify, which is T-09's residual: %v", kinds(rep))
	}
	if rep := verify(t, f, tally.WithWitnesses(wkeys, 1), tally.WithRequireWitnessed()); !hasKind(rep, tally.UnwitnessedTail) {
		t.Fatalf("the fork, requiring the witness: %v, want UnwitnessedTail", kinds(rep))
	}
	f.cps = append(f.cps, witnessed)
	if rep := verify(t, f, tally.WithWitnesses(wkeys, 1)); !hasKind(rep, tally.CheckpointMismatch) {
		t.Fatalf("the honest cosigned checkpoint against the fork: %v, want CheckpointMismatch", kinds(rep))
	}
}

// A bad cosignature from a trusted witness fails the checkpoint, and a
// witness configuration that cannot be right is an error, not a report.
func TestWitnessMisuse(t *testing.T) {
	w, wkeys := testWitness(t, 9)
	src := honestLog(t, 3)
	good := cosign(t, w, tlogOfSize(t, src, 4))
	lines := strings.Split(strings.TrimSuffix(string(good), "\n"), "\n")
	last := lines[len(lines)-1]
	prefix, b64, _ := strings.Cut(last[strings.Index(last, " ")+1:], " ")
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 1 // the Ed25519 signature's last byte, still canonical base64
	lines[len(lines)-1] = "\u2014 " + prefix + " " + base64.StdEncoding.EncodeToString(raw)
	src.cps = append(src.cps, tally.SignedCheckpoint(strings.Join(lines, "\n")+"\n"))
	if rep := verify(t, src, tally.WithWitnesses(wkeys, 1)); !hasKind(rep, tally.BadSignature) {
		t.Errorf("a bad cosignature: %v, want BadSignature", kinds(rep))
	}
	ctx := context.Background()
	for name, opts := range map[string][]tally.VerifyOption{
		"quorum 0":                 {tally.WithWitnesses(wkeys, 0)},
		"quorum above the count":   {tally.WithWitnesses(wkeys, 2)},
		"a log key as a witness":   {tally.WithWitnesses(testKeys(t), 1)},
		"required with no witness": {tally.WithRequireWitnessed()},
	} {
		if _, err := tally.Verify(ctx, src, testKeys(t), opts...); err == nil {
			t.Errorf("%s: Verify ran", name)
		}
	}
}
