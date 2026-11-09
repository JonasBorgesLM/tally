package tally_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/internal/note"
	"github.com/JonasBorgesLM/tally/tallytest"
)

// TestAKeyRotation is the key rotation of docs/RUNBOOK.md, executed: the log
// is closed under the old key, the new verifier key is published, and the log
// is reopened under the new key, with the same name, which is the log's
// origin (SPEC §5.3). Checkpoints before and after carry different keys.
//
// RF-10: with both keys trusted the log verifies, fully attested. Without the
// old key, the checkpoints it signed are UnknownKey, never a pass: a
// checkpoint no trusted key signed proves nothing. Without the new key, the
// same holds for the checkpoints after the rotation.
//
// Negative control: letting Verify ignore a checkpoint with no trusted
// signature, instead of reporting UnknownKey, made the "without the old key"
// case pass.
func TestAKeyRotation(t *testing.T) {
	oldSkey, oldVkey := tallytest.TestSignerKey, tallytest.TestVerifierKey
	newSkey, newVkey, err := note.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0xB0}, 32)), "example.com/log")
	if err != nil {
		t.Fatal(err)
	}
	if newVkey == oldVkey {
		t.Fatal("the new key is the old one; the test would prove nothing")
	}

	mem := tallytest.NewMemStore()
	run := func(skey string, ids ...string) {
		t.Helper()
		l, err := tally.Open(context.Background(), keepOpen{mem}, mustSigner(skey), tally.WithCheckpointEvery(0, 0))
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		for _, id := range ids {
			if _, err := l.Append(context.Background(), event(id)); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := l.Checkpoint(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := l.Close(); err != nil { // the closed checkpoint, under this key
			t.Fatal(err)
		}
	}
	run(oldSkey, "a", "b") // before the rotation
	run(newSkey, "c", "d") // after: the same origin, a new key

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
		src.cps = append(src.cps, cp)
	}

	verifyWith := func(vkeys ...string) *tally.Report {
		t.Helper()
		keys, err := tally.NewVerifiers(vkeys...)
		if err != nil {
			t.Fatal(err)
		}
		rep, err := tally.Verify(context.Background(), src, keys)
		if err != nil {
			t.Fatal(err)
		}
		return rep
	}

	if rep := verifyWith(oldVkey, newVkey); !rep.OK() || rep.Size != 5 || rep.AttestedSize != 5 {
		t.Fatalf("with both keys: %+v, want OK and fully attested", rep)
	}
	for name, vkey := range map[string]string{"without the old key": newVkey, "without the new key": oldVkey} {
		rep := verifyWith(vkey)
		if rep.OK() || !hasKind(rep, tally.UnknownKey) {
			t.Fatalf("%s: %v, want UnknownKey for the checkpoints the missing key signed", name, kinds(rep))
		}
	}
}
