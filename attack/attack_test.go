// Package attack_test is tally's attack suite (#47): one test per threat of
// docs/THREAT-MODEL.md, asserting the detection a threat must meet, or, for a
// partial threat, the limit it documents. registry_test.go maps every T-nn to
// its test, here or in another package, and generates the README's table.
package attack_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/anchor"
	"github.com/JonasBorgesLM/tally/filestore"
	"github.com/JonasBorgesLM/tally/internal/note"
	"github.com/JonasBorgesLM/tally/seal"
	"github.com/JonasBorgesLM/tally/tallytest"
)

// T-01: altering an entry's content inside the attested prefix breaks the
// chain at the next entry. Past the last checkpoint, an entry rewritten with
// nothing after it verifies, and is counted as unattested: the limit.
//
// Seen failing with the prev_hash check removed from the chain.
func TestT01AlterAnEntry(t *testing.T) {
	src := writeLog(t, tallytest.TestSignerKey, 0, ids(5, "e"), 5)
	src.bodies[2] = bytes.Replace(src.bodies[2], []byte("doc-e1"), []byte("doc-X1"), 1)
	detected(t, verify(t, src), tally.PrevHashMismatch)

	tail := writeLog(t, tallytest.TestSignerKey, 0, ids(5, "e"), 3)
	tail.cps = tail.cps[:1] // drop the closing checkpoint: the tail is unattested
	last := len(tail.bodies) - 1
	tail.bodies[last] = bytes.Replace(tail.bodies[last], []byte("doc-e4"), []byte("doc-X4"), 1)
	rep := verify(t, tail)
	undetected(t, rep)
	if rep.UnattestedEntries == 0 {
		t.Fatal("the rewritten tail is not counted as unattested")
	}
}

// T-02: removing an entry from the middle leaves a gap in seq.
//
// Seen failing with the seq check removed from the chain.
func TestT02RemoveFromTheMiddle(t *testing.T) {
	src := writeLog(t, tallytest.TestSignerKey, 0, ids(5, "e"), 5)
	src.bodies = slices.Delete(src.bodies, 2, 3)
	detected(t, verify(t, src), tally.SeqGap)
}

// T-03: an entry inserted in the middle, even one from a log sharing the
// genesis and so correctly chained to its predecessor, pushes seq back.
//
// Seen failing with the seq checks removed from the chain.
func TestT03InsertAForgedEntry(t *testing.T) {
	src := writeLog(t, tallytest.TestSignerKey, 0x51, ids(5, "e"), 5)
	forged := writeLog(t, tallytest.TestSignerKey, 0x51, ids(5, "f"))
	src.bodies = slices.Insert(src.bodies, 1, forged.bodies[1])
	detected(t, verify(t, src), tally.SeqRegression)
}

// T-04: swapping two entries breaks the order of seq.
//
// Seen failing with the seq checks removed from the chain.
func TestT04Reorder(t *testing.T) {
	src := writeLog(t, tallytest.TestSignerKey, 0, ids(5, "e"), 5)
	src.bodies[2], src.bodies[3] = src.bodies[3], src.bodies[2]
	detected(t, verify(t, src), tally.SeqGap)
}

// T-06: a host without the key rewrites from a point on, with a consistent
// chain and checkpoints it signs itself. The anchor's checkpoint over the
// original disagrees: a fork; its own checkpoints are under an unknown key.
//
// The limit (audit A-01, #126): records are not signed, so the host can
// instead rewrite them and delete the checkpoints after the point it rewrote
// from. Nothing local contradicts the rewrite; the honest writer, reopened,
// signs its next checkpoint over it with the real key, and without an anchor
// the log verifies fully attested.
//
// The fork was seen failing with the anchor's checkpoints not compared with
// the log.
func TestT06RewriteWithoutTheKey(t *testing.T) {
	orig := writeLog(t, tallytest.TestSignerKey, 0x52, ids(5, "e"), 2)
	rewritten := writeLog(t, attackerKey(t), 0x52, append(ids(2, "e"), "x2", "x3", "x4"), 2)
	if !bytes.Equal(orig.bodies[1], rewritten.bodies[1]) || bytes.Equal(orig.bodies[3], rewritten.bodies[3]) {
		t.Fatal("the rewrite meant to share a prefix and diverge after it")
	}
	rep := verify(t, rewritten, tally.WithAnchor(anchorList(orig.cps)))
	detected(t, rep, tally.ForkDetected)
	detected(t, rep, tally.UnknownKey)

	// The limit: the rewritten records, the original's checkpoints up to the
	// one at size 3 (before the rewrite's first entry, seq 3), and the honest
	// writer reopening it.
	ctx := context.Background()
	mem := tallytest.NewMemStore()
	recs := make([]tally.Record, 0, len(rewritten.bodies))
	for i, b := range rewritten.bodies {
		recs = append(recs, tally.Record{Seq: uint64(i), Body: b}) // #nosec G115 -- a slice index
	}
	if err := mem.AppendBatch(ctx, recs); err != nil {
		t.Fatal(err)
	}
	if err := mem.PutCheckpoint(ctx, orig.cps[0]); err != nil { // size 3, below the rewrite
		t.Fatal(err)
	}
	l, err := tally.Open(ctx, keepOpen{mem}, signer(t, tallytest.TestSignerKey))
	if err != nil {
		t.Fatalf("the honest writer refused the rewrite: the limit asserted here no longer holds (%v)", err)
	}
	if err = l.Close(); err != nil { // signs the rewritten history
		t.Fatal(err)
	}
	resigned := &source{}
	for r, err := range mem.Records(ctx, 0) {
		if err != nil {
			t.Fatal(err)
		}
		resigned.bodies = append(resigned.bodies, r.Body)
	}
	for cp, err := range mem.Checkpoints(ctx) {
		if err != nil {
			t.Fatal(err)
		}
		resigned.cps = append(resigned.cps, cp)
	}
	undetected(t, verify(t, resigned, tally.WithRequireFullyAttested()))
	// Against the anchor, it is still a fork.
	detected(t, verify(t, resigned, tally.WithAnchor(anchorList(orig.cps))), tally.ForkDetected)
}

// T-09: split view. A host holding the key shows one auditor one history and
// another a different one, each with its own anchor: each verifies, the
// limit, for any verifier that does not require a witness. A shared anchor
// makes the second a fork; and a witness (ADR-0021), which cosigned only the
// history it was shown, makes the other UnwitnessedTail for a verifier that
// requires it.
//
// The fork half was seen failing with the anchor not read by Verify; the
// witness half, with Verify counting every checkpoint as cosigned
// (TestTheWitnessedSize's control).
func TestT09SplitView(t *testing.T) {
	a := writeLog(t, tallytest.TestSignerKey, 0x53, ids(4, "a"), 2)
	b := writeLog(t, tallytest.TestSignerKey, 0x53, ids(4, "b"), 2)
	undetected(t, verify(t, a, tally.WithAnchor(anchorList(a.cps)), tally.WithRequireFullyAttested()))
	undetected(t, verify(t, b, tally.WithAnchor(anchorList(b.cps)), tally.WithRequireFullyAttested()))
	// With one anchor for both, the second is a fork.
	detected(t, verify(t, b, tally.WithAnchor(anchorList(a.cps))), tally.ForkDetected)

	// A witness was shown a, and cosigned its newest tlog-checkpoint.
	wsk, wvk, err := note.GenerateCosignerKey(bytes.NewReader(bytes.Repeat([]byte{0x77}, 32)), "witness.example")
	if err != nil {
		t.Fatal(err)
	}
	w, err := note.NewCosigner(wsk)
	if err != nil {
		t.Fatal(err)
	}
	witnesses, err := tally.NewVerifiers(wvk)
	if err != nil {
		t.Fatal(err)
	}
	var newest tally.SignedCheckpoint
	for _, cp := range a.cps {
		if text, _, _ := strings.Cut(string(cp), "\n\n"); len(strings.Split(text, "\n")) == 3 {
			newest = cp
		}
	}
	text, _, _ := strings.Cut(string(newest), "\n\n")
	line, err := note.Cosign([]byte(text+"\n"), w, time.Unix(1_790_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	a.cps = append(a.cps, append(slices.Clone(newest), line...))
	b.cps = append(b.cps, a.cps[len(a.cps)-1]) // the host pastes a's cosigned checkpoint in too
	required := []tally.VerifyOption{tally.WithWitnesses(witnesses, 1), tally.WithRequireWitnessed()}
	undetected(t, verify(t, a, required...))
	detected(t, verify(t, b, required...), tally.UnwitnessedTail)
	// Without the requirement, b still verifies on its own anchor: the limit.
	b.cps = b.cps[:len(b.cps)-1]
	undetected(t, verify(t, b, tally.WithAnchor(anchorList(b.cps)), tally.WithWitnesses(witnesses, 1)))
}

// T-10: an entry spliced in from another log carries the other log_id.
//
// Seen failing with the log_id check removed from the chain.
func TestT10SpliceAcrossLogs(t *testing.T) {
	src := writeLog(t, tallytest.TestSignerKey, 0, ids(5, "e"), 5)
	other := writeLog(t, tallytest.TestSignerKey, 0, ids(5, "e"), 5) // another random log_id
	src.bodies[2] = other.bodies[2]
	detected(t, verify(t, src), tally.MalformedRecord)
}

// T-11: a duplicated entry repeats a seq.
//
// Seen failing with the seq checks removed from the chain.
func TestT11DuplicateAnEntry(t *testing.T) {
	src := writeLog(t, tallytest.TestSignerKey, 0, ids(5, "e"), 5)
	src.bodies = slices.Insert(src.bodies, 3, src.bodies[2])
	detected(t, verify(t, src), tally.SeqRegression)
}

// T-14: occurred_at is the caller's claim and untrusted: an entry dated
// fifty years back verifies. recorded_at is the host's clock, kept monotonic
// by the writer, and proves no real time either; the limit. A limit test has
// no protection to remove: it fails if the limit changes, and then the threat
// model and the README must change with it.
func TestT14BackdatingByTheCaller(t *testing.T) {
	ctx := context.Background()
	mem := tallytest.NewMemStore()
	l, err := tally.Open(ctx, keepOpen{mem}, signer(t, tallytest.TestSignerKey))
	if err != nil {
		t.Fatal(err)
	}
	ev := event("old", "doc-old")
	ev.OccurredAt = time.Unix(0, 0)
	if _, err = l.Append(ctx, ev); err != nil {
		t.Fatal(err)
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	undetected(t, verify(t, mem, tally.WithRequireFullyAttested()))
}

// sealedLog writes a log in a directory with two sealed payloads for one
// subject, through a vault in another directory, and returns both, the
// subject's ref and the plaintexts.
func sealedLog(t *testing.T) (logDir string, v *seal.FileVault, vaultDir string, ref tally.SubjectRef, plain [][]byte) {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	logDir, vaultDir = filepath.Join(root, "log"), filepath.Join(root, "vault")
	kek, err := seal.NewLocalKEK("kek-1", bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if v, err = seal.OpenFileVault(ctx, vaultDir, kek); err != nil {
		t.Fatal(err)
	}
	s, err := filestore.Open(ctx, logDir)
	if err != nil {
		t.Fatal(err)
	}
	l, err := tally.Open(ctx, s, signer(t, tallytest.TestSignerKey))
	if err != nil {
		t.Fatal(err)
	}
	if ref, err = v.Resolve(ctx, []byte("alice@example.com")); err != nil {
		t.Fatal(err)
	}
	for i, p := range []string{"alice's address: Rua A, 1", "alice's phone: 5551234"} {
		plain = append(plain, []byte(p))
		id := tally.EventID(rune('a' + i))
		payload, perr := seal.Payload(ctx, v, l.ID(), id, ref, []byte(p))
		if perr != nil {
			t.Fatal(perr)
		}
		ev := tally.Event{ID: id, OccurredAt: time.Unix(1_700_000_000, 0), Actor: tally.Subject(ref),
			Action: "profile.update", Outcome: tally.OutcomeSuccess, Payload: payload}
		if _, err = l.Append(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	return logDir, v, vaultDir, ref, plain
}

func filesContain(t *testing.T, dir string, needles ...[]byte) []string {
	t.Helper()
	var found []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(path) // #nosec G304 G122 -- a test's own temporary directory
		if err != nil {
			return err
		}
		for _, n := range needles {
			if bytes.Contains(b, n) {
				found = append(found, path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

// T-19: a sealed payload is ciphertext on disk, the identifier is in neither
// the log nor the vault, and the vault opens with no other KEK. A process
// holding the KEK, or memory, are out of reach; the limit is in the README.
//
// Seen failing with seal.Payload returning a plain payload.
func TestT19PersonalPayloadsOnDisk(t *testing.T) {
	logDir, v, vaultDir, _, plain := sealedLog(t)
	_ = v.Close()
	if found := filesContain(t, logDir, append(plain, []byte("alice@example.com"))...); len(found) != 0 {
		t.Fatalf("personal data in clear in the log: %v", found)
	}
	if found := filesContain(t, vaultDir, []byte("alice")); len(found) != 0 {
		t.Fatalf("the identifier is in the vault: %v", found)
	}
	other, err := seal.NewLocalKEK("kek-1", bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := seal.OpenFileVault(context.Background(), vaultDir, other); err == nil {
		t.Fatal("the vault opened under a KEK that did not wrap it")
	}
}

// T-20: after a shred the payloads are gone, and the ref still links the
// subject's entries to each other, so their pattern remains: the limit. It
// fails if the limit changes, as T-14's does.
func TestT20LinkAfterAShred(t *testing.T) {
	ctx := context.Background()
	logDir, v, _, ref, _ := sealedLog(t)
	defer func() { _ = v.Close() }()
	if err := v.Shred(ctx, ref); err != nil {
		t.Fatal(err)
	}
	r, err := filestore.OpenReader(logDir)
	if err != nil {
		t.Fatal(err)
	}
	undetected(t, verify(t, r, tally.WithRequireFullyAttested()))
	linked := 0
	for rec, err := range r.Records(ctx, 1) {
		if err != nil {
			t.Fatal(err)
		}
		rv, err := tally.DecodeRecord(rec.Body)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(rv.SubjectRef, ref[:]) {
			linked++
			a, err := seal.AAD(rv.LogID, tally.EventID(rv.EventID), ref)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := v.Open(ctx, ref, rv.Payload, a); !errors.Is(err, tally.ErrShredded) {
				t.Errorf("a payload opened after the shred: %v", err)
			}
		}
	}
	if linked != 2 {
		t.Fatalf("%d entries carry the shredded ref, want 2: the limit is that both still do", linked)
	}
}

// T-21: an "anchor" the host can write is no anchor. The host rolls its log
// back and deletes, from a host-writable anchor.Dir, the checkpoints past the
// rollback; the log then verifies against it: the limit RS-17 exists to state.
// It fails if the limit changes, as T-14's does.
func TestT21RewriteTheAnchorFromTheHost(t *testing.T) {
	ctx := context.Background()
	old := writeLog(t, tallytest.TestSignerKey, 0x54, ids(3, "e"))
	full := writeLog(t, tallytest.TestSignerKey, 0x54, ids(6, "e"))
	spool := filepath.Join(t.TempDir(), "anchor")
	dir, err := anchor.NewDir(spool)
	if err != nil {
		t.Fatal(err)
	}
	for _, cp := range append(slices.Clone(old.cps), full.cps...) {
		if err = dir.Publish(ctx, cp); err != nil {
			t.Fatal(err)
		}
	}
	detected(t, verify(t, old, tally.WithAnchor(dir)), tally.TruncatedBelowCheckpoint)

	// The host deletes every anchored checkpoint its rolled-back log lacks.
	entries, err := os.ReadDir(spool)
	if err != nil {
		t.Fatal(err)
	}
	removed := 0
	for _, e := range entries {
		b, rerr := os.ReadFile(filepath.Join(spool, e.Name())) // #nosec G304 -- a test's own file
		if rerr != nil {
			t.Fatal(rerr)
		}
		if !slices.ContainsFunc(old.cps, func(cp tally.SignedCheckpoint) bool { return bytes.Equal(cp, b) }) {
			if err = os.Remove(filepath.Join(spool, e.Name())); err != nil {
				t.Fatal(err)
			}
			removed++
		}
	}
	if removed == 0 {
		t.Fatal("the anchor held nothing past the rollback; the test meant it to")
	}
	undetected(t, verify(t, old, tally.WithAnchor(dir)))
}

// T-22: a flipped bit in the last entry past the last checkpoint looks like a
// torn write: recovery quarantines it, and the log verifies without it. The
// bytes are kept as evidence; the question is not settled: the limit.
// Inside a checkpoint the same damage refuses to open (filestore's
// TestNeverBelowTheLastCheckpoint). It fails if the limit changes, as T-14's
// does.
func TestT22TamperingDisguisedAsACrash(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "log")
	s, err := filestore.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	l, err := tally.Open(ctx, keepOpen{s}, signer(t, tallytest.TestSignerKey), tally.WithCheckpointEvery(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	for i, id := range ids(3, "e") {
		if _, err = l.Append(ctx, event(id, "doc-"+id)); err != nil {
			t.Fatal(err)
		}
		if i == 1 {
			if _, err = l.Checkpoint(ctx); err != nil { // covers genesis and two entries
				t.Fatal(err)
			}
		}
	}
	_ = s.Close() // a crash: no closing checkpoint over the last entry
	seg := filepath.Join(dir, "0000000000000000.tlog")
	b, err := os.ReadFile(seg) // #nosec G304 -- a test's own file
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)-6] ^= 1                                   // inside the last entry's frame
	if err = os.WriteFile(seg, b, 0o600); err != nil { // #nosec G703 -- a test's own file
		t.Fatal(err)
	}

	s, err = filestore.Open(ctx, dir)
	if err != nil {
		t.Fatalf("recovery refused: %v", err)
	}
	defer func() { _ = s.Close() }()
	if s.Recovered() == 0 {
		t.Fatal("nothing was quarantined")
	}
	rep := verify(t, s)
	undetected(t, rep)
	if rep.Size != 3 {
		t.Fatalf("Size %d, want 3: the tampered entry is gone, and the log verifies without it", rep.Size)
	}
}

// T-23: deleting leading segments down to a boundary leaves a log that
// verifies from the checkpoint there, as a prune does: the limit. The anchor
// holds that checkpoint too, so nothing in the log tells a deletion from a
// prune. It fails if the limit changes, as T-14's does.
func TestT23DeleteLeadingSegments(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "log")
	s, err := filestore.Open(ctx, dir, filestore.WithSegmentSize(400))
	if err != nil {
		t.Fatal(err)
	}
	var anchored anchorList
	l, err := tally.Open(ctx, s, signer(t, tallytest.TestSignerKey), tally.WithCheckpointEvery(3, 0),
		tally.WithAnchors(listAnchor{&anchored}))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids(12, "e") {
		if _, err = l.Append(ctx, event(id, "doc-"+id)); err != nil {
			t.Fatal(err)
		}
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	var segs []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tlog") {
			segs = append(segs, e.Name())
		}
	}
	if len(segs) < 3 {
		t.Fatalf("segments %v: the test meant several", segs)
	}
	// The attacker deletes the first two segments: no prune, no marker.
	for _, name := range segs[:2] {
		if err = os.Remove(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	r, err := filestore.OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	rep := verify(t, r, tally.WithAnchor(anchored))
	undetected(t, rep)
	if rep.Size == 0 || len(segs) < 3 {
		t.Fatal("nothing was verified")
	}
}

// listAnchor is an Anchor that keeps what it receives.
type listAnchor struct{ list *anchorList }

func (a listAnchor) Publish(_ context.Context, cp tally.SignedCheckpoint) error {
	*a.list = append(*a.list, slices.Clone(cp))
	return nil
}
