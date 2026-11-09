package interop

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"iter"
	"math/rand/v2"
	"testing"

	xnote "golang.org/x/mod/sumdb/note"

	"github.com/JonasBorgesLM/tally"
	tnote "github.com/JonasBorgesLM/tally/internal/note"
	"github.com/JonasBorgesLM/tally/tallytest"
)

// Differential tests of tally's signed notes (internal/note, SPEC §5) against
// golang.org/x/mod/sumdb/note, the reference implementation (ADR-0005). tally
// may be stricter than x/mod, never looser (SPEC §5).

// The keys interchange both ways, and both name the same key id.
func TestKeysInterchange(t *testing.T) {
	xs, xv, err := xnote.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{1}, 64)), "example.com/log")
	if err != nil {
		t.Fatal(err)
	}
	ts, tv, err := tnote.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{2}, 32)), "example.com/log")
	if err != nil {
		t.Fatal(err)
	}
	fromX, err := tnote.NewSigner(xs)
	if err != nil {
		t.Fatalf("tally reads x/mod's signer key: %v", err)
	}
	fromXV, err := tnote.NewVerifier(xv)
	if err != nil {
		t.Fatalf("tally reads x/mod's verifier key: %v", err)
	}
	toX, err := xnote.NewSigner(ts)
	if err != nil {
		t.Fatalf("x/mod reads tally's signer key: %v", err)
	}
	toXV, err := xnote.NewVerifier(tv)
	if err != nil {
		t.Fatalf("x/mod reads tally's verifier key: %v", err)
	}
	if fromX.KeyHash() != fromXV.KeyHash() || toX.KeyHash() != toXV.KeyHash() {
		t.Fatal("the key ids disagree across implementations")
	}
	// The published test key, whose base64 holds '+', the separator.
	if _, err := xnote.NewVerifier(tallytest.TestVerifierKey); err != nil {
		t.Fatalf("x/mod reads the published test key: %v", err)
	}
}

// A checkpoint signed by a real tally Log opens under x/mod, and a note x/mod
// signs over a checkpoint body opens under tally and verifies as a checkpoint.
//
// Negative control: making internal/note sign the text without its final
// newline made the x/mod direction fail.
func TestCheckpointsInterchange(t *testing.T) {
	signer, err := tnote.NewSigner(tallytest.TestSignerKey)
	if err != nil {
		t.Fatal(err)
	}
	mem := tallytest.NewMemStore()
	l, err := tally.Open(context.Background(), mem, signer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	ev := tally.Event{ID: "e1", Actor: tally.System(), Action: "user.login", Outcome: tally.OutcomeSuccess}
	ev.OccurredAt = ev.OccurredAt.AddDate(2026, 0, 0)
	if _, aerr := l.Append(context.Background(), ev); aerr != nil {
		t.Fatal(aerr)
	}
	cp, err := l.Checkpoint(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	xv, err := xnote.NewVerifier(tallytest.TestVerifierKey)
	if err != nil {
		t.Fatal(err)
	}
	n, err := xnote.Open(cp, xnote.VerifierList(xv))
	if err != nil {
		t.Fatalf("x/mod does not open a checkpoint tally signed: %v\n%s", err, cp)
	}

	// The reverse: x/mod signs the same body; tally opens it and its Verify
	// accepts it as a checkpoint of this log.
	xs, err := xnote.NewSigner(tallytest.TestSignerKey)
	if err != nil {
		t.Fatal(err)
	}
	xcp, err := xnote.Sign(&xnote.Note{Text: n.Text}, xs)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(xcp, cp) {
		t.Fatalf("for one key and one text the implementations sign different bytes:\n%s\n%s", xcp, cp)
	}
	keys, err := tally.NewVerifiers(tallytest.TestVerifierKey)
	if err != nil {
		t.Fatal(err)
	}
	src := &memWithCheckpoint{MemStore: mem, cp: tally.SignedCheckpoint(xcp)}
	rep, err := tally.Verify(context.Background(), src, keys)
	if err != nil || !rep.OK() || rep.AttestedSize != 2 {
		t.Fatalf("tally's Verify over x/mod's checkpoint: %+v, %v", rep, err)
	}
}

// memWithCheckpoint serves a MemStore's records with one given checkpoint.
type memWithCheckpoint struct {
	*tallytest.MemStore
	cp tally.SignedCheckpoint
}

func (m *memWithCheckpoint) Checkpoints(context.Context) iter.Seq2[tally.SignedCheckpoint, error] {
	return func(yield func(tally.SignedCheckpoint, error) bool) { yield(m.cp, nil) }
}

// Never looser: over random mutations of a valid note, whatever tally accepts
// x/mod accepts too. The other direction is allowed (SPEC §5: tally is
// stricter by design), and the cases where only x/mod accepts are counted.
//
// This is a sweep, not a targeted check: a random mutation almost always
// breaks the signature, so both sides reject it whatever their rules. Removing
// tally's control-character check did not make it fail;
// TestASignedControlCharacterIsRejectedByBoth is the targeted case.
func TestTallyIsNeverLooser(t *testing.T) {
	ts, tv, err := tnote.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{3}, 32)), "example.com/log")
	if err != nil {
		t.Fatal(err)
	}
	tSigner, _ := tnote.NewSigner(ts)
	tVer, _ := tnote.NewVerifier(tv)
	xVer, err := xnote.NewVerifier(tv)
	if err != nil {
		t.Fatal(err)
	}
	head := base64.StdEncoding.EncodeToString(make([]byte, 32))
	valid, err := tnote.Sign([]byte("example.com/log\ntally-chain/v1\n1\n"+head+"\n2026-11-10T12:00:00.000000000Z\nopen\n"), tSigner)
	if err != nil {
		t.Fatal(err)
	}

	r := rand.New(rand.NewPCG(30, 2026)) // #nosec G404 -- reproducible test data.
	const n = 50_000
	ran, tallyAccepted, onlyX := 0, 0, 0
	for range n {
		m := bytes.Clone(valid)
		for range 1 + r.IntN(3) {
			i := r.IntN(len(m))
			switch r.IntN(3) {
			case 0:
				m[i] ^= byte(1 + r.UintN(255)) // #nosec G115 -- below 256.
			case 1:
				m = append(m[:i], m[i+1:]...)
			default:
				m = append(m[:i], append([]byte{byte(r.UintN(256))}, m[i:]...)...) // #nosec G115 -- below 256.
			}
		}
		_, tErr := tnote.Open(m, []*tnote.Verifier{tVer})
		_, xErr := xnote.Open(m, xnote.VerifierList(xVer))
		ran++
		if tErr == nil {
			tallyAccepted++
			if xErr != nil {
				t.Fatalf("tally accepts a note x/mod rejects (%v):\n%q", xErr, m)
			}
		} else if xErr == nil {
			onlyX++
		}
	}
	if ran != n {
		t.Fatalf("ran %d of %d mutations", ran, n)
	}
	t.Logf("%d mutations: tally accepted %d, only x/mod accepted %d", n, tallyAccepted, onlyX)
}

// Over the limits tally sets and x/mod does not, tally rejects what x/mod
// accepts, and never the reverse (SPEC §8).
func TestTallyRejectsWhatOnlyItsLimitsForbid(t *testing.T) {
	ts, tv, err := tnote.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{4}, 32)), "k")
	if err != nil {
		t.Fatal(err)
	}
	tSigner, _ := tnote.NewSigner(ts)
	tVer, _ := tnote.NewVerifier(tv)
	xVer, _ := xnote.NewVerifier(tv)
	one, err := tnote.Sign([]byte("text\n"), tSigner)
	if err != nil {
		t.Fatal(err)
	}
	sig := one[bytes.LastIndex(one, []byte("\n\n"))+2:]
	seventeen := append(bytes.Clone(one), bytes.Repeat(sig, 16)...)
	if _, err := xnote.Open(seventeen, xnote.VerifierList(xVer)); err != nil {
		t.Fatalf("x/mod rejects 17 signature lines: %v", err)
	}
	if _, err := tnote.Open(seventeen, []*tnote.Verifier{tVer}); err == nil {
		t.Fatal("tally accepts 17 signature lines, over SPEC §6's 16")
	}
}

// A note holding a control character, validly signed, so that only the
// envelope rule can reject it (SPEC §5.1). x/mod rejects it, and tally must
// too: accepting it would make tally looser. The envelope is built by hand,
// since both Sign functions refuse such a text.
//
// Negative control: removing tally's control-character check made this fail.
func TestASignedControlCharacterIsRejectedByBoth(t *testing.T) {
	ts, tv, err := tnote.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{5}, 32)), "k")
	if err != nil {
		t.Fatal(err)
	}
	s, _ := tnote.NewSigner(ts)
	tVer, _ := tnote.NewVerifier(tv)
	xVer, _ := xnote.NewVerifier(tv)

	text := []byte("a\x01b\n")
	sig, err := s.Sign(text)
	if err != nil {
		t.Fatal(err)
	}
	raw := binary.BigEndian.AppendUint32(nil, s.KeyHash())
	msg := append(bytes.Clone(text), "\n— k "+base64.StdEncoding.EncodeToString(append(raw, sig...))+"\n"...)

	if _, err := xnote.Open(msg, xnote.VerifierList(xVer)); err == nil {
		t.Fatal("x/mod accepted a control character; the test's premise is wrong")
	}
	if _, err := tnote.Open(msg, []*tnote.Verifier{tVer}); err == nil {
		t.Fatal("tally accepted a signed note holding a control character, which x/mod rejects")
	}
}
