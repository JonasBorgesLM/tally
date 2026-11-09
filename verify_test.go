package tally_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"iter"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/internal/note"
	"github.com/JonasBorgesLM/tally/tallytest"
)

// sliceSource is a Source a test can tamper with.
type sliceSource struct {
	recs []tally.Record
	cps  []tally.SignedCheckpoint
	err  error // returned after the records, to simulate an IO failure
}

func (s *sliceSource) Records(_ context.Context, from uint64) iter.Seq2[tally.Record, error] {
	return func(yield func(tally.Record, error) bool) {
		for _, r := range s.recs {
			if r.Seq >= from && !yield(tally.Record{Seq: r.Seq, Body: slices.Clone(r.Body)}, nil) {
				return
			}
		}
		if s.err != nil {
			yield(tally.Record{}, s.err)
		}
	}
}

func (s *sliceSource) Checkpoints(context.Context) iter.Seq2[tally.SignedCheckpoint, error] {
	return func(yield func(tally.SignedCheckpoint, error) bool) {
		for _, cp := range s.cps {
			if !yield(slices.Clone(cp), nil) {
				return
			}
		}
	}
}

func testKeys(t *testing.T) tally.Verifiers {
	t.Helper()
	k, err := tally.NewVerifiers(tallytest.TestVerifierKey)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// honestLog writes n entries with a checkpoint after each in cpAt, and returns
// the log as a sliceSource, closed checkpoint included.
func honestLog(t *testing.T, n int, cpAt ...int) *sliceSource {
	t.Helper()
	mem := tallytest.NewMemStore()
	l, err := tally.Open(context.Background(), keepOpen{mem}, testOrigin, tally.WithCheckpointEvery(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		if _, err := l.Append(context.Background(), event("e"+strconv.Itoa(i))); err != nil {
			t.Fatal(err)
		}
		if slices.Contains(cpAt, i+1) {
			if _, err := l.Checkpoint(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
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
	return src
}

// signedCheckpoint crafts a checkpoint body and signs it with skey.
func signedCheckpoint(t *testing.T, skey, origin string, size uint64, head [32]byte, at, state string) tally.SignedCheckpoint {
	t.Helper()
	s, err := note.NewSigner(skey)
	if err != nil {
		t.Fatal(err)
	}
	text := origin + "\ntally-chain/v1\n" + strconv.FormatUint(size, 10) + "\n" +
		base64.StdEncoding.EncodeToString(head[:]) + "\n" + at + "\n" + state + "\n"
	cp, err := note.Sign([]byte(text), s)
	if err != nil {
		t.Fatal(err)
	}
	return cp
}

func verify(t *testing.T, src tally.Source, opts ...tally.VerifyOption) *tally.Report {
	t.Helper()
	rep, err := tally.Verify(context.Background(), src, testKeys(t), opts...)
	if err != nil {
		t.Fatalf("Verify returned an error, not a report: %v", err)
	}
	return rep
}

func kinds(rep *tally.Report) []tally.FailureKind {
	out := make([]tally.FailureKind, 0, len(rep.Failures))
	for _, f := range rep.Failures {
		out = append(out, f.Kind)
	}
	return out
}

func TestAnHonestLogVerifies(t *testing.T) {
	src := honestLog(t, 10, 4, 10)
	rep := verify(t, src)
	if !rep.OK() || rep.Size != 11 || rep.AttestedSize != 11 || rep.UnattestedEntries != 0 {
		t.Fatalf("report %+v", rep)
	}
}

// #27: every failure kind that needs no anchor and no full-attestation
// requirement is produced by Verify itself. HeartbeatGap needs anchor
// checkpoints and the caller's time (#29); UnattestedTail needs the
// requirement (#28).
func TestEveryKindIsProduced(t *testing.T) {
	const at = "2026-11-10T12:00:00.000000000Z"

	cases := map[tally.FailureKind]func(t *testing.T) *sliceSource{
		tally.MalformedRecord: func(t *testing.T) *sliceSource {
			src := honestLog(t, 3)
			src.recs[2].Body = []byte{0x01, 0x02, 0x03}
			src.cps = nil
			return src
		},
		tally.PrevHashMismatch: func(t *testing.T) *sliceSource {
			src := honestLog(t, 3)
			src.recs[1].Body[offOccurredAt] ^= 1 // entry 1 still decodes; its hash changes
			src.cps = nil
			return src
		},
		tally.SeqGap: func(t *testing.T) *sliceSource {
			src := honestLog(t, 3)
			src.recs = append(src.recs[:2], src.recs[3:]...)
			for i := range src.recs {
				src.recs[i].Seq = uint64(i)
			}
			src.cps = nil
			return src
		},
		tally.SeqRegression: func(t *testing.T) *sliceSource {
			src := honestLog(t, 3)
			dup := src.recs[1]
			src.recs = append(src.recs[:2], append([]tally.Record{dup}, src.recs[2:]...)...)
			for i := range src.recs {
				src.recs[i].Seq = uint64(i)
			}
			src.cps = nil
			return src
		},
		tally.TimeRegression: func(t *testing.T) *sliceSource {
			// Two checkpoints in size order whose times go back.
			src := honestLog(t, 3)
			h1, h2 := leaf(src.recs[1].Body), leaf(src.recs[2].Body)
			src.cps = []tally.SignedCheckpoint{
				signedCheckpoint(t, tallytest.TestSignerKey, "example.com/log", 2, h1, "2099-01-01T00:00:00.000000000Z", "open"),
				signedCheckpoint(t, tallytest.TestSignerKey, "example.com/log", 3, h2, "2099-01-01T00:00:00.000000000Z", "open"),
			}
			src.cps[1] = signedCheckpoint(t, tallytest.TestSignerKey, "example.com/log", 3, h2, "2098-01-01T00:00:00.000000000Z", "open")
			return src
		},
		tally.NonCanonicalEncoding: func(t *testing.T) *sliceSource {
			src := honestLog(t, 1)
			s, _ := note.NewSigner(tallytest.TestSignerKey)
			h := leaf(src.recs[1].Body)
			b64 := base64.StdEncoding.EncodeToString(h[:]) // 44 chars, one '=' of padding
			alpha := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
			c := strings.IndexByte(alpha, b64[42])
			mutated := b64[:42] + string(alpha[c^1]) + b64[43:] // flips a padding bit
			text := "example.com/log\ntally-chain/v1\n2\n" + mutated + "\n" + at + "\nopen\n"
			cp, err := note.Sign([]byte(text), s)
			if err != nil {
				t.Fatal(err)
			}
			src.cps = []tally.SignedCheckpoint{cp}
			return src
		},
		tally.BadSignature: func(t *testing.T) *sliceSource {
			src := honestLog(t, 1, 1)
			cp := []byte(src.cps[0])
			cp[3] ^= 1 // the text no longer matches its trusted signature
			src.cps = []tally.SignedCheckpoint{cp}
			return src
		},
		tally.UnknownKey: func(t *testing.T) *sliceSource {
			src := honestLog(t, 1)
			src.cps = []tally.SignedCheckpoint{signedCheckpoint(t, mustOtherKey(t), "example.com/log", 2, leaf(src.recs[1].Body), at, "open")}
			return src
		},
		tally.CheckpointMismatch: func(t *testing.T) *sliceSource {
			src := honestLog(t, 2)
			src.cps = []tally.SignedCheckpoint{signedCheckpoint(t, tallytest.TestSignerKey, "example.com/log", 2, leaf(src.recs[0].Body), at, "open")}
			return src
		},
		tally.TruncatedBelowCheckpoint: func(t *testing.T) *sliceSource {
			src := honestLog(t, 3, 3)
			src.recs = src.recs[:3]
			return src
		},
		tally.ForkDetected: func(t *testing.T) *sliceSource {
			src := honestLog(t, 2)
			src.cps = []tally.SignedCheckpoint{
				signedCheckpoint(t, tallytest.TestSignerKey, "example.com/log", 5, [32]byte{1}, at, "open"),
				signedCheckpoint(t, tallytest.TestSignerKey, "example.com/log", 5, [32]byte{2}, at, "open"),
			}
			return src
		},
		tally.PrunedWithoutTrustedCheckpoint: func(t *testing.T) *sliceSource {
			src := honestLog(t, 3)
			src.recs = src.recs[2:] // leaves 0 and 1 are gone
			src.cps = nil
			return src
		},
	}
	for want, build := range cases {
		t.Run(want.String(), func(t *testing.T) {
			rep := verify(t, build(t))
			found := false
			for _, k := range kinds(rep) {
				found = found || k == want
			}
			if !found || rep.OK() {
				t.Fatalf("failures %v (%+v), want %v among them", kinds(rep), rep.Failures, want)
			}
		})
	}
}

// RF-08: verifying from a checkpoint gives the same verdict as a full run, on
// an honest log and on one whose tampering lies past the start.
//
// Negative control: starting the incremental read at leaf s instead of s-1,
// so that the start checkpoint is never compared, made the tampered case
// differ from the full run.
func TestIncrementalMatchesAFullRun(t *testing.T) {
	src := honestLog(t, 12, 4, 8, 12)
	full, inc := verify(t, src), verify(t, src, tally.FromCheckpoint(src.cps[0])) // the size-5 checkpoint
	if !full.OK() || !inc.OK() || full.Size != inc.Size || full.AttestedSize != inc.AttestedSize {
		t.Fatalf("honest log: full %+v, incremental %+v", full, inc)
	}

	tampered := honestLog(t, 12, 4, 8, 12)
	tampered.recs[9].Body[offOccurredAt] ^= 1 // past the start
	full, inc = verify(t, tampered), verify(t, tampered, tally.FromCheckpoint(tampered.cps[0]))
	if full.OK() || inc.OK() || !slices.Equal(kinds(full), kinds(inc)) || full.Size != inc.Size {
		t.Fatalf("tampered past the start: full %v size %d, incremental %v size %d",
			kinds(full), full.Size, kinds(inc), inc.Size)
	}

	// Tampering below the start is the start checkpoint's to attest, so the
	// incremental run reads past it: the change shows only if it reaches the
	// start's own leaf.
	below := honestLog(t, 12, 4, 8, 12)
	below.recs[4].Body[offOccurredAt] ^= 1 // leaf 4, the start's head
	if inc := verify(t, below, tally.FromCheckpoint(below.cps[0])); inc.OK() {
		t.Fatal("a change to the start checkpoint's own leaf passed the incremental run")
	}
}

// SPEC §7.1, RS-04: a read that fails is Verify's error, never a Report, and
// never a partial read reported as success.
//
// Negative control: ending the record loop on a source error instead of
// returning it made this fail (a report came back OK over a partial read).
func TestCouldNotVerifyIsAnErrorNotAReport(t *testing.T) {
	ioErr := errors.New("disk read failed")
	partial := honestLog(t, 5)
	partial.recs = partial.recs[:3]
	partial.err = ioErr

	cases := map[string]struct {
		src  tally.Source
		opts []tally.VerifyOption
	}{
		"IO error mid-read": {src: partial},
		"no record at all":  {src: &sliceSource{}},
		"an untrusted start": {
			src: honestLog(t, 2),
			opts: []tally.VerifyOption{tally.FromCheckpoint(
				signedCheckpoint(t, mustOtherKey(t), "example.com/log", 2, [32]byte{}, "2026-11-10T12:00:00.000000000Z", "open"))},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rep, err := tally.Verify(context.Background(), tc.src, testKeys(t), tc.opts...)
			if err == nil || rep != nil {
				t.Fatalf("Verify = %+v, %v; want an error and no report", rep, err)
			}
		})
	}
	if _, err := tally.Verify(context.Background(), partial, testKeys(t)); !errors.Is(err, ioErr) {
		t.Fatalf("the IO error is not wrapped: %v", err)
	}
}

func mustOtherKey(t *testing.T) string {
	t.Helper()
	skey, _, err := note.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{9}, 32)), "example.com/log")
	if err != nil {
		t.Fatal(err)
	}
	return skey
}

// The Report states what it asserts: Size, AttestedSize and the unattested
// tail in leaves (SPEC §7 step 9).
func TestTheReportCountsTheAttestedPrefix(t *testing.T) {
	src := honestLog(t, 6, 2) // a checkpoint at size 3; Close adds one at 7
	src.cps = src.cps[:1]     // keep only the size-3 checkpoint
	rep := verify(t, src)
	if !rep.OK() || rep.Size != 7 || rep.AttestedSize != 3 || rep.UnattestedEntries != 4 {
		t.Fatalf("report %+v, want OK with Size 7, AttestedSize 3, UnattestedEntries 4", rep)
	}
}

// A start checkpoint that is not accepted is ErrUntrustedStart, named for what
// went wrong: any other error would pass a test that only asks for one.
//
// Negative control: accepting the start without checking it made this fail.
// The run still ended in an error, for another reason, which is why the
// cases above cannot stand in for this one.
func TestAnUntrustedStartIsNamed(t *testing.T) {
	src := honestLog(t, 2)
	cp := signedCheckpoint(t, mustOtherKey(t), "example.com/log", 2, leaf(src.recs[1].Body), "2026-11-10T12:00:00.000000000Z", "open")
	if _, err := tally.Verify(context.Background(), src, testKeys(t), tally.FromCheckpoint(cp)); !errors.Is(err, tally.ErrUntrustedStart) {
		t.Fatalf("Verify = %v, want ErrUntrustedStart", err)
	}
}
