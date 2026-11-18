package attack_test

import (
	"bytes"
	"context"
	"fmt"
	"iter"
	"slices"
	"testing"
	"time"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/internal/note"
	"github.com/JonasBorgesLM/tally/tallytest"
)

// source is a tally.Source an attacker can rewrite: records and checkpoints
// in memory, records numbered by position, as a store returns them.
type source struct {
	bodies [][]byte
	cps    []tally.SignedCheckpoint
}

func (s *source) Records(_ context.Context, from uint64) iter.Seq2[tally.Record, error] {
	return func(yield func(tally.Record, error) bool) {
		for i, b := range s.bodies {
			if uint64(i) >= from && !yield(tally.Record{Seq: uint64(i), Body: slices.Clone(b)}, nil) { // #nosec G115 -- a slice index
				return
			}
		}
	}
}

func (s *source) Checkpoints(context.Context) iter.Seq2[tally.SignedCheckpoint, error] {
	return func(yield func(tally.SignedCheckpoint, error) bool) {
		for _, cp := range s.cps {
			if !yield(slices.Clone(cp), nil) {
				return
			}
		}
	}
}

// anchorList is an AnchorReader holding what the anchor received.
type anchorList []tally.SignedCheckpoint

func (a anchorList) Checkpoints(context.Context) iter.Seq2[tally.SignedCheckpoint, error] {
	return func(yield func(tally.SignedCheckpoint, error) bool) {
		for _, cp := range a {
			if !yield(slices.Clone(cp), nil) {
				return
			}
		}
	}
}

func signer(t *testing.T, skey string) tally.Signer {
	t.Helper()
	s, err := note.NewSigner(skey)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func keys(t *testing.T) tally.Verifiers {
	t.Helper()
	k, err := tally.NewVerifiers(tallytest.TestVerifierKey)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// attackerKey is a key under the log's name that the verifier does not trust.
func attackerKey(t *testing.T) string {
	t.Helper()
	skey, _, err := note.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0x66}, 32)), "example.com/log")
	if err != nil {
		t.Fatal(err)
	}
	return skey
}

func event(id, resource string) tally.Event {
	return tally.Event{ID: tally.EventID(id), OccurredAt: time.Unix(1_700_000_000, 0), Actor: tally.System(),
		Action: "doc.read", Resource: resource, Outcome: tally.OutcomeSuccess}
}

// writeLog writes entries named by ids under skey, with a checkpoint after
// each entry number in cpAt, and closes it, which signs a closing checkpoint.
// genesis, if non-zero, fixes the random source and the clock, so two logs
// written with the same value share a genesis and diverge after it: what a
// host rewriting its history produces.
func writeLog(t *testing.T, skey string, genesis byte, ids []string, cpAt ...int) *source {
	t.Helper()
	ctx := context.Background()
	mem := tallytest.NewMemStore()
	opts := []tally.Option{tally.WithCheckpointEvery(0, 0)}
	clock := tallytest.NewFixedClock(time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC))
	if genesis != 0 {
		opts = append(opts, tally.WithRand(bytes.NewReader(bytes.Repeat([]byte{genesis}, 16))), tally.WithClock(clock))
	}
	l, err := tally.Open(ctx, keepOpen{mem}, signer(t, skey), opts...)
	if err != nil {
		t.Fatal(err)
	}
	for i, id := range ids {
		clock.Advance(time.Second)
		if _, err := l.Append(ctx, event(id, "doc-"+id)); err != nil {
			t.Fatal(err)
		}
		if slices.Contains(cpAt, i+1) {
			if _, err := l.Checkpoint(ctx); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	src := &source{}
	for r, err := range mem.Records(ctx, 0) {
		if err != nil {
			t.Fatal(err)
		}
		src.bodies = append(src.bodies, r.Body)
	}
	for cp, err := range mem.Checkpoints(ctx) {
		if err != nil {
			t.Fatal(err)
		}
		src.cps = append(src.cps, cp)
	}
	return src
}

func ids(n int, prefix string) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s%d", prefix, i)
	}
	return out
}

// keepOpen lets a test read a MemStore after the Log closes it.
type keepOpen struct{ tally.Store }

func (keepOpen) Close() error { return nil }

func verify(t *testing.T, src tally.Source, opts ...tally.VerifyOption) *tally.Report {
	t.Helper()
	rep, err := tally.Verify(context.Background(), src, keys(t), opts...)
	if err != nil {
		t.Fatalf("Verify could not verify: %v", err)
	}
	return rep
}

// detected asserts that rep reports kind, the expected detection, and not
// merely that something failed.
func detected(t *testing.T, rep *tally.Report, kind tally.FailureKind) {
	t.Helper()
	for _, f := range rep.Failures {
		if f.Kind == kind {
			return
		}
	}
	t.Fatalf("want %v reported; got OK=%v, failures %+v", kind, rep.OK(), rep.Failures)
}

// undetected asserts a threat's documented limit: the attack verifies OK.
func undetected(t *testing.T, rep *tally.Report) {
	t.Helper()
	if !rep.OK() {
		t.Fatalf("the limit asserted here is that this goes undetected; got %+v", rep.Failures)
	}
}
