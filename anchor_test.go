package tally_test

import (
	"bytes"
	"context"
	"iter"
	"slices"
	"testing"
	"time"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/tallytest"
)

// anchorList is an AnchorReader over checkpoints a test chose: what an
// auditor reads off the host.
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

// sameGenesisLog writes a log whose genesis is fixed by the random source and
// the clock, so two calls with different ids share a genesis and diverge
// after it: what a key holder rewriting the history produces (T-07).
func sameGenesisLog(t *testing.T, ids []string, cpAt ...int) *sliceSource {
	t.Helper()
	mem := tallytest.NewMemStore()
	clock := tallytest.NewFixedClock(time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC))
	l, err := tally.Open(context.Background(), keepOpen{mem}, testOrigin,
		tally.WithRand(bytes.NewReader(bytes.Repeat([]byte{0x42}, 16))), tally.WithClock(clock),
		tally.WithCheckpointEvery(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	for i, id := range ids {
		clock.Advance(time.Second)
		if _, err := l.Append(context.Background(), event(id)); err != nil {
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

func hasKind(rep *tally.Report, k tally.FailureKind) bool {
	return slices.Contains(kinds(rep), k)
}

// T-05, truncating the end: the host deletes the newest entries and its own
// checkpoints over them. Nothing on the host disagrees; the anchor holds a
// checkpoint of larger size.
//
// Negative control: not reading the anchor in Verify made this fail (the
// truncated log verified).
func TestT05TruncationIsSeenOnlyAgainstTheAnchor(t *testing.T) {
	src := honestLog(t, 6, 6)
	anchor := anchorList{src.cps[0]} // size 7, published before the truncation
	src.recs, src.cps = src.recs[:4], nil

	if rep := verify(t, src); !rep.OK() {
		t.Fatalf("without the anchor the truncated log should verify, which is T-05's residual: %v", kinds(rep))
	}
	if rep := verify(t, src, tally.WithAnchor(anchor)); !hasKind(rep, tally.TruncatedBelowCheckpoint) {
		t.Fatalf("with the anchor: %v, want TruncatedBelowCheckpoint", kinds(rep))
	}
}

// T-08, rolling back to an older checkpoint: the host restores an earlier,
// consistent state, its own checkpoint included. The anchor holds a newer one.
//
// Negative control: not reading the anchor made this fail.
func TestT08RollbackIsSeenOnlyAgainstTheAnchor(t *testing.T) {
	src := honestLog(t, 6, 3, 6)                 // checkpoints at 4 and 7, then the closed one at 7
	anchor := anchorList{src.cps[0], src.cps[1]} // 4 and 7 were published
	src.recs, src.cps = src.recs[:4], src.cps[:1]

	if rep := verify(t, src); !rep.OK() {
		t.Fatalf("without the anchor the rolled-back log should verify: %v", kinds(rep))
	}
	if rep := verify(t, src, tally.WithAnchor(anchor)); !hasKind(rep, tally.TruncatedBelowCheckpoint) {
		t.Fatalf("with the anchor: %v, want TruncatedBelowCheckpoint", kinds(rep))
	}
}

// T-07, rewriting with the key: the host writes a different, fully consistent
// history after the shared genesis and signs it with the real key. Only a
// checkpoint published before the rewrite disagrees, and an anchored one that
// disagrees is a fork.
//
// Negative controls: not reading the anchor made this fail (the rewritten log
// verified); reporting an anchored mismatch as CheckpointMismatch made it fail
// on the kind.
func TestT07RewriteWithTheKeyIsAForkAgainstTheAnchor(t *testing.T) {
	original := sameGenesisLog(t, []string{"a", "b", "c", "d"}, 4)
	rewritten := sameGenesisLog(t, []string{"a", "b", "FORGED", "d"}, 4)
	if !bytes.Equal(original.recs[0].Body, rewritten.recs[0].Body) {
		t.Fatal("the two logs do not share a genesis; the test would prove nothing")
	}
	anchor := anchorList{original.cps[0]} // size 5, published before the rewrite

	if rep := verify(t, rewritten); !rep.OK() {
		t.Fatalf("without the anchor the rewritten log should verify, which is T-07's residual: %v", kinds(rep))
	}
	rep := verify(t, rewritten, tally.WithAnchor(anchor))
	if !hasKind(rep, tally.ForkDetected) || hasKind(rep, tally.CheckpointMismatch) {
		t.Fatalf("with the anchor: %v, want ForkDetected", kinds(rep))
	}
}

// T-15 and #29: a heartbeat gap is a stop the anchor saw. A clean Close marks
// its checkpoint closed, so a restart after it is no gap; a crash leaves an
// open checkpoint, and the same pause is a gap, for a human to judge.
//
// Negative controls: removing the gap check made the crash case pass;
// ignoring the closed state made the clean case fail.
func TestT15HeartbeatGaps(t *testing.T) {
	src := honestLog(t, 2)
	head := leaf(src.recs[2].Body)
	src.cps = nil
	t0 := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	cp := func(at time.Time, state string) tally.SignedCheckpoint {
		return signedCheckpoint(t, tallytest.TestSignerKey, "example.com/log", 3, head,
			at.Format("2006-01-02T15:04:05.000000000Z"), state)
	}
	const interval, tolerance = time.Minute, 30 * time.Second

	cases := map[string]struct {
		anchor  anchorList
		now     time.Time
		wantGap bool
	}{
		"steady heartbeats": {
			anchor: anchorList{cp(t0, "open"), cp(t0.Add(time.Minute), "open"), cp(t0.Add(2*time.Minute), "open")},
			now:    t0.Add(2*time.Minute + 10*time.Second),
		},
		"a crash: a long pause after an open checkpoint": {
			anchor:  anchorList{cp(t0, "open"), cp(t0.Add(time.Minute), "open"), cp(t0.Add(30*time.Minute), "open")},
			now:     t0.Add(30*time.Minute + 10*time.Second),
			wantGap: true,
		},
		"a clean stop and restart: the same pause after a closed checkpoint": {
			anchor: anchorList{cp(t0, "open"), cp(t0.Add(time.Minute), "closed"), cp(t0.Add(30*time.Minute), "open")},
			now:    t0.Add(30*time.Minute + 10*time.Second),
		},
		"silence since the last checkpoint": {
			anchor:  anchorList{cp(t0, "open")},
			now:     t0.Add(10 * time.Minute),
			wantGap: true,
		},
		"stopped cleanly and still stopped": {
			anchor: anchorList{cp(t0, "closed")},
			now:    t0.Add(10 * time.Minute),
		},
		"no anchored checkpoint at all": {
			anchor:  anchorList{},
			now:     t0,
			wantGap: true,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rep := verify(t, src, tally.WithAnchor(tc.anchor), tally.WithHeartbeat(interval, tolerance, tc.now))
			if got := hasKind(rep, tally.HeartbeatGap); got != tc.wantGap {
				t.Fatalf("HeartbeatGap reported: %v, want %v (failures %+v)", got, tc.wantGap, rep.Failures)
			}
		})
	}
}

// A heartbeat is judged on anchored checkpoints, so asking for one without an
// anchor is a misuse: an error, not a report.
func TestAHeartbeatWithoutAnAnchorIsAnError(t *testing.T) {
	rep, err := tally.Verify(context.Background(), honestLog(t, 1), testKeys(t),
		tally.WithHeartbeat(time.Minute, 0, time.Now()))
	if err == nil || rep != nil {
		t.Fatalf("Verify = %+v, %v; want an error", rep, err)
	}
}
