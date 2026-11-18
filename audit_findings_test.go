package tally_test

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/internal/note"
	"github.com/JonasBorgesLM/tally/tallytest"
)

// Findings A-04 and A-06 of the clean-session audit (#56, #128).

// A log with no record left at or after a checkpoint is a truncation below
// it, reported as a violation, not an error (RS-04): both incrementally, from
// a start checkpoint past the end, and with every record gone and an anchor
// holding a checkpoint. With no checkpoint at all, an empty source stays an
// error: it is more likely the wrong directory than a log.
//
// Seen failing with the !read branch returning the error unconditionally.
func TestNoRecordBelowACheckpointIsATruncation(t *testing.T) {
	ctx := context.Background()
	full := honestLog(t, 8, 8) // a checkpoint at size 9
	var start tally.SignedCheckpoint
	for _, cp := range full.cps {
		if strings.Contains(string(cp), "\n9\n") {
			start = cp
		}
	}
	if start == nil {
		t.Fatal("no checkpoint at size 9 to start from")
	}

	short := &sliceSource{recs: full.recs[:5], cps: nil}
	rep := verify(t, short, tally.FromCheckpoint(start))
	if !hasKind(rep, tally.TruncatedBelowCheckpoint) {
		t.Fatalf("incremental from size 9 over 5 records = %+v, want TruncatedBelowCheckpoint", rep.Failures)
	}

	empty := &sliceSource{}
	rep = verify(t, empty, tally.WithAnchor(anchorList{start}))
	if !hasKind(rep, tally.TruncatedBelowCheckpoint) || rep.OK() {
		t.Fatalf("no record, an anchor at size 9 = %+v, want TruncatedBelowCheckpoint", rep.Failures)
	}

	if _, err := tally.Verify(ctx, empty, testKeys(t)); err == nil {
		t.Fatal("an empty source with no checkpoint verified rather than erring")
	}
}

// When genesis itself is a violation, the result is that violation with
// Size 0, and nothing after it runs (SPEC §7 step 3): not an error about
// origins, which come from genesis.
//
// Seen failing with the early return after a genesis violation removed: the
// two origins became an error.
func TestABrokenGenesisIsTheResult(t *testing.T) {
	src := honestLog(t, 2)
	src.recs[0].Body = src.recs[0].Body[:len(src.recs[0].Body)-1] // genesis no longer decodes

	otherSkey, otherVkey, err := note.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0x31}, 32)), "example.org/other")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := tally.NewVerifiers(tallytest.TestVerifierKey, otherVkey)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC).Format("2006-01-02T15:04:05.000000000Z")
	src.cps = append(src.cps, signedCheckpoint(t, otherSkey, "example.org/other", 3, [32]byte{1}, at, "open"))

	rep, err := tally.Verify(context.Background(), src, keys)
	if err != nil {
		t.Fatalf("Verify = %v, want the genesis violation as a report", err)
	}
	if rep.Size != 0 || !hasKind(rep, tally.MalformedRecord) {
		t.Fatalf("report = %+v, want Size 0 and the genesis MalformedRecord", rep)
	}
	for _, f := range rep.Failures {
		if f.Kind == tally.TruncatedBelowCheckpoint || f.Kind == tally.ForkDetected || f.Kind == tally.TimeRegression {
			t.Errorf("step 5 to 8 ran after a genesis violation: %+v", f)
		}
	}
}

// An anchored checkpoint dated after now, beyond the tolerance, is reported
// under a heartbeat check: its gap to now is negative, and would otherwise
// hide a stop behind it (audit A-06).
//
// Seen failing with the future check removed from heartbeatGaps.
func TestAFutureCheckpointIsAHeartbeatViolation(t *testing.T) {
	src := honestLog(t, 2)
	head := leaf(src.recs[2].Body)
	src.cps = nil
	t0 := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	future := signedCheckpoint(t, tallytest.TestSignerKey, "example.com/log", 3, head,
		time.Date(2262, 4, 11, 0, 0, 0, 0, time.UTC).Format("2006-01-02T15:04:05.000000000Z"), "open")
	rep := verify(t, src, tally.WithAnchor(anchorList{future}), tally.WithHeartbeat(time.Minute, 30*time.Second, t0))
	if !hasKind(rep, tally.HeartbeatGap) {
		t.Fatalf("a checkpoint dated 2262 under a heartbeat at %v = %+v, want HeartbeatGap", t0, rep.Failures)
	}

	// Within the tolerance, a clock slightly ahead is not a violation.
	near := signedCheckpoint(t, tallytest.TestSignerKey, "example.com/log", 3, head,
		t0.Add(10*time.Second).Format("2006-01-02T15:04:05.000000000Z"), "open")
	if rep = verify(t, src, tally.WithAnchor(anchorList{near}), tally.WithHeartbeat(time.Minute, 30*time.Second, t0)); hasKind(rep, tally.HeartbeatGap) {
		t.Fatalf("a checkpoint 10 s ahead, tolerance 30 s = %+v, want no HeartbeatGap", rep.Failures)
	}
}
