package tally_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/tallytest"
)

// testAnchor records what it publishes. Until release is closed, Publish
// blocks: until ctx is done if cooperative, or regardless if not. failFirst
// makes the first n calls fail.
type testAnchor struct {
	release     chan struct{}
	cooperative bool
	failFirst   int

	mu        sync.Mutex
	calls     int
	published []tally.SignedCheckpoint
	started   chan struct{} // receives once per Publish call, if not nil
}

func newTestAnchor() *testAnchor {
	a := &testAnchor{release: make(chan struct{}), cooperative: true}
	close(a.release)
	return a
}

func blockedAnchor(cooperative bool) *testAnchor {
	return &testAnchor{release: make(chan struct{}), cooperative: cooperative, started: make(chan struct{}, 100)}
}

func (a *testAnchor) Publish(ctx context.Context, cp tally.SignedCheckpoint) error {
	a.mu.Lock()
	a.calls++
	call := a.calls
	a.mu.Unlock()
	if a.started != nil {
		a.started <- struct{}{}
	}
	if a.cooperative {
		select {
		case <-a.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	} else {
		<-a.release
	}
	if call <= a.failFirst {
		return fmt.Errorf("anchor unreachable (call %d)", call)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.published = append(a.published, slices.Clone(cp))
	return nil
}

func (a *testAnchor) got() []tally.SignedCheckpoint {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.published)
}

// anchorObserver records AnchorPublish calls. Its fields are not guarded: the
// Observer is never called concurrently, and the race detector holds tally to
// that.
type anchorObserver struct {
	errs    []error
	dropped []uint64
}

func (*anchorObserver) Batch(int, time.Duration)      {}
func (*anchorObserver) DiskSpace(uint64)              {}
func (*anchorObserver) ClockRegression(time.Duration) {}
func (*anchorObserver) Poisoned(error)                {}
func (*anchorObserver) Recovered(int64)               {}
func (o *anchorObserver) AnchorPublish(err error, dropped uint64) {
	o.errs = append(o.errs, err)
	o.dropped = append(o.dropped, dropped)
}

// A blocked anchor does not delay Append: with a checkpoint after every entry
// and the anchor stuck on the first, every Append still returns (RF-07).
//
// Seen failing with enqueue publishing synchronously instead of queueing.
func TestABlockedAnchorDoesNotDelayAppend(t *testing.T) {
	ctx := context.Background()
	a := blockedAnchor(true)
	l := open(t, tallytest.NewMemStore(), tally.WithAnchors(a), tally.WithAnchorQueue(4),
		tally.WithCheckpointEvery(1, 0), tally.WithMaxDelay(0))

	done := make(chan error, 1)
	go func() {
		for i := range 50 {
			if _, err := l.Append(ctx, event(fmt.Sprint(i))); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Append is blocked behind the anchor")
	}
	if got := a.got(); len(got) != 0 {
		t.Fatalf("the blocked anchor published %d checkpoints", len(got))
	}
	close(a.release)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if got := a.got(); len(got) == 0 || !bytes.Contains(got[len(got)-1], []byte("\nclosed\n")) {
		t.Fatalf("the anchor's last checkpoint is not the closing one: %d published", len(got))
	}
}

// A full queue drops the oldest checkpoint other than the newest, counts it,
// and tells the Observer each time; the newest always reaches the anchor
// (RF-19).
//
// Seen failing with push dropping the incoming checkpoint instead of the
// oldest, and with the drop not reported.
func TestAFullQueueDropsTheOldestAndCountsIt(t *testing.T) {
	ctx := context.Background()
	a := blockedAnchor(true)
	o := &anchorObserver{}
	l := open(t, tallytest.NewMemStore(), tally.WithAnchors(a), tally.WithAnchorQueue(3),
		tally.WithCheckpointEvery(0, 0), tally.WithObserver(o), tally.WithMaxDelay(0))

	cps := make([]tally.SignedCheckpoint, 0, 10)
	for i := range 10 {
		if _, err := l.Append(ctx, event(fmt.Sprint(i))); err != nil {
			t.Fatal(err)
		}
		cp, err := l.Checkpoint(ctx)
		if err != nil {
			t.Fatal(err)
		}
		cps = append(cps, cp)
		if i == 0 {
			<-a.started // the first is in flight, still queued
		}
	}
	// 10 into a queue of 3: 7 dropped, each reported, with a running count.
	if want := []uint64{1, 2, 3, 4, 5, 6, 7}; !slices.Equal(o.dropped, want) {
		t.Fatalf("reported drops %v, want %v", o.dropped, want)
	}
	for _, err := range o.errs {
		if !errors.Is(err, tally.ErrAnchorQueueFull) {
			t.Fatalf("a drop reported as %v", err)
		}
	}

	close(a.release)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	got := a.got()
	// The first was in flight when it was dropped; the last three, and then
	// the closing checkpoint, follow.
	want := append([]tally.SignedCheckpoint{cps[0]}, cps[7:]...)
	if len(got) != len(want)+1 {
		t.Fatalf("published %d checkpoints, want %d", len(got), len(want)+1)
	}
	for i, cp := range want {
		if !bytes.Equal(got[i], cp) {
			t.Errorf("published[%d] is not the expected checkpoint", i)
		}
	}
}

// Close is bounded when the anchor hangs, whether or not its Publish honours
// the context, and reports what it left unpublished (RF-19).
//
// Seen failing with flushAnchors waiting for the publishers without a
// deadline.
func TestCloseIsBoundedWhenTheAnchorHangs(t *testing.T) {
	for _, cooperative := range []bool{true, false} {
		t.Run(fmt.Sprintf("cooperative=%v", cooperative), func(t *testing.T) {
			a := blockedAnchor(cooperative)
			defer close(a.release) // let a non-cooperative Publish return after the test
			l := open(t, tallytest.NewMemStore(), tally.WithAnchors(a),
				tally.WithCheckpointEvery(0, 0), tally.WithAnchorFlushTimeout(100*time.Millisecond))
			if _, err := l.Append(context.Background(), event("a")); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- l.Close() }()
			select {
			case err := <-done:
				if !errors.Is(err, tally.ErrAnchorUnflushed) {
					t.Fatalf("Close = %v, want ErrAnchorUnflushed", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Close did not return while the anchor hung")
			}
		})
	}
}

// A failed publication is reported and retried, after a backoff on the Log's
// Clock, until it succeeds (RF-07).
//
// Seen failing with the retry removed: the checkpoint is then never
// published.
func TestAFailedPublicationIsReportedAndRetried(t *testing.T) {
	clock := tallytest.NewFixedClock(time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC))
	a := newTestAnchor()
	a.failFirst = 2
	o := &anchorObserver{}
	l := open(t, tallytest.NewMemStore(), tally.WithAnchors(a), tally.WithClock(clock),
		tally.WithCheckpointEvery(0, 0), tally.WithObserver(o))
	cp, err := l.Checkpoint(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Two failures, each followed by a backoff timer the test fires.
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		for deadline := time.Now().Add(10 * time.Second); !cond(); time.Sleep(time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s", what)
			}
		}
	}
	for range 2 {
		waitFor("a backoff timer", func() bool { return clock.Timers() > 0 })
		clock.Advance(time.Minute)
	}
	waitFor("the publication", func() bool { return len(a.got()) > 0 })
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if len(o.errs) != 2 || errors.Is(o.errs[0], tally.ErrAnchorQueueFull) {
		t.Fatalf("reported %v, want the two failures", o.errs)
	}
	got := a.got()
	if len(got) < 1 || !bytes.Equal(got[0], cp) {
		t.Fatalf("published %d checkpoints; the retried one first", len(got))
	}
}

// Close publishes what is queued, the closing checkpoint last, and leaves no
// goroutine behind (RF-19, RNF-06).
func TestCloseFlushesTheAnchors(t *testing.T) {
	checkNoLeaks(t)
	a, b := newTestAnchor(), newTestAnchor()
	l := open(t, tallytest.NewMemStore(), tally.WithAnchors(a, b), tally.WithCheckpointEvery(2, 0))
	for i := range 5 {
		if _, err := l.Append(context.Background(), event(fmt.Sprint(i))); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	for _, anchor := range []*testAnchor{a, b} {
		got := anchor.got()
		if len(got) < 2 || !bytes.Contains(got[len(got)-1], []byte("\nclosed\n")) {
			t.Fatalf("an anchor got %d checkpoints, the closing one not last", len(got))
		}
	}
}
