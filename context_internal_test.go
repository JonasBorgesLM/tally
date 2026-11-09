package tally

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"
)

// ADR-0010, R-09: Append's outcome under context cancellation. Cancelled
// before the entry reaches the writer's queue: ctx.Err(), and nothing is
// recorded. Cancelled after: ErrOutcomeUnknown, the entry may or may not be
// stored, and a retry with the same EventID yields exactly one entry either
// way. These tests are internal because they read the queue; none sleeps.

func ctxEvent(id string) Event {
	return Event{ID: EventID(id), OccurredAt: time.Unix(1, 0), Actor: System(),
		Action: "user.login", Outcome: OutcomeSuccess}
}

// entries returns the EventIDs of the stored entries, in order.
func (s *batchStore) entries(t *testing.T) []string {
	t.Helper()
	var ids []string
	for r, err := range s.Records(context.Background(), 1) {
		if err != nil {
			t.Fatal(err)
		}
		rec, err := decodeRecord(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, string(rec.(*entry).eventID))
	}
	return ids
}

// doneWatch signals the first call to Done. Append calls Err before trying to
// enqueue and Done only in the select that waits to enqueue, so reached closes
// when an Append is at that select.
type doneWatch struct {
	context.Context
	once    sync.Once
	reached chan struct{}
}

func (c *doneWatch) Done() <-chan struct{} {
	c.once.Do(func() { close(c.reached) })
	return c.Context.Done()
}

func openBatchStore(t *testing.T, s *batchStore, opts ...Option) *Log {
	t.Helper()
	l, err := Open(context.Background(), s, testSigner("example.com/log"), opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	t.Cleanup(s.unblock) // runs first: a test failing while the store is held must not hang Close
	return l
}

// An already-cancelled context never enqueues, even with room in the queue,
// where a select would otherwise choose at random between the two.
//
// Negative control: removing the ctx.Err() check before the select made this
// fail within the 200 rounds (an entry was recorded).
func TestACancelledContextNeverEnqueues(t *testing.T) {
	s := &batchStore{}
	l := openBatchStore(t, s)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	const rounds = 200
	for i := range rounds {
		r, err := l.Append(ctx, ctxEvent("e"))
		if !errors.Is(err, context.Canceled) || r != (Receipt{}) {
			t.Fatalf("round %d: Append = %+v, %v; want context.Canceled", i, r, err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if got := s.entries(t); len(got) != 0 {
		t.Fatalf("a cancelled Append was recorded: %v", got)
	}
}

// Blocked on a full queue, then cancelled: ctx.Err(), and the entry is never
// recorded, even after the writer drains the queue.
//
// Negative control: removing the ctx.Done case from the enqueue select made
// this fail ("Append never waited on its context"). Before doneWatch, the
// cancel ran ahead of the goroutine, the check before the select caught it,
// and that mutation passed: the test was not exercising its own path.
func TestCancelledWhileWaitingToEnqueue(t *testing.T) {
	s := &batchStore{block: 2, entered: make(chan struct{}), release: make(chan struct{})}
	l := openBatchStore(t, s, WithMaxBatch(1)) // a queue of one

	go func() { _, _ = l.Append(context.Background(), ctxEvent("held")) }()
	<-s.entered // the writer is in the store
	queued := make(chan error, 1)
	go func() { _, err := l.Append(context.Background(), ctxEvent("queued")); queued <- err }()
	for len(l.reqs) < 1 {
		runtime.Gosched()
	}

	// The queue is full, so this Append waits to enqueue. Cancel only once it
	// is waiting: cancelling earlier would test the check before the select.
	ctx, cancel := context.WithCancel(context.Background())
	wctx := &doneWatch{Context: ctx, reached: make(chan struct{})}
	waiting := make(chan error, 1)
	go func() { _, err := l.Append(wctx, ctxEvent("cancelled")); waiting <- err }()
	// The guards below fire only on failure; the normal path never waits on
	// them, so no outcome depends on time.
	select {
	case <-wctx.reached:
	case <-time.After(10 * time.Second):
		t.Fatal("Append never waited on its context while the queue was full")
	}
	cancel()
	select {
	case err := <-waiting:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Append cancelled before enqueueing = %v, want context.Canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Append did not return when cancelled while waiting to enqueue")
	}

	s.unblock()
	if err := <-queued; err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if got := s.entries(t); len(got) != 2 || got[0] != "held" || got[1] != "queued" {
		t.Fatalf("stored %v, want [held queued]: the cancelled entry must not be recorded", got)
	}
}

// Cancelled after the writer took the entry, which is then stored: the caller
// gets ErrOutcomeUnknown, and its retry is a duplicate of the stored entry.
//
// Negative control: returning ctx.Err() instead of ErrOutcomeUnknown after
// enqueueing made this fail.
func TestOutcomeUnknownThenStoredRetriesToOneEntry(t *testing.T) {
	s := &batchStore{block: 2, entered: make(chan struct{}), release: make(chan struct{})}
	l := openBatchStore(t, s)

	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { _, err := l.Append(ctx, ctxEvent("e1")); first <- err }()
	<-s.entered // the writer holds e1 in the store: it is past enqueueing
	cancel()
	if err := <-first; !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("Append cancelled after enqueueing = %v, want ErrOutcomeUnknown", err)
	}
	s.unblock() // the write completes after all

	r, err := l.Append(context.Background(), ctxEvent("e1"))
	if err != nil || !r.Duplicate || r.Seq != 1 {
		t.Fatalf("retry = %+v, %v; want the stored entry as a duplicate", r, err)
	}
	if got := s.entries(t); len(got) != 1 {
		t.Fatalf("stored %v, want exactly one entry", got)
	}
}

// Cancelled after enqueueing, but the entry is never stored, because the log
// closes before the writer reaches it: ErrOutcomeUnknown, and the retry on the
// reopened log records it exactly once.
//
// Negative control: removing the writer's priority for quit, so that it may
// start another batch after Close has asked, made this fail (e1 was written).
func TestOutcomeUnknownThenNotStoredRetriesToOneEntry(t *testing.T) {
	s := &batchStore{block: 2, entered: make(chan struct{}), release: make(chan struct{})}
	l, openErr := Open(context.Background(), s, testSigner("example.com/log"))
	if openErr != nil {
		t.Fatal(openErr)
	}
	t.Cleanup(func() { _ = l.Close() }) // idempotent; the test closes it itself
	t.Cleanup(s.unblock)

	go func() { _, _ = l.Append(context.Background(), ctxEvent("held")) }()
	<-s.entered

	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { _, err := l.Append(ctx, ctxEvent("e1")); first <- err }()
	for len(l.reqs) < 1 {
		runtime.Gosched() // e1 is in the queue: past enqueueing
	}
	cancel()
	if err := <-first; !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("Append cancelled after enqueueing = %v, want ErrOutcomeUnknown", err)
	}

	closed := make(chan error, 1)
	go func() { closed <- l.Close() }()
	// Close stops the writer before the next batch, so e1 is refused, unless
	// the writer already took it. Release the held batch once Close has asked.
	for {
		select {
		case <-l.quit:
		default:
			runtime.Gosched()
			continue
		}
		break
	}
	s.unblock()
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if got := s.entries(t); len(got) != 1 || got[0] != "held" {
		t.Fatalf("stored %v, want only [held]: e1 must not have been written", got)
	}

	l2 := openBatchStore(t, s)
	r, err := l2.Append(context.Background(), ctxEvent("e1"))
	if err != nil || r.Duplicate || r.Seq != 2 {
		t.Fatalf("retry on the reopened log = %+v, %v; want a new entry at seq 2", r, err)
	}
	if got := s.entries(t); len(got) != 2 || got[1] != "e1" {
		t.Fatalf("stored %v, want [held e1]: exactly one e1", got)
	}
}
