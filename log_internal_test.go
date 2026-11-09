package tally

import (
	"context"
	"errors"
	"iter"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// This file is an internal test because it reads the writer's queue, which an
// external test cannot see. It cannot import tallytest (an import cycle), so
// it carries its own small store.

type testSigner string

func (s testSigner) Name() string              { return string(s) }
func (testSigner) KeyHash() uint32             { return 0 }
func (testSigner) Sign([]byte) ([]byte, error) { return nil, errors.New("not a real signer") }

// batchStore records every batch's size, and blocks the call-th AppendBatch
// until release is closed, after sending on entered.
type batchStore struct {
	block            int
	fail             int // the call that fails, writing nothing
	releaseOnce      sync.Once
	entered, release chan struct{}

	mu    sync.Mutex
	calls int
	sizes []int
	recs  []Record
}

func (s *batchStore) AppendBatch(_ context.Context, recs []Record) error {
	s.mu.Lock()
	s.calls++
	n := s.calls
	s.mu.Unlock()
	if n == s.block {
		s.entered <- struct{}{}
		<-s.release
	}
	if n == s.fail {
		return errors.New("disk on fire")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sizes = append(s.sizes, len(recs))
	for _, r := range recs {
		s.recs = append(s.recs, Record{Seq: r.Seq, Body: slices.Clone(r.Body)})
	}
	return nil
}

func (s *batchStore) Records(_ context.Context, from uint64) iter.Seq2[Record, error] {
	return func(yield func(Record, error) bool) {
		s.mu.Lock()
		recs := slices.Clone(s.recs)
		s.mu.Unlock()
		for _, r := range recs {
			if r.Seq >= from && !yield(r, nil) {
				return
			}
		}
	}
}

func (s *batchStore) Close() error { return nil }

// unblock releases the held AppendBatch. It is safe to call more than once,
// so a test registers it as a cleanup and also calls it where it means to.
func (s *batchStore) unblock() {
	if s.release != nil {
		s.releaseOnce.Do(func() { close(s.release) })
	}
}

// Group commit: appends that queue while a batch is being made durable share
// the next one, and no batch exceeds MaxBatch (ADR-0008).
//
// Negative control: making the writer send one request per batch made this
// fail (the largest batch was 1).
func TestGroupCommitCoalescesUpToMaxBatch(t *testing.T) {
	const maxBatch = 4
	s := &batchStore{block: 2, entered: make(chan struct{}), release: make(chan struct{})}
	l, err := Open(context.Background(), s, testSigner("example.com/log"), WithMaxBatch(maxBatch))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	t.Cleanup(s.unblock) // runs first: a test failing while the store is held must not hang Close

	ev := func(id string) Event {
		return Event{ID: EventID(id), OccurredAt: time.Unix(1, 0), Actor: System(),
			Action: "user.login", Outcome: OutcomeSuccess}
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := l.Append(context.Background(), ev("first")); err != nil {
			t.Errorf("Append: %v", err)
		}
	}()
	<-s.entered // the writer is inside the store with a batch of one

	const queued = 10
	for i := range queued {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := l.Append(context.Background(), ev("e"+strconv.Itoa(i))); err != nil {
				t.Errorf("Append: %v", err)
			}
		}()
	}
	// Wait, without sleeping, until the queue is full: then the next batch is
	// certain to find maxBatch requests waiting.
	for len(l.reqs) < maxBatch {
		runtime.Gosched()
	}
	s.unblock()
	wg.Wait()

	s.mu.Lock()
	defer s.mu.Unlock()
	total, largest := 0, 0
	for _, n := range s.sizes[1:] { // [0] is the genesis
		total += n
		largest = max(largest, n)
		if n > maxBatch {
			t.Fatalf("a batch of %d exceeds MaxBatch %d: %v", n, maxBatch, s.sizes)
		}
	}
	if total != queued+1 || largest != maxBatch {
		t.Fatalf("batches %v: want %d entries in total and a full batch of %d", s.sizes[1:], queued+1, maxBatch)
	}
}

// RF-01 for retries inside one batch: a second Append of an EventID already in
// the batch is answered with the first one's receipt only once the batch is
// durable. If the batch then fails, neither may hold a Receipt. Both requests
// are certainly in one batch: they wait in the queue while the writer is held
// in the store, and the batch they form is the one that fails.
//
// Negative control: answering the in-batch retry when it is found, before
// AppendBatch, made this fail.
func TestAnInBatchRetryIsAnsweredOnlyOnceDurable(t *testing.T) {
	s := &batchStore{block: 2, fail: 3, entered: make(chan struct{}), release: make(chan struct{})}
	l, err := Open(context.Background(), s, testSigner("example.com/log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	t.Cleanup(s.unblock) // runs first: a test failing while the store is held must not hang Close
	ev := func(id string) Event {
		return Event{ID: EventID(id), OccurredAt: time.Unix(1, 0), Actor: System(),
			Action: "user.login", Outcome: OutcomeSuccess}
	}

	held := make(chan error, 1)
	go func() { _, err := l.Append(context.Background(), ev("held")); held <- err }()
	<-s.entered // batch 2 is in the store

	type result struct {
		r   Receipt
		err error
	}
	results := make(chan result, 2)
	for range 2 {
		go func() {
			r, err := l.Append(context.Background(), ev("same"))
			results <- result{r, err}
		}()
	}
	for len(l.reqs) < 2 {
		runtime.Gosched()
	}
	s.unblock() // batch 2 completes; batch 3 holds both retries, and fails

	if err := <-held; err != nil {
		t.Fatalf("the held Append: %v", err)
	}
	for range 2 {
		res := <-results
		if res.err == nil || res.r != (Receipt{}) {
			t.Fatalf("an Append of a failed batch returned %+v, %v; want an error and no Receipt", res.r, res.err)
		}
	}
}

// poisonWatch is an Observer that keeps Poisoned events.
type poisonWatch struct {
	mu   sync.Mutex
	errs []error
}

func (*poisonWatch) Batch(int, time.Duration)      {}
func (*poisonWatch) AnchorPublish(error, uint64)   {}
func (*poisonWatch) DiskSpace(uint64)              {}
func (*poisonWatch) ClockRegression(time.Duration) {}
func (*poisonWatch) Recovered(int64)               {}
func (p *poisonWatch) Poisoned(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.errs = append(p.errs, err)
}

// ADR-0009, R-04: a failing AppendBatch fails every waiter in its batch with
// ErrPoisoned wrapping the store's error, every later Append returns
// ErrPoisoned without reaching the store, and the Observer is told once.
// Several distinct entries are certainly in the failing batch: they wait in
// the queue while the writer is held in the store.
//
// Negative controls: replying success to the batch's waiters on a store error
// made the waiter check fail; letting the writer call AppendBatch while
// poisoned made the call count fail; removing the Poisoned event made the
// Observer check fail.
func TestAStoreErrorPoisonsEveryWaiterAndEverythingAfter(t *testing.T) {
	const waiters = 5
	s := &batchStore{block: 2, fail: 3, entered: make(chan struct{}), release: make(chan struct{})}
	watch := &poisonWatch{}
	l, err := Open(context.Background(), s, testSigner("example.com/log"), WithObserver(watch))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	t.Cleanup(s.unblock) // runs first: a test failing while the store is held must not hang Close
	ev := func(id string) Event {
		return Event{ID: EventID(id), OccurredAt: time.Unix(1, 0), Actor: System(),
			Action: "user.login", Outcome: OutcomeSuccess}
	}

	held := make(chan error, 1)
	go func() { _, err := l.Append(context.Background(), ev("held")); held <- err }()
	<-s.entered

	errs := make(chan error, waiters)
	for i := range waiters {
		go func() {
			r, err := l.Append(context.Background(), ev("w"+strconv.Itoa(i)))
			if r != (Receipt{}) {
				err = errors.New("a Receipt came with the failure")
			}
			errs <- err
		}()
	}
	for len(l.reqs) < waiters {
		runtime.Gosched()
	}
	s.unblock() // batch 2 succeeds; batch 3 holds every waiter, and fails

	if err := <-held; err != nil {
		t.Fatalf("the held Append: %v", err)
	}
	for range waiters {
		if err := <-errs; !errors.Is(err, ErrPoisoned) || !strings.Contains(err.Error(), "disk on fire") {
			t.Fatalf("a waiter of the failing batch got %v, want ErrPoisoned wrapping the store error", err)
		}
	}

	for i := range 3 {
		if _, err := l.Append(context.Background(), ev("later"+strconv.Itoa(i))); !errors.Is(err, ErrPoisoned) {
			t.Fatalf("Append after poisoning = %v, want ErrPoisoned", err)
		}
	}
	s.mu.Lock()
	calls := s.calls
	s.mu.Unlock()
	if calls != 3 { // the genesis, the held batch, the failing batch
		t.Fatalf("the store was called %d times, want 3: never again after poisoning", calls)
	}

	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	watch.mu.Lock()
	defer watch.mu.Unlock()
	if len(watch.errs) != 1 || !strings.Contains(watch.errs[0].Error(), "disk on fire") {
		t.Fatalf("Poisoned events %v, want exactly one with the store error", watch.errs)
	}
}
