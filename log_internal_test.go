package tally

import (
	"context"
	"errors"
	"iter"
	"runtime"
	"slices"
	"strconv"
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

func (s *batchStore) Records(context.Context, uint64) iter.Seq2[Record, error] {
	return func(func(Record, error) bool) {} // always empty: Open writes a genesis
}

func (s *batchStore) Close() error { return nil }

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
	close(s.release)
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
	close(s.release) // batch 2 completes; batch 3 holds both retries, and fails

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
