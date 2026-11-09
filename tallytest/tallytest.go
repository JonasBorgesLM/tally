// Package tallytest provides test doubles for code that uses tally, in the
// style of net/http/httptest: an in-memory Store, a Store that fails on a
// chosen call, and a clock the test controls.
//
// Production code must not import it, which check-boundaries.sh enforces.
// Nothing here is durable, so none of it may stand in for a real Store.
//
// Test signing keys are not here yet: they need the signed-note key encoding,
// which arrives with #25.
package tallytest

import (
	"context"
	"fmt"
	"iter"
	"slices"
	"sync"
	"time"

	"github.com/JonasBorgesLM/tally"
)

// MemStore is a tally.Store held in memory. It is safe for concurrent use.
//
// It is stricter than a Store has to be: a batch that does not continue the
// stored log (recs[0].Seq one past the last record, then contiguous) is
// refused, so a writer that assigns seq wrongly fails in tests rather than
// writing a log that verifies as broken later.
type MemStore struct {
	mu      sync.Mutex
	records []tally.Record
	closed  bool
}

// NewMemStore returns an empty MemStore.
func NewMemStore() *MemStore {
	return &MemStore{}
}

// AppendBatch stores copies of recs. It is "durable" as soon as it returns.
func (s *MemStore) AppendBatch(ctx context.Context, recs []tally.Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return tally.ErrClosed
	}
	next := uint64(len(s.records))
	for i, r := range recs {
		if want := next + uint64(i); r.Seq != want {
			return fmt.Errorf("tallytest: record %d of the batch has seq %d, want %d", i, r.Seq, want)
		}
	}
	for _, r := range recs {
		s.records = append(s.records, tally.Record{Seq: r.Seq, Body: slices.Clone(r.Body)})
	}
	return nil
}

// Records yields copies of the stored records from fromSeq on. The sequence
// is a snapshot: records appended while it is being read are not included.
func (s *MemStore) Records(ctx context.Context, fromSeq uint64) iter.Seq2[tally.Record, error] {
	return func(yield func(tally.Record, error) bool) {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			yield(tally.Record{}, tally.ErrClosed)
			return
		}
		var snapshot []tally.Record
		if fromSeq < uint64(len(s.records)) {
			snapshot = s.records[fromSeq:]
		}
		s.mu.Unlock()

		for _, r := range snapshot {
			if err := ctx.Err(); err != nil {
				yield(tally.Record{}, err)
				return
			}
			if !yield(tally.Record{Seq: r.Seq, Body: slices.Clone(r.Body)}, nil) {
				return
			}
		}
	}
}

// Len returns the number of stored records.
func (s *MemStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records)
}

// Close makes every later call return tally.ErrClosed. It is idempotent.
func (s *MemStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

// FixedClock is a tally.Clock that moves only when the test moves it, in
// either direction. It is safe for concurrent use.
type FixedClock struct {
	mu  sync.Mutex
	now time.Time
}

// NewFixedClock returns a clock reading t.
func NewFixedClock(t time.Time) *FixedClock {
	return &FixedClock{now: t}
}

// Now returns the clock's current reading.
func (c *FixedClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Set moves the clock to t, which may be earlier than its current reading.
func (c *FixedClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

// Advance moves the clock by d. A negative d steps it backwards, as a host
// clock does after an NTP correction.
func (c *FixedClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}
