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
	mu          sync.Mutex
	records     []tally.Record
	checkpoints []tally.SignedCheckpoint
	closed      bool
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

// PutCheckpoint stores a copy of cp. It is "durable" as soon as it returns.
func (s *MemStore) PutCheckpoint(ctx context.Context, cp tally.SignedCheckpoint) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return tally.ErrClosed
	}
	s.checkpoints = append(s.checkpoints, slices.Clone(cp))
	return nil
}

// Checkpoints yields copies of the stored checkpoints, oldest first, as a
// snapshot.
func (s *MemStore) Checkpoints(ctx context.Context) iter.Seq2[tally.SignedCheckpoint, error] {
	return func(yield func(tally.SignedCheckpoint, error) bool) {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			yield(nil, tally.ErrClosed)
			return
		}
		snapshot := slices.Clone(s.checkpoints)
		s.mu.Unlock()
		for _, cp := range snapshot {
			if err := ctx.Err(); err != nil {
				yield(nil, err)
				return
			}
			if !yield(slices.Clone(cp), nil) {
				return
			}
		}
	}
}

// CheckpointCount returns the number of stored checkpoints.
func (s *MemStore) CheckpointCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.checkpoints)
}

// FixedClock is a tally.Clock that moves only when the test moves it, in
// either direction. Its timers fire when a move reaches their deadline, so a
// test drives a heartbeat by advancing the clock, never by sleeping. It is
// safe for concurrent use.
type FixedClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []timer
}

type timer struct {
	at time.Time
	ch chan time.Time
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

// After returns a channel that receives the clock's reading once the clock
// has been moved to d past now or later. A d of zero or less fires at once.
func (c *FixedClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := make(chan time.Time, 1)
	c.timers = append(c.timers, timer{at: c.now.Add(d), ch: ch})
	c.fire()
	return ch
}

// Timers returns how many timers are waiting to fire. A test uses it to know,
// without sleeping, that the code under test has armed its timer.
func (c *FixedClock) Timers() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.timers)
}

// Set moves the clock to t, which may be earlier than its current reading,
// and fires every timer whose deadline it reaches.
func (c *FixedClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
	c.fire()
}

// Advance moves the clock by d and fires every timer whose deadline it
// reaches. A negative d steps it backwards, as a host clock does after an NTP
// correction; no timer fires on a step back.
func (c *FixedClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	c.fire()
}

// fire sends on, and forgets, every timer whose deadline has been reached.
// Each channel has room for its one value, so this never blocks.
func (c *FixedClock) fire() {
	kept := c.timers[:0]
	for _, t := range c.timers {
		if c.now.Before(t.at) {
			kept = append(kept, t)
			continue
		}
		t.ch <- c.now
	}
	c.timers = kept
}
