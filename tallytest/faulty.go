package tallytest

import (
	"context"
	"iter"
	"sync"

	"github.com/JonasBorgesLM/tally"
)

// Fault is a misbehaviour that a FaultyStore applies to one call. Build one
// with FailAppend, TearAppend, BlockAppend or FailPutCheckpoint.
type Fault struct {
	checkpoint bool // a PutCheckpoint call, not an AppendBatch call
	call       int
	keep       int // records of the batch written before failing, for a tear
	err        error
	entered    chan<- struct{}
	release    <-chan struct{}
}

// FailAppend makes the call-th AppendBatch (counting from 1) write nothing and
// return err, as a write or an fsync that fails outright.
func FailAppend(call int, err error) Fault {
	return Fault{call: call, err: err}
}

// TearAppend makes the call-th AppendBatch write the first keep records of its
// batch and then return err, as a crash or a failed fsync halfway through. The
// Log must treat it as poisoning, whatever part of the batch was stored.
func TearAppend(call, keep int, err error) Fault {
	return Fault{call: call, keep: keep, err: err}
}

// BlockAppend makes the call-th AppendBatch send on entered once it has
// started, then wait until release is closed or its context is done, before
// going on to the inner store. A test learns that the writer is inside the
// store, and decides when the batch becomes durable, without sleeping.
func BlockAppend(call int, entered chan<- struct{}, release <-chan struct{}) Fault {
	return Fault{call: call, entered: entered, release: release}
}

// FailPutCheckpoint makes the call-th PutCheckpoint (counting from 1) store
// nothing and return err. The Log must treat it as poisoning (ADR-0009).
func FailPutCheckpoint(call int, err error) Fault {
	return Fault{checkpoint: true, call: call, err: err}
}

// FaultyStore wraps a tally.Store and applies Faults to chosen AppendBatch
// calls. Every other call goes to the inner store unchanged. It is safe for
// concurrent use.
type FaultyStore struct {
	inner tally.Store

	mu       sync.Mutex
	calls    int
	cpCalls  int
	faults   map[int]Fault
	cpFaults map[int]Fault
}

// NewFaultyStore wraps inner. Each fault applies to the call it names; two
// faults for one call keep the last.
func NewFaultyStore(inner tally.Store, faults ...Fault) *FaultyStore {
	s := &FaultyStore{inner: inner, faults: map[int]Fault{}, cpFaults: map[int]Fault{}}
	for _, f := range faults {
		if f.checkpoint {
			s.cpFaults[f.call] = f
		} else {
			s.faults[f.call] = f
		}
	}
	return s
}

// AppendBatch counts the call, applies its fault if there is one, and
// otherwise appends to the inner store.
func (s *FaultyStore) AppendBatch(ctx context.Context, recs []tally.Record) error {
	s.mu.Lock()
	s.calls++
	f, faulty := s.faults[s.calls]
	s.mu.Unlock()

	if !faulty {
		return s.inner.AppendBatch(ctx, recs)
	}
	if f.release != nil {
		select {
		case f.entered <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
		select {
		case <-f.release:
		case <-ctx.Done():
			return ctx.Err()
		}
		return s.inner.AppendBatch(ctx, recs)
	}
	if keep := min(f.keep, len(recs)); keep > 0 {
		if err := s.inner.AppendBatch(ctx, recs[:keep]); err != nil {
			return err
		}
	}
	return f.err
}

// AppendCalls returns how many times AppendBatch has been called, faults
// included. A poisoned Log must not call it again (ADR-0009), and this is how
// a test proves that.
func (s *FaultyStore) AppendCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// Records reads from the inner store.
func (s *FaultyStore) Records(ctx context.Context, fromSeq uint64) iter.Seq2[tally.Record, error] {
	return s.inner.Records(ctx, fromSeq)
}

// PutCheckpoint counts the call, applies its fault if there is one, and
// otherwise stores in the inner store.
func (s *FaultyStore) PutCheckpoint(ctx context.Context, cp tally.SignedCheckpoint) error {
	s.mu.Lock()
	s.cpCalls++
	f, faulty := s.cpFaults[s.cpCalls]
	s.mu.Unlock()
	if faulty {
		return f.err
	}
	return s.inner.PutCheckpoint(ctx, cp)
}

// PutCheckpointCalls returns how many times PutCheckpoint has been called,
// faults included.
func (s *FaultyStore) PutCheckpointCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cpCalls
}

// Checkpoints reads from the inner store.
func (s *FaultyStore) Checkpoints(ctx context.Context) iter.Seq2[tally.SignedCheckpoint, error] {
	return s.inner.Checkpoints(ctx)
}

// Close closes the inner store.
func (s *FaultyStore) Close() error {
	return s.inner.Close()
}
