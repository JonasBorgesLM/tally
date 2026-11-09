package tally

import (
	"context"
	"errors"
	"iter"
	"time"
)

// ErrClosed is returned by a Log or a Store used after Close.
var ErrClosed = errors.New("tally: closed")

// Record is one leaf as a Store holds it: its index and its stored bytes
// (SPEC §2). The bytes are hashed as they are (RS-03), so a Store returns
// exactly what it was given, never a re-encoding.
type Record struct {
	Seq  uint64
	Body []byte
}

// SignedCheckpoint is a checkpoint as it is stored and anchored: the bytes of
// a signed note (SPEC §5). A checkpoint is not a leaf (R-26): it is persisted
// beside the records, never among them, so it does not shift their indices.
type SignedCheckpoint []byte

// Source is the read half of a Store, which Verify reads (#27).
type Source interface {
	// Records yields the records from fromSeq on, in order, ending at the
	// last durable one. An error ends the sequence; a reader must treat it as
	// "could not read", never as the end of the log. A cancelled ctx yields
	// ctx.Err().
	Records(ctx context.Context, fromSeq uint64) iter.Seq2[Record, error]

	// Checkpoints yields the stored checkpoints, oldest first, with the
	// same error rules as Records.
	Checkpoints(ctx context.Context) iter.Seq2[SignedCheckpoint, error]
}

// Store persists records and checkpoints for a Log. tally calls it from a
// single goroutine, the writer (ADR-0008).
//
// AppendBatch must return only once every record in recs is durable (RF-01):
// a Receipt is built on that return, and a receipt for a lost record falsifies
// the only promise the log makes. recs continue the stored log, so recs[0].Seq
// is one past the last stored record. Any error is final for the Log, which
// poisons itself and never calls the Store's write methods again: after a
// failed fsync, a retry can report success with the data gone (ADR-0009). An
// error may leave part of the batch stored; recovery on the next open deals
// with it.
//
// PutCheckpoint must return only once cp is durable. A checkpoint is stored
// before it is published to any anchor, so that an honest restart never finds
// an anchored checkpoint it does not have, which would look like a rollback.
// An error poisons the Log as AppendBatch's does.
//
// A Store must not retain or modify recs, their bodies, or cp after returning.
type Store interface {
	Source
	AppendBatch(ctx context.Context, recs []Record) error
	PutCheckpoint(ctx context.Context, cp SignedCheckpoint) error
	Close() error
}

// AnchorReader reads checkpoints back from an anchor, off the host (RF-09).
// It is deliberately separate from the writing side (#38): the writer on the
// host only publishes, and the auditor off the host only reads, so neither
// interface suggests that the host reads back from what it must not control.
type AnchorReader interface {
	Checkpoints(ctx context.Context) iter.Seq2[SignedCheckpoint, error]
}

// Clock is the log's source of time: recorded_at (RF-03) and the heartbeat
// timer (RF-06). It is injectable so that tests control time without sleeping
// (RNF-11). The log keeps recorded_at monotonic itself, so a Clock may step
// backwards: the reading is clamped to the previous recorded_at and reported
// through Observer.ClockRegression (ADR-0007).
//
// Monotonic is not proof of real time (T-14). recorded_at is the host's claim:
// a host whose clock is wrong, or whose owner sets it, records wrong times in
// order. Only an outside timestamp, such as an anchored checkpoint's arrival,
// bounds it.
type Clock interface {
	Now() time.Time
	// After returns a channel that receives once d has passed on this
	// clock, as time.After does on the host's.
	After(d time.Duration) <-chan time.Time
}
