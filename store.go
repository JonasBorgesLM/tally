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

// Source is the read half of a Store, which Verify will read (#27).
// SignedCheckpoint persistence joins it with the checkpoints themselves (#26):
// a checkpoint is not a leaf (R-26), so it has its own methods, not a Record.
type Source interface {
	// Records yields the records from fromSeq on, in order, ending at the
	// last durable one. An error ends the sequence; a reader must treat it as
	// "could not read", never as the end of the log. A cancelled ctx yields
	// ctx.Err().
	Records(ctx context.Context, fromSeq uint64) iter.Seq2[Record, error]
}

// Store persists records for a Log. tally calls it from a single goroutine,
// the writer (ADR-0008).
//
// AppendBatch must return only once every record in recs is durable (RF-01):
// a Receipt is built on that return, and a receipt for a lost record falsifies
// the only promise the log makes. recs continue the stored log, so recs[0].Seq
// is one past the last stored record. Any error is final for the Log, which
// poisons itself and never calls AppendBatch again: after a failed fsync, a
// retry can report success with the data gone (ADR-0009). An error may leave
// part of the batch stored; recovery on the next open deals with it.
//
// A Store must not retain or modify recs or their bodies after returning.
type Store interface {
	Source
	AppendBatch(ctx context.Context, recs []Record) error
	Close() error
}

// Clock is the log's source of recorded_at (RF-03). It is injectable so that
// tests control time (RNF-11). The log keeps recorded_at monotonic itself, so
// a Clock may step backwards; that is reported, not trusted (ADR-0007).
type Clock interface {
	Now() time.Time
}
