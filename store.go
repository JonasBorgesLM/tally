package tally

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"time"

	"github.com/JonasBorgesLM/tally/internal/note"
)

// ErrClosed is returned by a Log or a Store used after Close.
var ErrClosed = errors.New("tally: closed")

// ErrLocked is returned when opening a log that another writer holds open, in
// this process or another (RS-09). filestore returns it; it is declared here
// so that a caller can test for it without importing filestore.
var ErrLocked = errors.New("tally: log locked by another writer")

// ErrShredded is returned by seal when a subject's key has been destroyed:
// what was sealed under it no longer opens, and nothing new is sealed under
// it (RF-12). The entries still verify; only their payloads are gone. It is
// declared here so that a caller can test for it without importing seal.
var ErrShredded = errors.New("tally: the subject's key was shredded")

// Size ceilings of SPEC §6, which a Store reading untrusted bytes checks a
// length prefix against before it allocates (RS-05).
const (
	// MaxRecordLen is the frame ceiling: no valid record body is longer.
	MaxRecordLen = 16<<20 + 2<<10
	// MaxCheckpointLen is the ceiling of a signed checkpoint note.
	MaxCheckpointLen = note.MaxSize
)

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

// MalformedError is how a Source reports stored bytes that break the format
// (SPEC §3): a segment header, name, frame length or CRC that is wrong, as
// opposed to an IO failure. Verify reports it as a MalformedRecord violation
// and keeps the prefix it verified; any other error from a Source means
// "could not verify" (RS-04, #93).
//
// From Records, Seq is the first leaf the Source could not yield: the next
// leaf after the last one it yielded, or, before yielding any, the first leaf
// it was asked for or the first_seq of the first segment it read. From
// Checkpoints, Seq is not used.
type MalformedError struct {
	Seq uint64
	Err error
}

func (e *MalformedError) Error() string {
	return fmt.Sprintf("tally: malformed stored bytes at leaf %d: %v", e.Seq, e.Err)
}

func (e *MalformedError) Unwrap() error { return e.Err }

// Source is the read half of a Store, which Verify reads (#27).
type Source interface {
	// Records yields the records from fromSeq on, in order, ending at the
	// last durable one. An error ends the sequence; a reader must treat it as
	// "could not read", never as the end of the log. A *MalformedError says
	// the stored bytes break the format, which is a violation, not an IO
	// failure. A cancelled ctx yields ctx.Err().
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
// PutCheckpoint must return only once cp is durable. cp covers every record
// stored: its size is one past the last record AppendBatch stored, so a Store
// may treat the call as a safe point to start a new file (ADR-0019). A
// checkpoint is stored
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

// RecoveryReporter is implemented by a Store that recovers a damaged tail
// when it is opened, as filestore does (RF-20). Open checks for it, once, and
// reports a non-zero count through Observer.Recovered, so a caller who passes
// an Observer to the Log hears about a recovery without wiring the Store.
type RecoveryReporter interface {
	// Recovered returns how many bytes the Store moved to quarantine when
	// it was opened.
	Recovered() int64
}

// SpaceReporter is implemented by a Store that watches the free space under
// it, as filestore does with WithFreeSpaceThreshold (RNF-10). After every
// batch and every checkpoint it stores, the Log asks, and reports low space
// through Observer.DiskSpace, each time it is low: a full disk is a denial of
// service against every action that fails closed (T-16), and the warning is
// worth something only before writes start failing.
type SpaceReporter interface {
	// LowSpace returns the free bytes and whether they are below the Store's
	// threshold. It is called on the writer goroutine and must not block.
	LowSpace() (free uint64, low bool)
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
