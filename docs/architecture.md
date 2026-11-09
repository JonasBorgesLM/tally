# tally — Architecture

Packages, real signatures with no bodies, and the flows that matter. **Nothing below exists
yet.** Writing the signatures is what found R-26: v0.2's `Store` had nowhere to keep checkpoints,
and `Anchor` could only write, though `Verify` has to read it.

## Packages and dependency direction

```
cmd/tally ──▶ tally, filestore, anchor
filestore, anchor, seal, tallytest ──▶ tally ──▶ internal/wire, internal/note
filestore ──▶ internal/fsx
```

`tally` (the root) imports no subpackage. `internal/wire`, `internal/note` and `internal/fsx`
import no tally package. Nothing outside `*_test.go` imports `tallytest`. The whole module is
stdlib only; `interop/` has its own `go.mod` and only tests. `check-boundaries.sh` asserts all of
this against the resolver, once each package exists.

```
tally/                  module github.com/JonasBorgesLM/tally (stdlib only, RNF-01)
├── *.go                Log, Event, Principal, checkpoints, Verify, Store, Anchor, Observer, errors
├── filestore/          segments, flock, recovery, Prune
├── seal/               Vault, FileVault, AES-256-GCM
├── anchor/             anchor.Dir, a create-only spool (RS-17)
├── tallytest/          MemStore, FaultyStore, FixedClock, test keys
├── internal/wire/      strict encoding
├── internal/note/      minimal signed-note (Ed25519)
├── internal/fsx/       fsync of file and directory, flock, atomic write, injectable filesystem
├── cmd/tally/          CLI (flag, no cobra)
├── docs/, testdata/vectors/
└── interop/            own go.mod: differential tests against golang.org/x/mod/sumdb/note
```

Everything an ordinary user needs is in `tally`. A subpackage exists only for an optional
implementation (R-16).

## The root package

### Writing

```go
// Open reads or creates the log. On a store with no genesis it writes one, with
// origin = signer.Name(): a signed note's key name is the log's origin (SPEC §5),
// so a separate WithOrigin could only ever disagree.
func Open(ctx context.Context, s Store, signer Signer, opts ...Option) (*Log, error)

func (l *Log) Append(ctx context.Context, ev Event) (Receipt, error)
func (l *Log) Checkpoint(ctx context.Context) (SignedCheckpoint, error)
func (l *Log) ID() LogID
func (l *Log) ObserverPanics() uint64 // ADR-0017: a panicking Observer is recovered and counted
func (l *Log) Close() error

type Receipt struct {
    Seq       uint64
    LeafHash  [32]byte
    Duplicate bool
}

type Event struct {
    ID         EventID
    OccurredAt time.Time
    Actor      Principal
    Action     string
    Resource   string
    Outcome    Outcome
    Payload    Payload
}

type (
    LogID      [16]byte
    EventID    string
    SubjectRef [16]byte
    Outcome    uint8 // OutcomeSuccess, OutcomeFailure, OutcomeDenied, OutcomeError
)

// Principal has no exported fields and no constructor accepting a human
// identifier (RS-14).
type Principal struct{ /* unexported */ }

func Subject(ref SubjectRef) Principal
func Service(name string) (Principal, error) // RS-18
func System() Principal

// Payload is built by Plain, or by seal.Payload.
type Payload struct{ /* unexported */ }

func Plain(b []byte) Payload
func Sealed(ref SubjectRef, ciphertext []byte) Payload

func WithCheckpointEvery(n uint64, d time.Duration) Option
func WithMaxBatch(n int) Option
func WithMaxDelay(d time.Duration) Option
func WithAnchors(a ...Anchor) Option
func WithClock(c Clock) Option
func WithObserver(o Observer) Option
func WithIdempotencyWindow(n int) Option
func WithLimits(l Limits) Option
func WithRand(r io.Reader) Option // RNF-11
```

### Ports

The decision R-26 forced: **a checkpoint is not a leaf.** Making it one would shift every
later index and put signatures inside the tree the signatures attest. So checkpoints get their
own persistence, and `Source` is the read half both the store and `Verify` share.

```go
type Record struct {
    Seq  uint64
    Body []byte // bytes as stored: SPEC §2. Hashed as is (RS-03).
}

// Source is what Verify reads. A Store is one.
type Source interface {
    Records(ctx context.Context, fromSeq uint64) iter.Seq2[Record, error]
    Checkpoints(ctx context.Context) iter.Seq2[SignedCheckpoint, error]
}

type Store interface {
    Source
    // AppendBatch returns only once the records are durable (R-17).
    AppendBatch(ctx context.Context, recs []Record) error
    // PutCheckpoint returns only once the checkpoint is durable.
    PutCheckpoint(ctx context.Context, cp SignedCheckpoint) error
    Close() error
}

type Anchor interface {
    Publish(ctx context.Context, cp SignedCheckpoint) error
}

// AnchorReader is deliberately separate from Anchor. The writer on the host
// needs only Publish, and the auditor off the host needs only this; a single
// interface would suggest the host reads back from what it must not control.
type AnchorReader interface {
    Checkpoints(ctx context.Context) iter.Seq2[SignedCheckpoint, error]
}

// Signer matches the shape of golang.org/x/mod/sumdb/note.Signer without
// importing it. It may be a separate process or a KMS (RS-06, ADR-0015).
type Signer interface {
    Name() string
    KeyHash() uint32
    Sign(msg []byte) ([]byte, error)
}

type Clock interface {
    Now() time.Time
    After(d time.Duration) <-chan time.Time // the heartbeat timer; FixedClock fires it on Advance
}

// Observer methods are called from the writer goroutine and must not block.
// None receives a payload (RF-16).
type Observer interface {
    Batch(n int, syncLatency time.Duration)
    AnchorPublish(err error, dropped uint64)
    DiskSpace(free uint64)
    ClockRegression(by time.Duration)
    Poisoned(err error)
    Recovered(quarantinedBytes int64)
}
```

### Verifying

```go
// Verify's error means verification was not possible; a violation is in Report.
func Verify(ctx context.Context, src Source, keys Verifiers, opts ...VerifyOption) (*Report, error)

func NewVerifiers(keys ...string) (Verifiers, error) // signed-note verifier keys

func FromCheckpoint(cp SignedCheckpoint) VerifyOption
func WithAnchor(a AnchorReader) VerifyOption
func WithHeartbeat(interval, tolerance time.Duration, now time.Time) VerifyOption
func WithRequireFullyAttested() VerifyOption // RF-18

type Report struct {
    Size              uint64
    AttestedSize      uint64
    UnattestedEntries uint64
    Failures          []Failure
}

func (r *Report) OK() bool

type Failure struct {
    Kind FailureKind // REQUIREMENTS §5.1
    Seq  uint64
    Note string
}
```

`now` is supplied by the caller: the log's own clock is what is in question.

### Errors

`ErrClosed`, `ErrPoisoned`, `ErrLocked`, `ErrOutcomeUnknown`, `ErrEventConflict`, `ErrShredded`, all
compatible with `errors.Is`. Validation is `*ValidationError`, through `errors.As`. `ErrLocked` is
returned by `filestore` and `ErrShredded` by `seal`; they are declared here so a caller needs no import
to test for them.

## Subpackages

```go
package filestore

func Open(ctx context.Context, dir string, opts ...Option) (*Store, error) // lock, recovery
func (s *Store) Prune(ctx context.Context, cp tally.SignedCheckpoint, keys tally.Verifiers) (removed int, err error)

package anchor

func NewDir(dir string) (*Dir, error)
func (d *Dir) Publish(ctx context.Context, cp tally.SignedCheckpoint) error                // O_EXCL, atomic
func (d *Dir) Checkpoints(ctx context.Context) iter.Seq2[tally.SignedCheckpoint, error]

package seal

type Vault interface {
    Resolve(ctx context.Context, identifier []byte) (tally.SubjectRef, error)
    Seal(ctx context.Context, ref tally.SubjectRef, plaintext, aad []byte) ([]byte, error)
    Open(ctx context.Context, ref tally.SubjectRef, sealed, aad []byte) ([]byte, error) // ErrShredded
    Shred(ctx context.Context, ref tally.SubjectRef) error                               // idempotent
}

func OpenFileVault(dir string, kek KEK, opts ...Option) (*FileVault, error)
func Payload(ctx context.Context, v Vault, log tally.LogID, ev tally.EventID, ref tally.SubjectRef, plaintext []byte) (tally.Payload, error) // RS-19

package tallytest

func NewMemStore() *MemStore
func NewFaultyStore(inner tally.Store, faults ...Fault) *FaultyStore
func NewFixedClock(t time.Time) *FixedClock
func NewTestSigner(tb testing.TB, name string) tally.Signer
```

## Flows

### Append

Steps run in this order, and **the order is the requirement** where marked.

1. On the caller's goroutine: validate the event (RF-02), and seal it if sealed (RS-12).
2. Enqueue. A context cancelled before this returns `ctx.Err()`; after it, `ErrOutcomeUnknown` (ADR-0010).
3. On the writer: if the log is poisoned, fail with `ErrPoisoned`.
4. Look up `EventID`: same metadata returns the original receipt (RF-04); different metadata returns
   `ErrEventConflict` (RF-17).
5. Assign `seq`, clamp `recorded_at` (RF-03), set `prev_hash`, encode.
6. `AppendBatch`. **Any error poisons the log, and every waiter in the batch fails** (ADR-0009).
7. **Only now** return the `Receipt` (RF-01). Replying before step 6 returned is the defect this library
   exists to rule out.

### Checkpoint

1. Triggered by N entries, the timer, rotation, demand or `Close` (RF-06), and only over records that step 6
   above made durable.
2. Sign. 3. `PutCheckpoint`, durable. 4. Enqueue for the anchors (RF-07), and **only then** can a queue drop
   or a hung anchor happen, neither of which touches `Append`.

Local durability comes before publication: a published checkpoint the host then cannot find would make an
honest restart look like a rollback.

### Recovery (filestore.Open, then tally.Open)

1. Take the `flock` (RS-09). Check permissions (RS-15).
2. Validate every segment's header, and every frame of the last segment.
3. Classify the tail per SPEC §3.3. **Write quarantine durably before truncating** (RF-20). Refuse if it would cut
   below the last local checkpoint, or on a bad middle.
4. Check the tail's chain against the last local checkpoint.
5. Rebuild the idempotency window.

### Verify

SPEC §7. Streaming, O(1) memory (RNF-04); a parse error is a violation (RS-04), and an unreadable file is the
`error` return, never a `Report` that says OK.
