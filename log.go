package tally

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// Errors returned by a Log.
var (
	// ErrPoisoned means a store error made the log stop accepting entries
	// (ADR-0009). After a failed write or fsync, a retry can report success
	// with the data gone, so there is no retry: close the Log, and reopen it
	// after a restart, verifying the tail. Treat the most recent entries as
	// suspect (R-31).
	ErrPoisoned = errors.New("tally: log poisoned by a store error")

	// ErrOutcomeUnknown means the context ended after the entry was handed to
	// the writer: it may or may not have been stored. Retry with the same
	// EventID (ADR-0010).
	ErrOutcomeUnknown = errors.New("tally: outcome unknown; retry with the same EventID")
)

// Signer signs checkpoints. It matches the shape of
// golang.org/x/mod/sumdb/note.Signer without importing it, and may be a
// separate process or a KMS (RS-06, ADR-0015). Its Name is the log's origin
// (SPEC §5), so a separate origin setting could only ever disagree with it.
type Signer interface {
	Name() string
	KeyHash() uint32
	Sign(msg []byte) ([]byte, error)
}

// Receipt is the proof Append returns once an entry is durable (RF-01).
type Receipt struct {
	Seq       uint64
	LeafHash  [32]byte
	Duplicate bool
}

// Option configures Open.
type Option func(*config)

type config struct {
	maxBatch   int
	maxDelay   time.Duration
	clock      Clock
	rand       io.Reader
	maxPayload int
}

// Defaults. MaxDelay is RNF-03's provisional 2 ms; MaxBatch bounds the work
// one fsync carries.
const (
	defaultMaxBatch = 256
	defaultMaxDelay = 2 * time.Millisecond
)

// WithMaxBatch caps how many entries one AppendBatch carries. Values below 1
// mean 1.
func WithMaxBatch(n int) Option {
	return func(c *config) { c.maxBatch = max(n, 1) }
}

// WithMaxDelay is how long the writer waits for more entries after the first
// one of a batch, trading latency for fewer fsyncs. Zero means it takes only
// what is already queued.
func WithMaxDelay(d time.Duration) Option {
	return func(c *config) { c.maxDelay = max(d, 0) }
}

// WithClock sets the source of recorded_at (RNF-11). The default is the host
// clock.
func WithClock(clk Clock) Option {
	return func(c *config) { c.clock = clk }
}

// WithRand sets the randomness source for the log_id of a new log (RNF-11).
// The default is crypto/rand.
func WithRand(r io.Reader) Option {
	return func(c *config) { c.rand = r }
}

// hostClock is the default Clock, the host's.
type hostClock struct{}

// Now returns the host's time.
func (hostClock) Now() time.Time { return time.Now() }

// Log is a tamper-evident audit log. It is safe for concurrent use. One
// goroutine, the writer, orders and stores entries (ADR-0008).
type Log struct {
	store Store
	id    LogID
	cfg   config

	reqs chan *request
	quit chan struct{}
	done chan struct{}

	// closed and senders make Close and Append agree on who may still
	// enqueue: an Append registers as a sender only while the log is open,
	// and Close waits for registered senders before stopping the writer, so
	// no request can land in the queue after the writer has gone.
	mu      sync.RWMutex
	closed  bool
	senders sync.WaitGroup

	closeOnce sync.Once
	closeErr  error

	// Owned by the writer goroutine once Open returns.
	head chainState
	err  error // the error that poisoned the log, or nil
}

// request is one Append on its way to the writer.
type request struct {
	entry *entry
	reply chan reply // buffered, so the writer never blocks on a caller
}

type reply struct {
	receipt Receipt
	err     error
}

// Open opens the log held by s, writing a genesis if s is empty, and starts
// its writer. The Log owns s from then on and closes it in Close.
//
// The log's origin is signer.Name(). On an existing log, Open reads the stored
// chain back by the verifier's rules and refuses a broken one, or one whose
// origin is not signer.Name(): extending either would write entries no
// verifier accepts. That read is linear in the log's size until local
// checkpoints bound it (#26).
func Open(ctx context.Context, s Store, signer Signer, opts ...Option) (*Log, error) {
	cfg := config{
		maxBatch:   defaultMaxBatch,
		maxDelay:   defaultMaxDelay,
		clock:      hostClock{},
		rand:       rand.Reader,
		maxPayload: defaultMaxPayload,
	}
	for _, o := range opts {
		o(&cfg)
	}
	l := &Log{
		store: s,
		cfg:   cfg,
		reqs:  make(chan *request, cfg.maxBatch),
		quit:  make(chan struct{}),
		done:  make(chan struct{}),
	}
	if err := l.load(ctx, signer.Name()); err != nil {
		return nil, err
	}
	l.id = l.head.logID
	// The writer outlives every caller: Append's context governs only the wait
	// for a reply, and a caller giving up must not interrupt a write in progress.
	go l.writer() //nolint:contextcheck // deliberate, see above.
	return l, nil
}

// load reads the stored chain into l.head, or writes a genesis on an empty
// store.
func (l *Log) load(ctx context.Context, origin string) error {
	for r, err := range l.store.Records(ctx, 0) {
		if err != nil {
			return fmt.Errorf("tally: reading the stored log: %w", err)
		}
		if r.Seq != l.head.size {
			return fmt.Errorf("tally: the store returned seq %d at leaf %d", r.Seq, l.head.size)
		}
		if v := l.head.add(r.Body); v != nil {
			return fmt.Errorf("tally: the stored log does not verify: %w", v)
		}
	}
	if l.head.size > 0 {
		if l.head.origin != origin {
			return fmt.Errorf("tally: the log's origin is %q, the signer's name is %q", l.head.origin, origin)
		}
		return nil
	}

	g := &genesis{createdAt: l.cfg.clock.Now().UnixNano(), origin: origin}
	if _, err := io.ReadFull(l.cfg.rand, g.logID[:]); err != nil {
		return fmt.Errorf("tally: reading a random log_id: %w", err)
	}
	body, err := encodeRecord(g)
	if err != nil {
		var ve *ValidationError
		if errors.As(err, &ve) {
			return ve
		}
		return err
	}
	if err := l.store.AppendBatch(ctx, []Record{{Seq: 0, Body: body}}); err != nil {
		return fmt.Errorf("tally: writing the genesis: %w", err)
	}
	if v := l.head.add(body); v != nil {
		return fmt.Errorf("tally: the genesis written does not verify: %w", v)
	}
	return nil
}

// ID returns the log's random identifier, fixed at genesis.
func (l *Log) ID() LogID { return l.id }

// Append records ev and returns its Receipt once the entry is durable (RF-01).
//
// Validation runs on the caller's goroutine (RF-02). If ctx ends before the
// entry reaches the writer, Append returns ctx.Err() and nothing was recorded.
// If it ends after, Append returns ErrOutcomeUnknown: the entry may or may not
// be stored, and the caller retries with the same EventID.
func (l *Log) Append(ctx context.Context, ev Event) (Receipt, error) {
	if err := validateEvent(ev, l.cfg.maxPayload); err != nil {
		return Receipt{}, err
	}
	req := &request{entry: eventEntry(ev), reply: make(chan reply, 1)}

	l.mu.RLock()
	if l.closed {
		l.mu.RUnlock()
		return Receipt{}, ErrClosed
	}
	l.senders.Add(1)
	l.mu.RUnlock()

	select {
	case l.reqs <- req:
		l.senders.Done()
	case <-ctx.Done():
		l.senders.Done()
		return Receipt{}, ctx.Err()
	}

	select {
	case rep := <-req.reply:
		return rep.receipt, rep.err
	case <-ctx.Done():
		return Receipt{}, ErrOutcomeUnknown
	}
}

// Close refuses new Appends, lets those already enqueueing finish, stops the
// writer after the batch in flight, answers every queued Append with
// ErrClosed, and closes the store. It is idempotent.
func (l *Log) Close() error {
	l.closeOnce.Do(func() {
		l.mu.Lock()
		l.closed = true
		l.mu.Unlock()
		l.senders.Wait()
		close(l.quit)
		<-l.done
		l.closeErr = l.store.Close()
	})
	return l.closeErr
}

// writer is the only goroutine that touches l.head and l.err after Open.
func (l *Log) writer() {
	defer close(l.done)
	batch := make([]*request, 0, l.cfg.maxBatch)
	for {
		// quit first: once Close has asked, no new batch starts.
		select {
		case <-l.quit:
			l.refuseQueued()
			return
		default:
		}
		select {
		case <-l.quit:
			l.refuseQueued()
			return
		case first := <-l.reqs:
			batch = l.collect(append(batch[:0], first))
			l.commit(batch)
		}
	}
}

// collect adds whatever is queued to batch, waiting up to MaxDelay for more,
// until the batch is full. This is the group commit: entries that arrive
// while a batch is being made durable share the next fsync (ADR-0008).
func (l *Log) collect(batch []*request) []*request {
	var deadline <-chan time.Time
	if l.cfg.maxDelay > 0 {
		t := time.NewTimer(l.cfg.maxDelay)
		defer t.Stop()
		deadline = t.C
	}
	for len(batch) < l.cfg.maxBatch {
		select {
		case r := <-l.reqs:
			batch = append(batch, r)
			continue
		default:
		}
		if deadline == nil {
			return batch
		}
		select {
		case r := <-l.reqs:
			batch = append(batch, r)
		case <-deadline:
			return batch
		case <-l.quit:
			return batch
		}
	}
	return batch
}

// commit chains batch onto the head, stores it, and only then replies. A
// store error poisons the log, and every waiter in the batch fails with it
// (ADR-0009).
func (l *Log) commit(batch []*request) {
	if l.err != nil {
		for _, r := range batch {
			r.reply <- reply{err: l.err}
		}
		return
	}

	next := l.head
	recs := make([]Record, 0, len(batch))
	accepted := batch[:0]
	for _, r := range batch {
		e := r.entry
		e.logID, e.seq, e.prevHash = next.logID, next.size, next.prevLeaf
		// recorded_at never goes back (RF-03): a clock that steps backwards is
		// clamped to the previous value. Reporting it is #18.
		e.recordedAt = max(l.cfg.clock.Now().UnixNano(), next.prevTime)
		body, err := encodeRecord(e)
		if err != nil {
			// Validation already ran on the caller's goroutine, so this is a
			// bug; the entry is refused and the chain does not move.
			r.reply <- reply{err: fmt.Errorf("tally: encoding a validated entry: %w", err)}
			continue
		}
		if v := next.add(body); v != nil {
			r.reply <- reply{err: fmt.Errorf("tally: a chained entry does not verify: %w", v)}
			continue
		}
		recs = append(recs, Record{Seq: e.seq, Body: body})
		accepted = append(accepted, r)
	}
	if len(recs) == 0 {
		return
	}

	// No reply before this returns (RF-01). The writer's context is not the
	// caller's: a caller giving up does not interrupt a write in progress.
	if err := l.store.AppendBatch(context.Background(), recs); err != nil {
		l.err = fmt.Errorf("%w: %w", ErrPoisoned, err)
		for _, r := range accepted {
			r.reply <- reply{err: l.err}
		}
		return
	}
	l.head = next
	for i, r := range accepted {
		r.reply <- reply{receipt: Receipt{Seq: recs[i].Seq, LeafHash: leafHash(recs[i].Body)}}
	}
}

// refuseQueued answers every request still queued at Close.
func (l *Log) refuseQueued() {
	for {
		select {
		case r := <-l.reqs:
			r.reply <- reply{err: ErrClosed}
		default:
			return
		}
	}
}
