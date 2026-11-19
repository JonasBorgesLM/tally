package tally

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Anchor receives checkpoints to keep off the host (RF-07). It must be
// unalterable from the host that publishes to it: the host holds no
// credential that can modify or delete what it already published (RS-17).
// The library cannot check that property of a deployment; anchor.Dir (#39)
// is one way to get it.
//
// Publish is called from the anchor's own goroutine, never from Append's
// path, one call at a time. A failed Publish is retried with the same
// checkpoint, so it must accept a checkpoint it may already hold. It should
// return when ctx is done: Close cancels ctx at its flush deadline.
type Anchor interface {
	Publish(ctx context.Context, cp SignedCheckpoint) error
}

// Errors an anchor queue reports, through Observer.AnchorPublish and Close.
var (
	// ErrAnchorQueueFull means a checkpoint was dropped from a full queue:
	// the oldest one other than the newest (RF-19). A later checkpoint
	// subsumes its integrity claim, but its heartbeat evidence is lost.
	ErrAnchorQueueFull = errors.New("tally: anchor queue full; the oldest checkpoint was dropped")

	// ErrAnchorUnflushed means Close reached its flush deadline with
	// checkpoints not yet published. They are stored locally; they are not
	// anchored.
	ErrAnchorUnflushed = errors.New("tally: checkpoints left unpublished at Close")
)

const (
	defaultAnchorQueue        = 64
	defaultAnchorFlushTimeout = 10 * time.Second

	// A failed publication is retried after anchorRetryMin, doubling up to
	// anchorRetryMax, on the Log's Clock.
	anchorRetryMin = time.Second
	anchorRetryMax = time.Minute
)

// WithAnchors publishes every checkpoint the log stores to each of anchors,
// asynchronously: publication never blocks Append, and a failure reaches the
// Observer, never the caller (RF-07, ADR-0006). Each anchor has its own
// bounded queue and goroutine, so a slow anchor does not hold up another.
// A checkpoint is queued only once it is stored locally, so a restart never
// finds an anchored checkpoint it does not have.
func WithAnchors(anchors ...Anchor) Option {
	return func(c *config) { c.anchors = append(c.anchors, anchors...) }
}

// WithAnchorQueue bounds each anchor's queue at n checkpoints (RF-19). When it
// is full, the oldest checkpoint other than the newest is dropped, counted,
// and reported through Observer.AnchorPublish with ErrAnchorQueueFull. The
// newest is never dropped, so the anchor always ends up with the latest
// claim. n below 1 means 1. The default is 64.
//
// The queue counts notes, and a v0.2 checkpoint is two (#60): the
// tlog-checkpoint, then the heartbeat note. So the default holds 32
// checkpoints, and a queue of 1 keeps only the newest heartbeat note, never
// its tlog-checkpoint, which a witness needs (#61).
func WithAnchorQueue(n int) Option {
	return func(c *config) { c.anchorQueue = max(n, 1) }
}

// WithAnchorFlushTimeout bounds how long Close waits for the anchors to
// publish what is queued, the closing checkpoint included (RF-19). At the
// deadline Close cancels the Publish in progress and returns
// ErrAnchorUnflushed if anything is left. An Anchor that ignores its context
// can outlive Close in its goroutine; Close still returns. The default is
// 10 seconds, on the Log's Clock.
func WithAnchorFlushTimeout(d time.Duration) Option {
	return func(c *config) { c.anchorFlush = max(d, 0) }
}

// anchorQueue is one anchor's bounded queue (RF-19). The writer pushes; the
// anchor's goroutine publishes from the head.
type anchorQueue struct {
	anchor Anchor
	limit  int

	mu      sync.Mutex
	items   []queuedCheckpoint
	nextID  uint64
	dropped uint64

	wake chan struct{} // buffered: one pending wake-up is enough
	done chan struct{} // closed when the goroutine returns
}

type queuedCheckpoint struct {
	id uint64
	cp SignedCheckpoint
}

func newAnchorQueue(a Anchor, limit int) *anchorQueue {
	return &anchorQueue{anchor: a, limit: limit, wake: make(chan struct{}, 1), done: make(chan struct{})}
}

// push queues cp, dropping the oldest checkpoint when the queue is full. It
// never blocks. It returns the running drop count, and whether this push
// dropped one.
func (q *anchorQueue) push(cp SignedCheckpoint) (dropped uint64, did bool) {
	q.mu.Lock()
	if len(q.items) == q.limit {
		// The oldest is never the newest: the newest is cp.
		q.items = q.items[1:]
		q.dropped++
		did = true
	}
	q.items = append(q.items, queuedCheckpoint{id: q.nextID, cp: cp})
	q.nextID++
	dropped = q.dropped
	q.mu.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
	return dropped, did
}

// head returns the oldest queued checkpoint, if any. It stays queued while it
// is published, so an overflow can still drop it.
func (q *anchorQueue) head() (queuedCheckpoint, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) == 0 {
		return queuedCheckpoint{}, false
	}
	return q.items[0], true
}

// published removes the checkpoint id, if an overflow has not already.
func (q *anchorQueue) published(id uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) > 0 && q.items[0].id == id {
		q.items = q.items[1:]
	}
}

func (q *anchorQueue) state() (queued int, dropped uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items), q.dropped
}

// startAnchors starts one publishing goroutine per anchor.
func (l *Log) startAnchors() {
	if len(l.cfg.anchors) == 0 {
		return
	}
	l.anchorCtx, l.anchorCancel = context.WithCancel(context.Background())
	l.anchorFlush = make(chan struct{})
	for _, a := range l.cfg.anchors {
		q := newAnchorQueue(a, l.cfg.anchorQueue)
		l.anchors = append(l.anchors, q)
		go l.publish(q)
	}
}

// enqueue hands a stored checkpoint to every anchor. Only the writer calls
// it, after PutCheckpoint returned.
func (l *Log) enqueue(cp SignedCheckpoint) {
	for _, q := range l.anchors {
		if dropped, did := q.push(cp); did {
			l.observe(func(o Observer) { o.AnchorPublish(ErrAnchorQueueFull, dropped) })
		}
	}
}

// publish is one anchor's goroutine. It publishes the queue's head until the
// queue is empty after Close asked for a flush, or until the flush deadline
// cancels its context. A failure is reported and retried with backoff.
func (l *Log) publish(q *anchorQueue) {
	defer close(q.done)
	ctx := l.anchorCtx
	var backoff time.Duration
	for {
		it, ok := q.head()
		if !ok {
			select {
			case <-q.wake:
				continue
			case <-l.anchorFlush:
				if n, _ := q.state(); n == 0 {
					return
				}
				continue
			case <-ctx.Done():
				return
			}
		}
		err := q.anchor.Publish(ctx, it.cp)
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			q.published(it.id)
			backoff = 0
			continue
		}
		_, dropped := q.state()
		l.observe(func(o Observer) { o.AnchorPublish(err, dropped) })
		backoff = min(max(2*backoff, anchorRetryMin), anchorRetryMax)
		select {
		case <-l.cfg.clock.After(backoff):
		case <-ctx.Done():
			return
		}
	}
}

// flushAnchors waits for every anchor to publish its queue, up to the flush
// deadline, then cancels what is still running. It returns
// ErrAnchorUnflushed, with a count, if checkpoints were left.
func (l *Log) flushAnchors() error {
	if len(l.anchors) == 0 {
		return nil
	}
	close(l.anchorFlush)
	deadline := l.cfg.clock.After(l.cfg.anchorFlush)
	for _, q := range l.anchors {
		select {
		case <-q.done:
		case <-deadline:
			l.anchorCancel()
			left := 0
			for _, q := range l.anchors {
				n, _ := q.state()
				left += n
			}
			if left == 0 {
				return nil
			}
			return fmt.Errorf("%w: %d", ErrAnchorUnflushed, left)
		}
	}
	l.anchorCancel()
	return nil
}
