package tally

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/JonasBorgesLM/tally/internal/note"
)

// Checkpoints (RF-06, SPEC §5). The writer signs one every N entries, every T
// of time even with no entries (a heartbeat), on demand and on Close, and
// always over durable state only. A checkpoint on segment rotation needs a
// store that rotates, and comes with filestore (#33).

// Defaults of RF-06. They set the exposure window of T-07: entries past the
// last anchored checkpoint are not covered.
const (
	defaultCheckpointEntries = 1000
	defaultCheckpointPeriod  = 60 * time.Second
)

// checkpointTimeLayout is SPEC §5.2's only recorded_at layout: nine fractional
// digits always, and Z. time.RFC3339Nano is not it: it drops trailing zeros.
const checkpointTimeLayout = "2006-01-02T15:04:05.000000000Z"

const (
	stateOpen   = "open"
	stateClosed = "closed"
)

// WithCheckpointEvery sets when the writer signs a checkpoint on its own:
// after n entries since the last one, and every d of time even with no entries,
// which is the heartbeat (RF-06). Zero turns that trigger off. The defaults
// are 1,000 entries and 60 seconds.
//
// A heartbeat proves that the signer was running, and nothing about whether
// the log is complete (T-15): a host that drops entries can keep signing
// heartbeats over what it kept.
func WithCheckpointEvery(n uint64, d time.Duration) Option {
	return func(c *config) {
		c.checkpointEntries = n
		c.checkpointPeriod = max(d, 0)
	}
}

// checkpointRequest is one Checkpoint call on its way to the writer.
type checkpointRequest struct {
	reply chan checkpointReply // buffered
}

type checkpointReply struct {
	cp  SignedCheckpoint
	err error
}

// lastCheckpoint is what the writer remembers of the last checkpoint it
// stored: its size, for the entry trigger, and its time, so that a later one
// never claims an earlier time (SPEC §7 step 6).
type lastCheckpoint struct {
	size uint64
	at   int64
}

// Checkpoint signs and stores a checkpoint over every durable entry, and
// returns it (RF-06). It runs on the writer, after any batch in progress, so
// it covers nothing that is not durable. It fails with ErrPoisoned on a
// poisoned log, and with the Signer's error if signing fails; a failure to
// store it poisons the log, as any store error does (ADR-0009).
func (l *Log) Checkpoint(ctx context.Context) (SignedCheckpoint, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	req := checkpointRequest{reply: make(chan checkpointReply, 1)}

	l.mu.RLock()
	if l.closed {
		l.mu.RUnlock()
		return nil, ErrClosed
	}
	l.senders.Add(1)
	l.mu.RUnlock()

	select {
	case l.cpReqs <- req:
		l.senders.Done()
	case <-ctx.Done():
		l.senders.Done()
		return nil, ctx.Err()
	}
	select {
	case rep := <-req.reply:
		return rep.cp, rep.err
	case <-ctx.Done():
		select {
		case rep := <-req.reply:
			return rep.cp, rep.err
		default:
			return nil, ctx.Err()
		}
	}
}

// checkpoint signs and stores a checkpoint over l.head. Only the writer calls
// it, so l.head is durable state: commit advances it only after AppendBatch
// returned.
func (l *Log) checkpoint(state string) (SignedCheckpoint, error) {
	if l.err != nil {
		return nil, l.err
	}
	// recorded_at is the head's or a later clock reading (SPEC §5.2), and
	// never earlier than the last checkpoint's.
	at := l.recordedAt(max(l.head.prevTime, l.lastCP.at))
	text := checkpointText(l.head.origin, l.head.size, l.head.prevLeaf, at, state)

	cp, err := note.Sign([]byte(text), l.signer)
	if err != nil {
		return nil, fmt.Errorf("tally: signing a checkpoint: %w", err)
	}
	if err := l.store.PutCheckpoint(context.Background(), cp); err != nil {
		l.poison(err)
		return nil, l.err
	}
	l.lastCP = lastCheckpoint{size: l.head.size, at: at}
	return cp, nil
}

// autoCheckpoint signs a checkpoint on the entry trigger or the heartbeat,
// where no caller waits for the result. A store error has already poisoned
// the log inside checkpoint, and is reported there: through ErrPoisoned on
// every later call and Observer.Poisoned. A signing error loses only this
// checkpoint, and the next trigger tries again; a signer that keeps failing
// is seen at the next Checkpoint or Close, which sign for a caller and return
// the error. Nothing else reports it: the Observer has no signing event.
func (l *Log) autoCheckpoint() {
	if _, err := l.checkpoint(stateOpen); err != nil {
		return // see above: already reported, or retried at the next trigger
	}
}

// checkpointText is SPEC §5.2's body.
func checkpointText(origin string, size uint64, head [32]byte, at int64, state string) string {
	var b strings.Builder
	b.WriteString(origin)
	b.WriteString("\ntally-chain/v1\n")
	b.WriteString(strconv.FormatUint(size, 10))
	b.WriteByte('\n')
	b.WriteString(base64.StdEncoding.EncodeToString(head[:]))
	b.WriteByte('\n')
	b.WriteString(time.Unix(0, at).UTC().Format(checkpointTimeLayout))
	b.WriteByte('\n')
	b.WriteString(state)
	b.WriteByte('\n')
	return b.String()
}

// loadLastCheckpoint recovers, on reopen, the size and time of the last stored
// checkpoint, so that the entry trigger counts from it and a new checkpoint
// never claims an earlier time than one already stored (SPEC §7 step 6).
//
// It reads only what it needs, and caps a stored size above the head: the
// subtraction in dueByEntries must not wrap. Refusing to open a store cut
// below its last checkpoint is recovery's job (RF-20, #34), not this one's.
func (l *Log) loadLastCheckpoint(ctx context.Context) error {
	var last SignedCheckpoint
	for cp, err := range l.store.Checkpoints(ctx) {
		if err != nil {
			return fmt.Errorf("tally: reading the stored checkpoints: %w", err)
		}
		last = cp
	}
	if last == nil {
		l.lastCP = lastCheckpoint{size: 1} // the entry trigger counts entries, not genesis
		return nil
	}
	size, at, ok := parseCheckpointHead(last)
	if !ok {
		return fmt.Errorf("tally: the last stored checkpoint does not parse")
	}
	l.lastCP = lastCheckpoint{size: min(size, l.head.size), at: at}
	return nil
}

// parseCheckpointHead reads the size and recorded_at lines of a checkpoint the
// log itself stored. It is not a verifier's parser: Verify reads checkpoints
// by SPEC §5.4 (#27).
func parseCheckpointHead(cp SignedCheckpoint) (size uint64, at int64, ok bool) {
	split := strings.LastIndex(string(cp), "\n\n")
	if split < 0 {
		return 0, 0, false
	}
	lines := strings.Split(string(cp[:split]), "\n")
	if len(lines) != 6 {
		return 0, 0, false
	}
	size, err := strconv.ParseUint(lines[2], 10, 64)
	if err != nil {
		return 0, 0, false
	}
	t, err := time.Parse(checkpointTimeLayout, lines[4])
	if err != nil {
		return 0, 0, false
	}
	return size, t.UnixNano(), true
}

// dueByEntries reports whether enough entries have been made durable since
// the last checkpoint for the entry trigger.
func (l *Log) dueByEntries() bool {
	n := l.cfg.checkpointEntries
	return n > 0 && l.head.size-l.lastCP.size >= n
}
