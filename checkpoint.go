package tally

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
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
	// Stored first, published after: an anchored checkpoint is always one
	// the host has (architecture.md, "Checkpoint").
	l.enqueue(cp)
	l.checkSpace()
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

// ErrStoredCheckpointMismatch means the stored log contradicts its own last
// stored checkpoint: the leaf at that checkpoint's size differs from its head,
// the log ends below it, or its signature under this log's key is not that
// key's (audit A-01, #126). Open refuses rather than append after it: the
// writer would otherwise sign the next checkpoint over a history its own
// signed checkpoint says is not the log's.
var ErrStoredCheckpointMismatch = errors.New("tally: the stored log contradicts its own last checkpoint")

// readLastStoredCheckpoint returns the last checkpoint the store holds,
// parsed, or nil if it holds none.
//
// A checkpoint that names this log's signer must be that signer's signature
// over its text. The signer holds no public key to check one with, but
// Ed25519 signatures are deterministic (RFC 8032, the only algorithm SPEC §5.3
// allows): signing the same text again reproduces the stored note byte for
// byte. A checkpoint under another key, from before a rotation, is not
// checked here; its head still is, in load.
func (l *Log) readLastStoredCheckpoint(ctx context.Context) (*checkpoint, error) {
	var last SignedCheckpoint
	for cp, err := range l.store.Checkpoints(ctx) {
		if err != nil {
			return nil, fmt.Errorf("tally: reading the stored checkpoints: %w", err)
		}
		last = cp
	}
	if last == nil {
		return nil, nil
	}
	split := bytes.LastIndex(last, []byte("\n\n"))
	if split < 0 {
		return nil, fmt.Errorf("%w: the last one is not a signed note", ErrStoredCheckpointMismatch)
	}
	text := last[:split+1]
	body, f := parseCheckpointBody(text)
	if f != nil {
		return nil, fmt.Errorf("%w: the last one does not parse: %s", ErrStoredCheckpointMismatch, f.Note)
	}
	if signedBy(last[split+2:], l.signer.Name(), l.signer.KeyHash()) {
		again, err := note.Sign(text, l.signer)
		if err != nil {
			return nil, fmt.Errorf("tally: signing the last stored checkpoint's text again: %w", err)
		}
		if !bytes.Equal(again, last) {
			return nil, fmt.Errorf("%w: its signature under this log's key is not this key's", ErrStoredCheckpointMismatch)
		}
	}
	return &body, nil
}

// signedBy reports whether sigs, a note's signature lines (SPEC §5.1),
// include one by the key named name with id keyHash.
func signedBy(sigs []byte, name string, keyHash uint32) bool {
	for _, line := range strings.Split(strings.TrimSuffix(string(sigs), "\n"), "\n") {
		rest, ok := strings.CutPrefix(line, "\u2014 ")
		if !ok {
			continue
		}
		lineName, b64, ok := strings.Cut(rest, " ")
		if !ok || lineName != name {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err == nil && len(raw) >= 4 && binary.BigEndian.Uint32(raw[:4]) == keyHash {
			return true
		}
	}
	return false
}

// CheckpointSize returns the size line of a checkpoint (SPEC §5.2) **without
// verifying its signature**. It is for a Store reading back the checkpoints it
// stored itself, such as recovery refusing to truncate below the last one
// (RF-20); a verifier reads checkpoints with Verify (SPEC §5.4).
func CheckpointSize(cp SignedCheckpoint) (uint64, error) {
	size, _, ok := parseCheckpointHead(cp)
	if !ok {
		return 0, errors.New("tally: a stored checkpoint does not parse")
	}
	return size, nil
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
