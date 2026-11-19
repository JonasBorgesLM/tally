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
	// tlogSize is the size of the last tlog-checkpoint stored. Heartbeats at
	// one size give the same tlog-checkpoint, byte for byte (Ed25519 is
	// deterministic), so it is stored and published once per size.
	tlogSize uint64
}

// Checkpoint signs and stores a checkpoint over every durable entry, and
// returns it (RF-06). A v0.2 checkpoint is a pair of notes (ADR-0006's
// amendment, SPEC §5.2): a tlog-checkpoint, which a witness cosigns, and a
// tally-heartbeat/v1 note, which carries the head and the time. Both are
// stored and published; Checkpoint returns the heartbeat note, which names a
// head and so serves FromCheckpoint and Prune. A log pruned before ranges
// existed has no tree, and gets a v0.1 tally-chain/v1 checkpoint instead. It runs on the writer, after any batch in progress, so
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

	// The notes to store, in order: the tlog-checkpoint before the heartbeat
	// note, so that the last one stored carries the time Open reads back.
	var texts []string
	tlogSize := l.lastCP.tlogSize
	if root, ok := l.treeRoot(); ok {
		if l.head.size != l.lastCP.tlogSize {
			texts = append(texts, tlogText(l.head.origin, l.head.size, root))
			tlogSize = l.head.size
		}
		texts = append(texts, heartbeatText(l.head.origin, l.head.size, l.head.prevLeaf, root, at, state))
	} else {
		texts = append(texts, checkpointText(l.head.origin, l.head.size, l.head.prevLeaf, at, state))
	}
	// Every note is signed before any is stored: a signing error then loses
	// this checkpoint whole, never half of a pair.
	cps := make([]SignedCheckpoint, 0, len(texts))
	for _, text := range texts {
		cp, err := note.Sign([]byte(text), l.signer)
		if err != nil {
			return nil, fmt.Errorf("tally: signing a checkpoint: %w", err)
		}
		cps = append(cps, cp)
	}
	for _, cp := range cps {
		if err := l.store.PutCheckpoint(context.Background(), cp); err != nil {
			l.poison(err)
			return nil, l.err
		}
	}
	l.lastCP = lastCheckpoint{size: l.head.size, at: at, tlogSize: tlogSize}
	// Stored first, published after: an anchored checkpoint is always one
	// the host has (architecture.md, "Checkpoint").
	for _, cp := range cps {
		l.enqueue(cp)
	}
	l.checkSpace()
	return cps[len(cps)-1], nil
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

// heartbeatText is SPEC §5.2's tally-heartbeat/v1 body: the chain body's
// fields, with the Merkle root after the head (ADR-0006's amendment).
func heartbeatText(origin string, size uint64, head, root [32]byte, at int64, state string) string {
	var b strings.Builder
	b.WriteString(origin)
	b.WriteString("\n" + bodyHeartbeatV1 + "\n")
	b.WriteString(strconv.FormatUint(size, 10))
	b.WriteByte('\n')
	b.WriteString(base64.StdEncoding.EncodeToString(head[:]))
	b.WriteByte('\n')
	b.WriteString(base64.StdEncoding.EncodeToString(root[:]))
	b.WriteByte('\n')
	b.WriteString(time.Unix(0, at).UTC().Format(checkpointTimeLayout))
	b.WriteByte('\n')
	b.WriteString(state)
	b.WriteByte('\n')
	return b.String()
}

// tlogText is SPEC §5.2's tlog-checkpoint body: origin, size and root, with
// no extension lines.
func tlogText(origin string, size uint64, root [32]byte) string {
	return origin + "\n" + strconv.FormatUint(size, 10) + "\n" + base64.StdEncoding.EncodeToString(root[:]) + "\n"
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

// CheckpointSize returns the size line of a checkpoint (SPEC §5.2), any of its
// three bodies, **without verifying its signature**. It is for a Store reading
// back the checkpoints it stored itself, such as recovery refusing to truncate
// below the last one (RF-20); a verifier reads checkpoints with Verify (SPEC
// §5.4).
func CheckpointSize(cp SignedCheckpoint) (uint64, error) {
	split := bytes.LastIndex(cp, []byte("\n\n"))
	if split < 0 {
		return 0, errors.New("tally: a stored checkpoint is not a signed note")
	}
	c, f := parseCheckpointBody(cp[:split+1])
	if f != nil {
		return 0, errors.New("tally: a stored checkpoint does not parse")
	}
	return c.size, nil
}

// dueByEntries reports whether enough entries have been made durable since
// the last checkpoint for the entry trigger.
func (l *Log) dueByEntries() bool {
	n := l.cfg.checkpointEntries
	return n > 0 && l.head.size-l.lastCP.size >= n
}

// treeRoot is the Merkle root of every durable leaf, if the tree is known.
func (l *Log) treeRoot() ([32]byte, bool) {
	if l.head.tree == nil {
		return [32]byte{}, false
	}
	root, err := l.head.tree.Root()
	return root, err == nil
}
