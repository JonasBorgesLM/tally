package tally

import (
	"crypto/sha256"
	"errors"

	"github.com/JonasBorgesLM/tally/internal/wire"
)

// ErrEventConflict means an Append reused an EventID still in the
// idempotency window with different metadata (RF-17). Nothing was recorded.
// Returning the original receipt instead would report success for an event
// that was never stored (R-29).
var ErrEventConflict = errors.New("tally: EventID reused with different metadata")

// defaultIdempotencyWindow is RF-04's default.
const defaultIdempotencyWindow = 10_000

// WithIdempotencyWindow sets how many of the most recent entries a retried
// EventID is checked against (RF-04). The default is 10,000. Zero turns
// idempotency off: every Append is a new entry.
//
// What it does not catch (T-11, ADR-0010): a retry of an EventID older than
// the window is recorded again as a new entry; the log then holds two entries
// for one event, which a verifier accepts. Sealed bytes are not compared, since
// a random nonce makes each retry differ, so a retry that changes only the
// sealed plaintext is taken as a duplicate.
func WithIdempotencyWindow(n int) Option {
	return func(c *config) { c.idempotencyWindow = max(n, 0) }
}

// fingerprint identifies an entry's metadata for RF-17: actor, action,
// resource, outcome, payload kind, the subject a sealed payload is for, and
// the payload bytes only when plain. A hash keeps the window's memory bounded
// whatever the payload size. occurred_at is excluded, as RF-17 lists it not;
// the subject_ref is included although RF-17 does not list it, because unlike
// the sealed bytes it is not random, and a retry for another person is
// another event.
func fingerprint(e *entry) ([32]byte, error) {
	var enc wire.Encoder
	enc.Uint8(uint8(e.actorKind))
	enc.Bytes(e.actorID, maxActorID)
	enc.String(e.action, maxAction)
	enc.String(e.resource, maxResource)
	enc.Uint8(uint8(e.outcome))
	enc.Uint8(uint8(e.payloadKind))
	enc.Bytes(e.subjectRef, maxSubjectRef)
	if e.payloadKind == payloadPlain {
		enc.Bytes(e.payload, maxPayload)
	}
	// A validated entry always encodes. The error is still returned rather
	// than hashed away: a fixed hash on failure would make two failures look
	// alike, which is a false duplicate.
	b, err := enc.Result()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// seen is what the window keeps of one entry.
type seen struct {
	seq         uint64
	leaf        [32]byte
	fingerprint [32]byte
}

// idWindow maps the EventIDs of the most recent entries to what was recorded
// for them. Only the writer goroutine touches it.
type idWindow struct {
	size  int
	byID  map[string]seen
	order []string // the window's ids, oldest at next once full
	next  int
}

func newIDWindow(size int) *idWindow {
	return &idWindow{size: size, byID: make(map[string]seen, size), order: make([]string, 0, size)}
}

func (w *idWindow) get(id string) (seen, bool) {
	s, ok := w.byID[id]
	return s, ok
}

// add records id as the newest entry, evicting the oldest when full. The
// caller adds only an id the window does not hold (one it holds is a
// duplicate or a conflict, never a new entry), so the evicted slot is the only
// one for its id.
func (w *idWindow) add(id string, s seen) {
	if w.size == 0 {
		return
	}
	if len(w.order) < w.size {
		w.order = append(w.order, id)
	} else {
		delete(w.byID, w.order[w.next])
		w.order[w.next] = id
		w.next = (w.next + 1) % w.size
	}
	w.byID[id] = s
}
