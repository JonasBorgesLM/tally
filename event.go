package tally

import (
	"fmt"
	"math"
	"time"
)

type (
	// LogID identifies one log. It is random, chosen at genesis, and carried in
	// every entry so that one log's entries cannot pass as another's (T-10).
	LogID [16]byte

	// EventID is the caller's identifier for an event, used for idempotency
	// (RF-04). It is stored in clear, so it must be random or opaque and never
	// derived from personal data. It is required, and at most 128 bytes.
	EventID string

	// SubjectRef is a random reference that stands for a person (RS-14). Only
	// the vault in package seal maps it back to an identifier, and Shred breaks
	// that mapping. It is the only way a human appears in the log.
	SubjectRef [16]byte

	// Outcome is the result of the audited action.
	Outcome uint8
)

// The outcomes. The zero Outcome is not one of them, so an Event whose Outcome
// was never set is rejected rather than recorded as a success.
const (
	OutcomeSuccess Outcome = 0x01
	OutcomeFailure Outcome = 0x02
	OutcomeDenied  Outcome = 0x03
	OutcomeError   Outcome = 0x04
)

// defaultMaxPayload is SPEC §6's default payload limit for writers. The hard
// ceiling, maxPayload, is what verifiers accept.
const defaultMaxPayload = 64 << 10

// Event is one auditable action, as the caller describes it.
type Event struct {
	// ID is required; see EventID.
	ID EventID
	// OccurredAt is when the caller says the action happened. It is untrusted
	// and never checked against the log's clock: a caller can backdate it
	// (T-14). The log records its own recorded_at beside it, and that one is
	// monotonic (RF-03). It must be representable as nanoseconds since the Unix
	// epoch in an int64, between the years 1678 and 2262.
	OccurredAt time.Time
	// Actor is who performed the action. The zero Principal is rejected.
	Actor Principal
	// Action names what happened, as lowercase dotted segments, for example
	// "user.login": at least two segments, each [a-z][a-z0-9_]*, at most 128
	// bytes.
	Action string
	// Resource names what the action was performed on. It may be empty, is at
	// most 256 bytes, and rejects '@' and invisible or space characters
	// (SPEC §1.1). That rejection is a partial guard (RS-18): it catches an
	// email address or a full name pasted in, and nothing else. A CPF, a phone
	// number, or a login without '@' passes. Resource is stored in clear
	// forever, so the caller must keep personal data out of it.
	Resource string
	// Outcome is required.
	Outcome Outcome
	// Payload holds the details, plain or sealed. The zero Payload is none.
	Payload Payload
}

// Principal is the actor of an Event. It has no exported fields and no
// constructor that accepts a human identifier (RS-14): a person enters the log
// only as a SubjectRef.
type Principal struct {
	kind actorKind
	id   string
}

// Subject returns the Principal for a person, by the reference the vault
// issued for them.
func Subject(ref SubjectRef) Principal {
	return Principal{kind: actorSubject, id: string(ref[:])}
}

// Service returns the Principal for a non-human caller, such as "billing-api".
// The name is stored in clear in every entry it makes.
//
// The name is rejected if it is empty, over 256 bytes, not valid UTF-8, or
// holds '@', a space, a control character, or an invisible or bidirectional
// formatting character (SPEC §1.1). That is a partial guard (RS-18): it stops
// Service("joao@example.com") and a full name, the common ways a person's
// identifier ends up in clear in an immutable log. It does not stop a CPF, a
// phone number, or a login without '@': those are digits and letters like any
// service name. A name must never identify a person.
func Service(name string) (Principal, error) {
	if err := validateActor(actorService, []byte(name)); err != nil {
		return Principal{}, err
	}
	return Principal{kind: actorService, id: name}, nil
}

// System returns the Principal for the log's own actions, with no identifier.
func System() Principal {
	return Principal{kind: actorSystem}
}

// Payload is the optional detail of an Event. Build it with Plain, or with
// package seal for anything that identifies a person. The zero Payload is none.
type Payload struct {
	kind payloadKind
	ref  SubjectRef
	data string
}

// Plain returns a payload stored in clear. It copies b. An empty b is no
// payload, since the format has a single encoding for "no payload".
func Plain(b []byte) Payload {
	if len(b) == 0 {
		return Payload{}
	}
	return Payload{kind: payloadPlain, data: string(b)}
}

// Sealed returns a payload already sealed for ref, as package seal produces
// it: the seal format byte, the nonce and the ciphertext (SPEC §4). It copies
// ciphertext. Most callers want seal.Payload, which seals and builds this in
// one step and binds it to the event.
func Sealed(ref SubjectRef, ciphertext []byte) Payload {
	return Payload{kind: payloadSealed, ref: ref, data: string(ciphertext)}
}

// ValidationError reports an Event, Principal or record that breaks a rule of
// SPEC §2. Field is the format's name for the field, such as "resource" or
// "actor_id". The message names the field and the rule and never includes the
// rejected value, which may be the very personal data the rule exists to keep
// out (RS-07).
type ValidationError struct {
	Field  string
	Reason string
}

func (e *ValidationError) Error() string {
	return "tally: invalid " + e.Field + ": " + e.Reason
}

func invalid(field, reason string) error {
	return &ValidationError{Field: field, Reason: reason}
}

// validateEvent applies RF-02 to ev: the record rules of SPEC §2.2, shared
// with the verifier, and then the deployment's payload limit. A limit above
// SPEC §6's ceiling changes nothing: validateEntry already enforces the ceiling.
func validateEvent(ev Event, payloadLimit int) error {
	if ev.Actor.kind == 0 {
		return invalid("actor_id", "is missing: the zero Principal is not an actor")
	}
	minT, maxT := time.Unix(0, math.MinInt64), time.Unix(0, math.MaxInt64)
	if ev.OccurredAt.Before(minT) || ev.OccurredAt.After(maxT) {
		return invalid("occurred_at", "is outside the range of int64 nanoseconds since the Unix epoch")
	}
	if err := validateEntry(eventEntry(ev)); err != nil {
		return err
	}
	if len(ev.Payload.data) > payloadLimit {
		return invalid("payload", fmt.Sprintf("is over the configured limit of %d bytes", payloadLimit))
	}
	return nil
}

// eventEntry maps ev onto the record fields it determines. The writer fills in
// log_id, seq, recorded_at and prev_hash.
func eventEntry(ev Event) *entry {
	e := &entry{
		occurredAt:  ev.OccurredAt.UnixNano(),
		eventID:     []byte(ev.ID),
		actorKind:   ev.Actor.kind,
		actorID:     []byte(ev.Actor.id),
		action:      ev.Action,
		resource:    ev.Resource,
		outcome:     ev.Outcome,
		payloadKind: ev.Payload.kind,
		subjectRef:  []byte{},
		payload:     []byte(ev.Payload.data),
	}
	if ev.Payload.kind == payloadSealed {
		e.subjectRef = append(e.subjectRef, ev.Payload.ref[:]...)
	}
	return e
}
