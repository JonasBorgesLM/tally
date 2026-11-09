package tally

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/JonasBorgesLM/tally/internal/wire"
)

// This file is the record layer of SPEC §2: the two record types, their strict
// encoding, the validity rules that need no other record, and the leaf hash.
// The rules that relate a record to its neighbours (seq, prev_hash, log_id,
// recorded_at) belong to the verifier, which has the chain.

// Errors from decoding or encoding a record. SPEC §7.2 maps errMalformed to
// MalformedRecord and errNonCanonical to NonCanonicalEncoding.
var (
	errMalformed    = errors.New("tally: malformed record")
	errNonCanonical = errors.New("tally: record does not re-encode to its stored bytes")
)

const (
	recordVersion = 1

	typeGenesis = 0x01
	typeEntry   = 0x02

	// sealFormatV1 is the only known seal format byte (SPEC §4).
	sealFormatV1 = 0x01
	// sealedMin is format byte, nonce and GCM tag: an empty plaintext.
	sealedMin = 1 + 12 + 16

	subjectRefLen = 16
)

// Hard ceilings of SPEC §6. A verifier accepts up to these; a deployment's
// smaller limits apply to its writers, at validation of an Event (#13).
const (
	maxEventID    = 128
	maxActorID    = 256
	maxAction     = 128
	maxResource   = 256
	maxOrigin     = 256
	maxSubjectRef = subjectRefLen
	maxPayload    = 16 << 20
)

type actorKind uint8

const (
	actorSubject actorKind = 0x01
	actorService actorKind = 0x02
	actorSystem  actorKind = 0x03
)

type payloadKind uint8

const (
	payloadNone   payloadKind = 0x00
	payloadPlain  payloadKind = 0x01
	payloadSealed payloadKind = 0x02
)

// record is a decoded GENESIS or ENTRY. Callers switch on the concrete type.
type record interface {
	recordType() uint8
}

// genesis is leaf 0 (SPEC §2.1). Its seq is always 0, so it is not stored here.
type genesis struct {
	logID     [16]byte
	createdAt int64
	origin    string
}

func (*genesis) recordType() uint8 { return typeGenesis }

// entry is SPEC §2.2, field for field.
type entry struct {
	logID       [16]byte
	seq         uint64
	recordedAt  int64
	occurredAt  int64
	eventID     []byte
	actorKind   actorKind
	actorID     []byte
	action      string
	resource    string
	outcome     Outcome
	payloadKind payloadKind
	subjectRef  []byte
	payload     []byte
	prevHash    [32]byte
}

func (*entry) recordType() uint8 { return typeEntry }

// leafHash is the RFC 6962 leaf hash of a stored record body (SPEC §2.3). It
// takes the bytes as stored, never a re-encoding (RS-03): hashing a
// reconstruction would make a non-canonical encoding invisible.
func leafHash(body []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(body)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// encodeRecord validates r and returns its encoding. A writer never produces a
// record that a verifier would reject.
func encodeRecord(r record) ([]byte, error) {
	if err := validate(r); err != nil {
		return nil, err
	}
	return encodeFields(r)
}

// encodeFields encodes r's fields without the validity rules, only the wire
// limits. It exists so that tests can hand the decoder an invalid record.
func encodeFields(r record) ([]byte, error) {
	var e wire.Encoder
	e.Uint8(recordVersion)
	e.Uint8(r.recordType())
	switch r := r.(type) {
	case *genesis:
		e.Fixed(r.logID[:])
		e.Uint64(0)
		e.Int64(r.createdAt)
		e.String(r.origin, maxOrigin)
	case *entry:
		e.Fixed(r.logID[:])
		e.Uint64(r.seq)
		e.Int64(r.recordedAt)
		e.Int64(r.occurredAt)
		e.Bytes(r.eventID, maxEventID)
		e.Uint8(uint8(r.actorKind))
		e.Bytes(r.actorID, maxActorID)
		e.String(r.action, maxAction)
		e.String(r.resource, maxResource)
		e.Uint8(uint8(r.outcome))
		e.Uint8(uint8(r.payloadKind))
		e.Bytes(r.subjectRef, maxSubjectRef)
		e.Bytes(r.payload, maxPayload)
		e.Fixed(r.prevHash[:])
	default:
		return nil, fmt.Errorf("%w: unknown record %T", errMalformed, r)
	}
	b, err := e.Result()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errMalformed, err)
	}
	return b, nil
}

// decodeRecord decodes a stored body strictly (SPEC §1) and applies the
// validity rules of SPEC §2 that need no other record. The result holds no
// reference to body.
func decodeRecord(body []byte) (record, error) {
	r, err := decodeStrict(body)
	if err != nil {
		return nil, err
	}
	if err := validate(r); err != nil {
		return nil, err
	}
	return r, nil
}

// decodeStrict applies SPEC §1 rules 1 to 4 and nothing of §2, so that a
// verifier can run §2's rules in the order the spec lists them, chain rules
// first (§7 step 4). The record it returns may still break a §2 rule.
func decodeStrict(body []byte) (record, error) {
	return decodeStrictWith(body, encodeFields)
}

// decodeStrictWith is decodeStrict with the re-encoder injected, so that the
// check of SPEC §1 rule 4 can be seen to work: a correct encoder never trips it.
func decodeStrictWith(body []byte, reencode func(record) ([]byte, error)) (record, error) {
	r, err := decodeFields(body)
	if err != nil {
		return nil, err
	}
	again, err := reencode(r)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(again, body) {
		return nil, errNonCanonical
	}
	return r, nil
}

func decodeFields(body []byte) (record, error) {
	if len(body) < 2 {
		return nil, fmt.Errorf("%w: %w", errMalformed, wire.ErrTruncated)
	}
	if body[0] != recordVersion {
		return nil, fmt.Errorf("%w: unknown version %d", errMalformed, body[0])
	}

	d := wire.NewDecoder(body[2:])
	var r record
	switch typ := body[1]; typ {
	case typeGenesis:
		g := &genesis{}
		d.Fixed(g.logID[:])
		seq := d.Uint64()
		g.createdAt = d.Int64()
		g.origin = d.String(maxOrigin)
		if d.Finish() == nil && seq != 0 {
			return nil, fmt.Errorf("%w: genesis seq %d, want 0", errMalformed, seq)
		}
		r = g
	case typeEntry:
		e := &entry{}
		d.Fixed(e.logID[:])
		e.seq = d.Uint64()
		e.recordedAt = d.Int64()
		e.occurredAt = d.Int64()
		e.eventID = d.Bytes(maxEventID)
		e.actorKind = actorKind(d.Uint8())
		e.actorID = d.Bytes(maxActorID)
		e.action = d.String(maxAction)
		e.resource = d.String(maxResource)
		e.outcome = Outcome(d.Uint8())
		e.payloadKind = payloadKind(d.Uint8())
		e.subjectRef = d.Bytes(maxSubjectRef)
		e.payload = d.Bytes(maxPayload)
		d.Fixed(e.prevHash[:])
		r = e
	default:
		return nil, fmt.Errorf("%w: unknown type %#x", errMalformed, typ)
	}
	if err := d.Finish(); err != nil {
		return nil, fmt.Errorf("%w: %w", errMalformed, err)
	}
	return r, nil
}

// validate applies the record-local rules of SPEC §2. A failure is the
// *ValidationError the rule produced, wrapped in errMalformed, so the verifier
// classifies it (§7.2) and errors.As still reaches the field.
func validate(r record) error {
	var err error
	switch r := r.(type) {
	case *genesis:
		err = validateGenesis(r)
	case *entry:
		err = validateEntry(r)
	default:
		return fmt.Errorf("%w: unknown record %T", errMalformed, r)
	}
	if err != nil {
		return fmt.Errorf("%w: %w", errMalformed, err)
	}
	return nil
}

// validateGenesis applies SPEC §2.1. origin becomes a signed-note key name, so
// it must be one: non-empty, no '+', no forbidden code point.
func validateGenesis(g *genesis) error {
	switch {
	case g.origin == "":
		return invalid("origin", "is empty")
	case len(g.origin) > maxOrigin:
		return invalid("origin", fmt.Sprintf("is over %d bytes", maxOrigin))
	case strings.Contains(g.origin, "+"):
		return invalid("origin", "contains '+'")
	case !cleanText(g.origin):
		return invalid("origin", "is not valid UTF-8 or holds a forbidden code point")
	}
	return nil
}

// validateEntry applies the rules of SPEC §2.2 that need no other record, in
// the order the spec lists them, so the first failure is the one every
// verifier reports. Validate of an Event runs the same function (RF-02), so the
// writer and the verifier cannot disagree on a rule.
func validateEntry(e *entry) error {
	if len(e.eventID) == 0 {
		return invalid("event_id", "is empty")
	}
	if len(e.eventID) > maxEventID {
		return invalid("event_id", fmt.Sprintf("is over %d bytes", maxEventID))
	}
	if err := validateActor(e.actorKind, e.actorID); err != nil {
		return err
	}
	if !validAction(e.action) {
		return invalid("action", fmt.Sprintf("does not match %s or is over %d bytes", actionPattern, maxAction))
	}
	if len(e.resource) > maxResource || strings.Contains(e.resource, "@") || !cleanText(e.resource) {
		return invalid("resource", fmt.Sprintf("is over %d bytes, or holds '@' or a forbidden code point", maxResource))
	}
	switch e.outcome {
	case OutcomeSuccess, OutcomeFailure, OutcomeDenied, OutcomeError:
	default:
		return invalid("outcome", fmt.Sprintf("has the unknown value %#x", uint8(e.outcome)))
	}
	return validatePayload(e.payloadKind, e.subjectRef, e.payload)
}

func validateActor(kind actorKind, id []byte) error {
	switch kind {
	case actorSubject:
		if len(id) != subjectRefLen {
			return invalid("actor_id", fmt.Sprintf("of a subject is %d bytes, want %d", len(id), subjectRefLen))
		}
	case actorService:
		if len(id) == 0 || len(id) > maxActorID || bytes.IndexByte(id, '@') >= 0 || !cleanText(string(id)) {
			return invalid("actor_id", fmt.Sprintf(
				"of a service is empty, over %d bytes, not valid UTF-8, or holds '@' or a forbidden code point", maxActorID))
		}
	case actorSystem:
		if len(id) != 0 {
			return invalid("actor_id", "of the system is not empty")
		}
	default:
		return invalid("actor_kind", fmt.Sprintf("has the unknown value %#x", uint8(kind)))
	}
	return nil
}

func validatePayload(kind payloadKind, ref, payload []byte) error {
	switch kind {
	case payloadNone:
		if len(ref) != 0 || len(payload) != 0 {
			return invalid("payload", "is present with payload_kind none")
		}
	case payloadPlain:
		// An empty plain payload would be a second encoding of "no payload".
		if len(ref) != 0 {
			return invalid("subject_ref", "is present on a plain payload")
		}
		if len(payload) == 0 {
			return invalid("payload", "is empty with payload_kind plain")
		}
	case payloadSealed:
		if len(ref) != subjectRefLen {
			return invalid("subject_ref", fmt.Sprintf("of a sealed payload is %d bytes, want %d", len(ref), subjectRefLen))
		}
		if len(payload) < sealedMin || payload[0] != sealFormatV1 {
			return invalid("payload", fmt.Sprintf("is sealed but under %d bytes or with an unknown seal format", sealedMin))
		}
	default:
		return invalid("payload_kind", fmt.Sprintf("has the unknown value %#x", uint8(kind)))
	}
	if len(payload) > maxPayload {
		return invalid("payload", fmt.Sprintf("is over %d bytes", maxPayload))
	}
	return nil
}

// actionPattern is the rule validAction implements, stated for error messages.
const actionPattern = `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`

// validAction reports whether s matches actionPattern
// and fits SPEC §6. It is written out rather than compiled with regexp so that
// the package holds no global state.
func validAction(s string) bool {
	if len(s) > maxAction {
		return false
	}
	segments := strings.Split(s, ".")
	if len(segments) < 2 {
		return false
	}
	for _, seg := range segments {
		if seg == "" || seg[0] < 'a' || seg[0] > 'z' {
			return false
		}
		for i := 1; i < len(seg); i++ {
			c := seg[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
				return false
			}
		}
	}
	return true
}

// cleanText reports whether s is valid UTF-8 with no forbidden code point.
func cleanText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if forbidden(r) {
			return false
		}
	}
	return true
}

// forbidden reports whether r is in SPEC §1.1's list: controls, spaces, and
// invisible or bidirectional formatting. The list is explicit rather than a
// Unicode category, so the answer does not change with Go's Unicode version.
func forbidden(r rune) bool {
	switch {
	case r <= 0x20: // C0 controls and space
		return true
	case r >= 0x7F && r <= 0xA0: // DEL, C1 controls (NEL among them) and NBSP
		return true
	case r == 0x1680, r == 0x180E:
		return true
	case r >= 0x2000 && r <= 0x200F: // spaces, then ZWSP, ZWNJ, ZWJ, LRM, RLM
		return true
	case r >= 0x2028 && r <= 0x202F: // line and paragraph separators, bidi embeddings, NNBSP
		return true
	case r == 0x205F, r >= 0x2060 && r <= 0x2064, r >= 0x2066 && r <= 0x206F:
		return true
	case r == 0x3000, r == 0xFEFF:
		return true
	}
	return false
}
