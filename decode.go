package tally

import (
	"bytes"
	"fmt"
	"time"
)

// String names the outcome as SPEC §2.2 does: success, failure, denied or
// error. Any other value is shown as a number.
func (o Outcome) String() string {
	switch o {
	case OutcomeSuccess:
		return "success"
	case OutcomeFailure:
		return "failure"
	case OutcomeDenied:
		return "denied"
	case OutcomeError:
		return "error"
	default:
		return fmt.Sprintf("Outcome(%d)", uint8(o))
	}
}

// RecordView is one stored record's fields (SPEC §2), for reading a log
// outside tally, such as an export. It holds copies of the bytes, not
// references into the record. It is what was stored, not what is attested:
// Verify says whether the record belongs to an intact chain.
//
// Text fields hold what the writer validated, but a record read from a
// hostile store is decoded by the same rules and nothing more: a caller
// printing them to a terminal escapes them first (RS-13).
type RecordView struct {
	Seq     uint64
	Genesis bool // a genesis (SPEC §2.1); otherwise an entry (SPEC §2.2)
	LogID   LogID

	// Genesis only.
	Origin    string
	CreatedAt time.Time

	// Entry only.
	RecordedAt  time.Time
	OccurredAt  time.Time // caller-supplied and untrusted (RF-03)
	EventID     []byte    // opaque bytes
	ActorKind   string    // "subject", "service" or "system"
	ActorID     []byte    // a SubjectRef, a service name, or empty
	Action      string
	Resource    string
	Outcome     Outcome
	PayloadKind string // "none", "plain" or "sealed"
	SubjectRef  []byte // 16 bytes if sealed
	Payload     []byte // ciphertext if sealed
	PrevHash    [32]byte
}

// DecodeRecord decodes a stored record body strictly (SPEC §1) and applies
// the rules of SPEC §2 that need no other record. An error means the body is
// not a valid record. It does not check the chain: that is Verify's.
func DecodeRecord(body []byte) (RecordView, error) {
	r, err := decodeRecord(body)
	if err != nil {
		return RecordView{}, err
	}
	switch r := r.(type) {
	case *genesis:
		return RecordView{Genesis: true, LogID: r.logID, Origin: r.origin,
			CreatedAt: time.Unix(0, r.createdAt).UTC()}, nil
	case *entry:
		return RecordView{
			Seq:         r.seq,
			LogID:       r.logID,
			RecordedAt:  time.Unix(0, r.recordedAt).UTC(),
			OccurredAt:  time.Unix(0, r.occurredAt).UTC(),
			EventID:     bytes.Clone(r.eventID),
			ActorKind:   actorKindName(r.actorKind),
			ActorID:     bytes.Clone(r.actorID),
			Action:      r.action,
			Resource:    r.resource,
			Outcome:     r.outcome,
			PayloadKind: payloadKindName(r.payloadKind),
			SubjectRef:  bytes.Clone(r.subjectRef),
			Payload:     bytes.Clone(r.payload),
			PrevHash:    r.prevHash,
		}, nil
	default:
		return RecordView{}, fmt.Errorf("%w: unknown record", errMalformed)
	}
}

func actorKindName(k actorKind) string {
	switch k {
	case actorSubject:
		return "subject"
	case actorService:
		return "service"
	case actorSystem:
		return "system"
	default:
		return fmt.Sprintf("actor(%d)", uint8(k))
	}
}

func payloadKindName(k payloadKind) string {
	switch k {
	case payloadNone:
		return "none"
	case payloadPlain:
		return "plain"
	case payloadSealed:
		return "sealed"
	default:
		return fmt.Sprintf("payload(%d)", uint8(k))
	}
}
