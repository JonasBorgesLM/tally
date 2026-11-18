package tally

import (
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

func validEvent() Event {
	return Event{
		ID:         "01J9Z3K8V7",
		OccurredAt: time.Unix(1_700_000_000, 0),
		Actor:      System(),
		Action:     "user.login",
		Resource:   "session/42",
		Outcome:    OutcomeSuccess,
	}
}

// validationField returns the Field of the *ValidationError in err, failing the
// test if err is not one.
func validationField(t *testing.T, err error) string {
	t.Helper()
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("error = %v (%T), want *ValidationError", err, err)
	}
	return ve.Field
}

func TestValidEventPasses(t *testing.T) {
	ref := SubjectRef{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	svc, err := Service("billing-api")
	if err != nil {
		t.Fatalf("Service: %v", err)
	}
	sealed := Sealed(ref, append([]byte{sealFormatV1}, make([]byte, 28)...))
	for name, mutate := range map[string]func(ev *Event){
		"system, no payload":  func(*Event) {},
		"subject actor":       func(ev *Event) { ev.Actor = Subject(ref) },
		"service actor":       func(ev *Event) { ev.Actor = svc },
		"plain payload":       func(ev *Event) { ev.Payload = Plain([]byte(`{"ip":"10.0.0.1"}`)) },
		"sealed payload":      func(ev *Event) { ev.Payload = sealed },
		"empty resource":      func(ev *Event) { ev.Resource = "" },
		"payload at default":  func(ev *Event) { ev.Payload = Plain(make([]byte, defaultMaxPayload)) },
		"each outcome denied": func(ev *Event) { ev.Outcome = OutcomeDenied },
	} {
		t.Run(name, func(t *testing.T) {
			ev := validEvent()
			mutate(&ev)
			if err := validateEvent(ev, defaultMaxPayload); err != nil {
				t.Fatalf("validateEvent: %v", err)
			}
		})
	}
}

// RF-02: each limit and rule is enforced and named in a *ValidationError.
//
// Negative controls: removing the zero-Principal check, the OccurredAt range
// check and the deployment payload limit in validateEvent each made its case
// fail; the record rules underneath were controlled in record_test.go.
func TestEventValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(ev *Event)
		field  string
	}{
		{"empty ID", func(ev *Event) { ev.ID = "" }, "event_id"},
		{"ID over 128 bytes", func(ev *Event) { ev.ID = EventID(strings.Repeat("a", 129)) }, "event_id"},
		{"zero Principal", func(ev *Event) { ev.Actor = Principal{} }, "actor_id"},
		{"action without a dot", func(ev *Event) { ev.Action = "login" }, "action"},
		{"action over 128 bytes", func(ev *Event) { ev.Action = "a." + strings.Repeat("b", 127) }, "action"},
		{"resource with @", func(ev *Event) { ev.Resource = "user/joao@example.com" }, "resource"},
		{"resource with space", func(ev *Event) { ev.Resource = "user/joao silva" }, "resource"},
		{"resource over 256 bytes", func(ev *Event) { ev.Resource = strings.Repeat("r", 257) }, "resource"},
		{"zero Outcome", func(ev *Event) { ev.Outcome = 0 }, "outcome"},
		{"unknown Outcome", func(ev *Event) { ev.Outcome = 5 }, "outcome"},
		{"payload over the deployment limit", func(ev *Event) { ev.Payload = Plain(make([]byte, defaultMaxPayload+1)) }, "payload"},
		{"sealed with a bad format byte", func(ev *Event) { ev.Payload = Sealed(SubjectRef{}, make([]byte, 29)) }, "payload"},
		{"OccurredAt before 1678", func(ev *Event) { ev.OccurredAt = time.Date(1600, 1, 1, 0, 0, 0, 0, time.UTC) }, "occurred_at"},
		{"OccurredAt after 2262", func(ev *Event) { ev.OccurredAt = time.Date(2300, 1, 1, 0, 0, 0, 0, time.UTC) }, "occurred_at"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev := validEvent()
			tc.mutate(&ev)
			if got := validationField(t, validateEvent(ev, defaultMaxPayload)); got != tc.field {
				t.Fatalf("Field = %q, want %q", got, tc.field)
			}
		})
	}
}

// The deployment limit only lowers the ceiling: a configured limit above SPEC
// §6's hard ceiling must not let a writer produce what a verifier rejects.
// validatePayload in the record layer is what enforces it, which is why
// validateEvent needs no min() of its own.
//
// Negative control: removing the maxPayload check in validatePayload made this
// fail.
func TestPayloadLimitCannotExceedCeiling(t *testing.T) {
	ev := validEvent()
	ev.Payload = Plain(make([]byte, maxPayload+1))
	if got := validationField(t, validateEvent(ev, math.MaxInt)); got != "payload" {
		t.Fatalf("Field = %q, want payload", got)
	}
}

// RS-18, R-34: tally.Service("joao@example.com") type-checks, so the guard is
// the constructor. It is partial by design (see Service's godoc): digits pass.
//
// Negative control: removing the validateActor call in Service made the "@" and
// whitespace cases fail.
func TestServiceRejectsIdentifierShapes(t *testing.T) {
	for name, s := range map[string]string{
		"email":       "joao@example.com",
		"space":       "joao silva",
		"NBSP":        "joao\u00a0silva",
		"empty":       "",
		"bidi":        "svc\u202e",
		"not UTF-8":   "\xff",
		"over 256":    strings.Repeat("s", 257),
		"line break":  "svc\nname",
		"zero width":  "svc\u200bname",
		"tab":         "svc\tname",
		"ideographic": "svc\u3000name",
	} {
		t.Run(name, func(t *testing.T) {
			p, err := Service(s)
			if got := validationField(t, err); got != "actor_id" {
				t.Fatalf("Field = %q, want actor_id", got)
			}
			if p != (Principal{}) {
				t.Fatalf("Service returned a usable Principal with its error: %#v", p)
			}
		})
	}
	// The stated limit of the guard, asserted so the docs cannot drift from it:
	// a CPF is digits, and it passes.
	if _, err := Service("12345678909"); err != nil {
		t.Fatalf("Service(digits) = %v; the godoc says digits are not caught", err)
	}
}

// A ValidationError names the field and the rule, never the value: the value
// may be the personal data the rule exists to keep out (RS-07).
//
// Negative control: adding the rejected value to ValidationError.Error made
// this fail.
func TestValidationErrorDoesNotEchoTheValue(t *testing.T) {
	const secret = "joao@example.com"
	_, err := Service(secret)
	if err == nil {
		t.Fatal("Service accepted an email")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "joao") {
		t.Fatalf("error message echoes the rejected value: %q", err.Error())
	}
	ev := validEvent()
	ev.Resource = "user/" + secret
	if err := validateEvent(ev, defaultMaxPayload); err == nil || strings.Contains(err.Error(), "joao") {
		t.Fatalf("validateEvent error echoes the value or is nil: %v", err)
	}
}

// An Event is handed to another goroutine by Append, so Plain and Sealed copy
// their input: a caller reusing its buffer must not change a queued payload.
func TestPayloadCopiesInput(t *testing.T) {
	b := []byte("abc")
	p := Plain(b)
	s := Sealed(SubjectRef{}, b)
	b[0] = 'X'
	if p.data != "abc" || s.data != "abc" {
		t.Fatalf("payload aliases its input: %q %q", p.data, s.data)
	}
}

// An empty plain payload is invalid in the format (one encoding for "no
// payload"), so Plain of nothing is no payload rather than an error.
func TestPlainEmptyIsNoPayload(t *testing.T) {
	for _, b := range [][]byte{nil, {}} {
		if p := Plain(b); p != (Payload{}) {
			t.Fatalf("Plain(%#v) = %#v, want the zero Payload", b, p)
		}
	}
}

// The public Event maps onto the record layer's entry field for field, so a
// valid Event always encodes.
func TestEventEncodesAsEntry(t *testing.T) {
	ev := validEvent()
	ev.Actor = Subject(SubjectRef{9})
	ev.Payload = Plain([]byte("x"))
	e := eventEntry(ev)
	e.logID, e.seq, e.recordedAt = [16]byte{1}, 1, 1
	if _, err := encodeRecord(e); err != nil {
		t.Fatalf("a valid Event did not encode: %v", err)
	}
	if string(e.eventID) != string(ev.ID) || e.action != ev.Action || e.outcome != ev.Outcome ||
		e.occurredAt != ev.OccurredAt.UnixNano() || e.actorKind != actorSubject {
		t.Fatalf("entry does not mirror the Event: %#v", e)
	}
}
