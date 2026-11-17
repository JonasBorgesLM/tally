package tally_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/tallytest"
)

// Mirror is an observability pipeline as an application sees it: crier's
// emitter, or any other. It lives in the application, which wires it; tally
// imports none of them (RI-01).
type Mirror interface {
	Emit(ctx context.Context, fields map[string]string)
}

// printMirror prints what it is given, standing in for crier.
type printMirror struct{}

func (printMirror) Emit(_ context.Context, fields map[string]string) {
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+fields[k])
	}
	fmt.Println(strings.Join(parts, " "))
}

// Mirroring to crier (RI-03): the audit record is tally's, and crier gets a
// copy of what tally has already confirmed, for dashboards and alerts.
//
//   - Mirror only after Append returns a Receipt. An event mirrored before,
//     or after a failed Append, shows on a dashboard what the audit log does
//     not hold.
//   - Mirror no payload. A sealed payload is what a shred erases (RF-12), and
//     a copy in crier is a copy no shred reaches; a plain one is detail no
//     dashboard needs. Mirror the fields a dashboard needs, and the receipt's
//     seq, which finds the entry in the log.
//   - Ignore the mirror's failures. crier's buffer drops under load
//     (crier/IR3): a lost mirror loses a dashboard point, never an audit
//     record, because the record was durable before the mirror was called.
func Example_mirrorToCrier() {
	ctx := context.Background()
	signer, err := tally.NewSigner(tallytest.TestSignerKey) // the key from tally keygen
	if err != nil {
		panic(err)
	}
	// A MemStore stands in for filestore here.
	log, err := tally.Open(ctx, tallytest.NewMemStore(), signer)
	if err != nil {
		panic(err)
	}
	defer func() { _ = log.Close() }()

	const service = "billing"
	actor, err := tally.Service(service)
	if err != nil {
		panic(err)
	}
	ev := tally.Event{
		ID:         "req-7f3a",
		OccurredAt: time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC),
		Actor:      actor,
		Action:     "invoice.read",
		Resource:   "invoice/8812",
		Outcome:    tally.OutcomeSuccess,
		Payload:    tally.Plain([]byte(`{"reason":"monthly close"}`)), // stays in the log
	}

	receipt, err := log.Append(ctx, ev)
	if err != nil {
		// The application's own policy (ADR-0010): deny, or execute and
		// alarm. Either way, nothing is mirrored.
		return
	}

	var m Mirror = printMirror{}
	m.Emit(ctx, map[string]string{
		"event_id": string(ev.ID),
		"actor":    "service:" + service,
		"action":   ev.Action,
		"resource": ev.Resource,
		"outcome":  ev.Outcome.String(),
		"seq":      fmt.Sprint(receipt.Seq),
	})
	// Output:
	// action=invoice.read actor=service:billing event_id=req-7f3a outcome=success resource=invoice/8812 seq=1
}
