package tally_test

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/tallytest"
)

// withPayload returns an event with an n-byte plain payload and an EventID of
// its own, so that a rejection is about the size and never an idempotency
// conflict between two calls of one test.
func withPayload(n int) tally.Event {
	ev := event("p" + strconv.Itoa(n))
	ev.Payload = tally.Plain(make([]byte, n))
	return ev
}

func payloadRejected(t *testing.T, err error) {
	t.Helper()
	var ve *tally.ValidationError
	if !errors.As(err, &ve) || ve.Field != "payload" {
		t.Fatalf("Append = %v, want a ValidationError on payload", err)
	}
}

// RF-02: a deployment can lower the payload limit for its writers.
//
// Negative control: ignoring the configured limit in Open made this fail.
func TestALowerPayloadLimitApplies(t *testing.T) {
	l := open(t, tallytest.NewMemStore(), tally.WithLimits(tally.Limits{MaxPayload: 1024}))
	if _, err := l.Append(context.Background(), withPayload(1024)); err != nil {
		t.Fatalf("a payload at the limit: %v", err)
	}
	_, err := l.Append(context.Background(), withPayload(1025))
	payloadRejected(t, err)
}

// SPEC §6: a limit above the hard ceiling does not let a writer produce what a
// verifier rejects. A larger limit is honoured up to the ceiling, and the
// ceiling still applies.
//
// Negative control: removing the ceiling check in validatePayload made the
// over-ceiling case fail, though no longer with a ValidationError: the wire
// limit in the fingerprint stopped the payload instead. The ceiling is held
// twice, and this test requires the first, named one.
func TestALimitAboveTheCeilingStillStopsAtTheCeiling(t *testing.T) {
	const ceiling = 16 << 20
	l := open(t, tallytest.NewMemStore(), tally.WithLimits(tally.Limits{MaxPayload: 32 << 20}))
	if _, err := l.Append(context.Background(), withPayload(64<<10+1)); err != nil {
		t.Fatalf("a payload over the default, under the configured limit: %v", err)
	}
	_, err := l.Append(context.Background(), withPayload(ceiling+1))
	payloadRejected(t, err)
}

// The zero Limits, and no option at all, mean SPEC §6's default of 64 KiB.
func TestTheDefaultPayloadLimitIs64KiB(t *testing.T) {
	for name, opts := range map[string][]tally.Option{
		"no option":   nil,
		"zero Limits": {tally.WithLimits(tally.Limits{})},
	} {
		t.Run(name, func(t *testing.T) {
			l := open(t, tallytest.NewMemStore(), opts...)
			if _, err := l.Append(context.Background(), withPayload(64<<10)); err != nil {
				t.Fatalf("a payload of 64 KiB: %v", err)
			}
			_, err := l.Append(context.Background(), withPayload(64<<10+1))
			payloadRejected(t, err)
		})
	}
}
