package tally_test

import (
	"context"
	"encoding/binary"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/tallytest"
)

// Byte offsets in an ENTRY body, from SPEC §2.2: version and type (2), log_id
// (16), seq (8), then recorded_at and occurred_at. Read here rather than
// through the package's decoder.
const (
	offRecordedAt = 2 + 16 + 8
	offOccurredAt = offRecordedAt + 8
)

func int64At(b []byte, off int) int64 {
	return int64(binary.BigEndian.Uint64(b[off:])) // #nosec G115 -- the bit pattern is the encoding.
}

// regressions is an Observer that keeps ClockRegression events.
type regressions struct {
	recorder
	mu sync.Mutex
	by []time.Duration
}

func (r *regressions) ClockRegression(by time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.by = append(r.by, by)
}

func (r *regressions) events() []time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]time.Duration(nil), r.by...)
}

// RF-03, ADR-0007: a clock that steps back does not make recorded_at go back.
// The value is clamped to the previous one, and the Observer is told by how
// much the clock regressed. The chain still verifies.
//
// Negative controls: removing the clamp made Append fail with TimeRegression;
// removing the ClockRegression call made the event check fail.
func TestAClockSteppingBackIsClampedAndReported(t *testing.T) {
	mem := tallytest.NewMemStore()
	clock := tallytest.NewFixedClock(time.Unix(1_800_000_000, 0))
	obs := &regressions{}
	l := open(t, mem, tally.WithClock(clock), tally.WithObserver(obs))

	steps := []time.Duration{time.Second, -time.Hour, 10 * time.Minute, 2 * time.Hour}
	var last tally.Receipt
	for i, d := range steps {
		clock.Advance(d)
		r, err := l.Append(context.Background(), event("e"+strconv.Itoa(i)))
		if err != nil {
			t.Fatalf("Append after a step of %v: %v", d, err)
		}
		last = r
	}

	all := bodies(t, mem)
	prev := int64(0)
	for i, b := range all[1:] {
		got := int64At(b, offRecordedAt)
		if got < prev {
			t.Fatalf("entry %d: recorded_at %d is before the previous %d", i+1, got, prev)
		}
		prev = got
	}
	// After the step back the clock reads 1h earlier than the last value; the
	// next step of +10m still leaves it 50m behind, so it is clamped again.
	want := []time.Duration{time.Hour, 50 * time.Minute}
	if got := obs.events(); len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("ClockRegression events %v, want %v", got, want)
	}
	if size := verifyStored(t, mem, last.LeafHash); size != len(steps)+1 {
		t.Fatalf("store holds %d records", size)
	}
}

// A clock that stands still or moves forward is not a regression.
func TestAClockThatDoesNotGoBackIsNotReported(t *testing.T) {
	clock := tallytest.NewFixedClock(time.Unix(1_800_000_000, 0))
	obs := &regressions{}
	l := open(t, tallytest.NewMemStore(), tally.WithClock(clock), tally.WithObserver(obs))
	for i, d := range []time.Duration{0, 0, time.Nanosecond, time.Hour} {
		clock.Advance(d)
		if _, err := l.Append(context.Background(), event("e"+strconv.Itoa(i))); err != nil {
			t.Fatal(err)
		}
	}
	if got := obs.events(); len(got) != 0 {
		t.Fatalf("ClockRegression events %v for a clock that never went back", got)
	}
}

// occurred_at is the caller's claim and is stored as given: never clamped,
// whether it is far in the past, in the future, or earlier than the previous
// entry's (T-14 is documented, not corrected).
//
// Negative control: clamping occurred_at the way recorded_at is clamped made
// this fail.
func TestOccurredAtIsStoredAsGiven(t *testing.T) {
	mem := tallytest.NewMemStore()
	l := open(t, mem, tally.WithClock(tallytest.NewFixedClock(time.Unix(1_800_000_000, 0))))
	given := []time.Time{
		time.Unix(1_900_000_000, 0),       // after the log's clock
		time.Unix(1_000, 0),               // long before it, and before the previous
		time.Unix(-5, 0),                  // before the epoch
		time.Unix(1_800_000_000, 7).UTC(), // nanoseconds survive
	}
	for i, at := range given {
		ev := event("e" + strconv.Itoa(i))
		ev.OccurredAt = at
		if _, err := l.Append(context.Background(), ev); err != nil {
			t.Fatal(err)
		}
	}
	for i, b := range bodies(t, mem)[1:] {
		if got, want := int64At(b, offOccurredAt), given[i].UnixNano(); got != want {
			t.Fatalf("entry %d: occurred_at %d, want %d as given", i+1, got, want)
		}
	}
}
