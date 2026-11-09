package tally_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/tallytest"
)

func sealedPayload(ref tally.SubjectRef, nonce byte) tally.Payload {
	ct := append([]byte{0x01}, bytes.Repeat([]byte{nonce}, 12+16+8)...)
	return tally.Sealed(ref, ct)
}

// RF-04: a retry returns the original Receipt with Duplicate set, records
// nothing, and does not reach the store.
//
// Negative control: removing the window lookup in the writer made this fail
// (the retry got seq 2).
func TestARetryReturnsTheOriginalReceipt(t *testing.T) {
	mem := tallytest.NewMemStore()
	faulty := tallytest.NewFaultyStore(mem)
	l := open(t, faulty)

	first, err := l.Append(context.Background(), event("e1"))
	if err != nil {
		t.Fatal(err)
	}
	calls := faulty.AppendCalls()
	again, err := l.Append(context.Background(), event("e1"))
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if !again.Duplicate || again.Seq != first.Seq || again.LeafHash != first.LeafHash {
		t.Fatalf("retry = %+v, want the original %+v with Duplicate", again, first)
	}
	if first.Duplicate {
		t.Fatal("the first Append was marked Duplicate")
	}
	if mem.Len() != 2 || faulty.AppendCalls() != calls {
		t.Fatalf("the retry was stored: %d records, %d store calls (was %d)", mem.Len(), faulty.AppendCalls(), calls)
	}
}

// RF-17, R-29: the same EventID with different metadata is refused and records
// nothing. Returning the original receipt would hide the second event.
//
// Negative control: replying with the original receipt instead of
// ErrEventConflict made every case fail.
func TestARepeatedIDWithOtherMetadataIsAConflict(t *testing.T) {
	ref := tally.SubjectRef{1}
	svc, err := tally.Service("billing-api")
	if err != nil {
		t.Fatal(err)
	}
	base := event("e1")
	base.Payload = tally.Plain([]byte("detail"))

	for name, mutate := range map[string]func(ev *tally.Event){
		"actor":             func(ev *tally.Event) { ev.Actor = svc },
		"action":            func(ev *tally.Event) { ev.Action = "user.logout" },
		"resource":          func(ev *tally.Event) { ev.Resource = "session/2" },
		"outcome":           func(ev *tally.Event) { ev.Outcome = tally.OutcomeDenied },
		"payload kind":      func(ev *tally.Event) { ev.Payload = tally.Payload{} },
		"plain bytes":       func(ev *tally.Event) { ev.Payload = tally.Plain([]byte("other")) },
		"sealed, not plain": func(ev *tally.Event) { ev.Payload = sealedPayload(ref, 1) },
	} {
		t.Run(name, func(t *testing.T) {
			mem := tallytest.NewMemStore()
			l := open(t, mem)
			if _, err := l.Append(context.Background(), base); err != nil {
				t.Fatal(err)
			}
			ev := base
			mutate(&ev)
			r, err := l.Append(context.Background(), ev)
			if !errors.Is(err, tally.ErrEventConflict) {
				t.Fatalf("Append = %+v, %v; want ErrEventConflict", r, err)
			}
			if mem.Len() != 2 {
				t.Fatalf("a conflict recorded something: %d records", mem.Len())
			}
			// A conflict refuses one event; it does not poison the log.
			if _, err := l.Append(context.Background(), event("e2")); err != nil {
				t.Fatalf("Append after a conflict: %v", err)
			}
		})
	}
}

// A sealed payload differs on every retry, because its nonce is random, so the
// sealed bytes are not compared: a retry with a fresh nonce is a duplicate.
// The subject it is sealed for is compared: it is not random, and another
// subject is another event.
//
// Negative control: including the sealed bytes in the fingerprint made the
// fresh-nonce case a conflict.
func TestASealedRetryWithAFreshNonceIsADuplicate(t *testing.T) {
	ref := tally.SubjectRef{0xAB}
	l := open(t, tallytest.NewMemStore())
	ev := event("e1")
	ev.Payload = sealedPayload(ref, 1)
	first, err := l.Append(context.Background(), ev)
	if err != nil {
		t.Fatal(err)
	}

	ev.Payload = sealedPayload(ref, 2) // a fresh nonce
	again, err := l.Append(context.Background(), ev)
	if err != nil || !again.Duplicate || again.Seq != first.Seq {
		t.Fatalf("sealed retry = %+v, %v; want the original receipt as a duplicate", again, err)
	}

	ev.Payload = sealedPayload(tally.SubjectRef{0xCD}, 1) // another subject
	if _, err := l.Append(context.Background(), ev); !errors.Is(err, tally.ErrEventConflict) {
		t.Fatalf("sealed for another subject = %v, want ErrEventConflict", err)
	}
}

// T-11's residual, asserted so the docs cannot overclaim: past the window, a
// retried EventID is recorded again as a new entry.
func TestARetryPastTheWindowIsANewEntry(t *testing.T) {
	mem := tallytest.NewMemStore()
	l := open(t, mem, tally.WithIdempotencyWindow(3))
	for _, id := range []string{"a", "b", "c", "d"} {
		if _, err := l.Append(context.Background(), event(id)); err != nil {
			t.Fatal(err)
		}
	}
	r, err := l.Append(context.Background(), event("a"))
	if err != nil || r.Duplicate || r.Seq != 5 {
		t.Fatalf("retry of an id past the window = %+v, %v; want a new entry at seq 5", r, err)
	}
	if again, err := l.Append(context.Background(), event("d")); err != nil || !again.Duplicate {
		t.Fatalf("retry of an id inside the window = %+v, %v; want a duplicate", again, err)
	}
}

// RF-04: the window is rebuilt on open, so a retry after a restart is still a
// duplicate, and a conflict is still refused.
//
// Negative control: not rebuilding the window in Open made this fail (the
// retry got a new seq).
func TestTheWindowIsRebuiltOnOpen(t *testing.T) {
	mem := tallytest.NewMemStore()
	l1, err := tally.Open(context.Background(), keepOpen{mem}, testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	first, err := l1.Append(context.Background(), event("e1"))
	if err != nil {
		t.Fatal(err)
	}
	_ = l1.Close()

	l2 := open(t, mem)
	again, err := l2.Append(context.Background(), event("e1"))
	if err != nil || !again.Duplicate || again.Seq != first.Seq || again.LeafHash != first.LeafHash {
		t.Fatalf("retry after reopen = %+v, %v; want %+v as a duplicate", again, err, first)
	}
	other := event("e1")
	other.Action = "user.logout"
	if _, err := l2.Append(context.Background(), other); !errors.Is(err, tally.ErrEventConflict) {
		t.Fatalf("conflict after reopen = %v, want ErrEventConflict", err)
	}
}

// Concurrent retries of one event, which can share a batch: exactly one entry
// is recorded, every caller gets its receipt, and exactly one is not a
// duplicate.
//
// Negative control: removing the in-batch lookup in the writer made this fail
// (the same id was recorded several times).
func TestConcurrentRetriesRecordOneEntry(t *testing.T) {
	for round := range 20 {
		mem := tallytest.NewMemStore()
		l := open(t, mem, tally.WithMaxBatch(64))
		const callers = 16
		var (
			wg       sync.WaitGroup
			mu       sync.Mutex
			receipts []tally.Receipt
		)
		for range callers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r, err := l.Append(context.Background(), event("same"))
				if err != nil {
					t.Errorf("Append: %v", err)
					return
				}
				mu.Lock()
				receipts = append(receipts, r)
				mu.Unlock()
			}()
		}
		wg.Wait()
		originals := 0
		for _, r := range receipts {
			if !r.Duplicate {
				originals++
			}
			if r.Seq != 1 {
				t.Fatalf("round %d: a receipt has seq %d, want 1", round, r.Seq)
			}
		}
		if len(receipts) != callers || originals != 1 || mem.Len() != 2 {
			t.Fatalf("round %d: %d receipts, %d not duplicates, %d records; want %d, 1, 2",
				round, len(receipts), originals, mem.Len(), callers)
		}
	}
}

// A window of zero turns idempotency off: every Append is a new entry.
func TestAZeroWindowDisablesIdempotency(t *testing.T) {
	mem := tallytest.NewMemStore()
	l := open(t, mem, tally.WithIdempotencyWindow(0))
	for i := range 3 {
		r, err := l.Append(context.Background(), event("same"))
		if err != nil || r.Duplicate || r.Seq != uint64(i+1) {
			t.Fatalf("Append %d = %+v, %v; want a new entry", i, r, err)
		}
	}
}
