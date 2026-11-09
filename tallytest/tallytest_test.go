package tallytest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/JonasBorgesLM/tally"
)

var errDisk = errors.New("disk on fire")

func recs(from uint64, n int) []tally.Record {
	out := make([]tally.Record, n)
	for i := range out {
		seq := from + uint64(i)
		out[i] = tally.Record{Seq: seq, Body: []byte{byte(seq), 0xEE}} // #nosec G115 -- test seqs stay below 256.
	}
	return out
}

func readAll(t *testing.T, s tally.Source, from uint64) []tally.Record {
	t.Helper()
	var out []tally.Record
	for r, err := range s.Records(context.Background(), from) {
		if err != nil {
			t.Fatalf("Records: %v", err)
		}
		out = append(out, r)
	}
	return out
}

func TestMemStoreAppendsAndReads(t *testing.T) {
	s := NewMemStore()
	ctx := context.Background()
	if err := s.AppendBatch(ctx, recs(0, 3)); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendBatch(ctx, recs(3, 2)); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendBatch(ctx, nil); err != nil {
		t.Fatalf("an empty batch: %v", err)
	}
	got := readAll(t, s, 0)
	if len(got) != 5 || s.Len() != 5 {
		t.Fatalf("read %d records, Len %d; want 5", len(got), s.Len())
	}
	for i, r := range got {
		if r.Seq != uint64(i) || r.Body[0] != byte(i) {
			t.Fatalf("record %d = %+v", i, r)
		}
	}
	if tail := readAll(t, s, 3); len(tail) != 2 || tail[0].Seq != 3 {
		t.Fatalf("Records from 3 = %+v", tail)
	}
	if past := readAll(t, s, 99); len(past) != 0 {
		t.Fatalf("Records past the end = %+v", past)
	}
}

// A writer that assigns seq wrongly must fail in tests, and the refused batch
// must leave nothing behind.
//
// Negative control: removing the seq check in MemStore.AppendBatch made every
// case fail.
func TestMemStoreRefusesABatchThatDoesNotContinueTheLog(t *testing.T) {
	for name, batch := range map[string][]tally.Record{
		"starts with a gap":   recs(3, 1),
		"repeats the last":    recs(1, 1),
		"gap inside":          {{Seq: 2}, {Seq: 4}},
		"out of order inside": {{Seq: 3}, {Seq: 2}},
	} {
		t.Run(name, func(t *testing.T) {
			s := NewMemStore()
			if err := s.AppendBatch(context.Background(), recs(0, 2)); err != nil {
				t.Fatal(err)
			}
			if err := s.AppendBatch(context.Background(), batch); err == nil {
				t.Fatal("AppendBatch accepted it")
			}
			if s.Len() != 2 {
				t.Fatalf("Len = %d after a refused batch, want 2", s.Len())
			}
		})
	}
}

// Stored bytes are what was given: changing the caller's buffer afterwards, or
// a body read back, must not change what is stored (RS-03).
//
// Negative control: storing r.Body without cloning made the first check fail,
// and yielding it without cloning made the second fail.
func TestMemStoreCopiesBodies(t *testing.T) {
	s := NewMemStore()
	in := recs(0, 1)
	if err := s.AppendBatch(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	in[0].Body[0] = 0x77
	if got := readAll(t, s, 0)[0].Body[0]; got != 0x00 {
		t.Fatalf("the store holds the caller's buffer: byte 0 is %#x", got)
	}
	readAll(t, s, 0)[0].Body[0] = 0x77
	if got := readAll(t, s, 0)[0].Body[0]; got != 0x00 {
		t.Fatalf("a reader changed the stored bytes: byte 0 is %#x", got)
	}
}

func TestMemStoreAfterClose(t *testing.T) {
	s := NewMemStore()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := s.AppendBatch(context.Background(), recs(0, 1)); !errors.Is(err, tally.ErrClosed) {
		t.Fatalf("AppendBatch after Close = %v, want ErrClosed", err)
	}
	for _, err := range s.Records(context.Background(), 0) {
		if !errors.Is(err, tally.ErrClosed) {
			t.Fatalf("Records after Close yielded %v, want ErrClosed", err)
		}
		return
	}
	t.Fatal("Records after Close yielded nothing: an empty log, not an error")
}

func TestMemStoreHonoursContext(t *testing.T) {
	s := NewMemStore()
	if err := s.AppendBatch(context.Background(), recs(0, 3)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.AppendBatch(ctx, recs(3, 1)); !errors.Is(err, context.Canceled) || s.Len() != 3 {
		t.Fatalf("AppendBatch on a cancelled ctx = %v, Len %d", err, s.Len())
	}
	for _, err := range s.Records(ctx, 0) {
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Records on a cancelled ctx yielded %v", err)
		}
		return
	}
	t.Fatal("Records on a cancelled ctx yielded nothing")
}

// Negative control: making FailAppend write the batch before returning its
// error made this fail.
func TestFailAppendWritesNothing(t *testing.T) {
	mem := NewMemStore()
	s := NewFaultyStore(mem, FailAppend(2, errDisk))
	ctx := context.Background()
	if err := s.AppendBatch(ctx, recs(0, 2)); err != nil {
		t.Fatalf("call 1: %v", err)
	}
	if err := s.AppendBatch(ctx, recs(2, 2)); !errors.Is(err, errDisk) {
		t.Fatalf("call 2 = %v, want errDisk", err)
	}
	if mem.Len() != 2 {
		t.Fatalf("Len = %d after a failed call, want 2", mem.Len())
	}
	if err := s.AppendBatch(ctx, recs(2, 1)); err != nil {
		t.Fatalf("call 3 is not faulted: %v", err)
	}
	if got := s.AppendCalls(); got != 3 {
		t.Fatalf("AppendCalls = %d, want 3", got)
	}
}

func TestTearAppendWritesAPrefix(t *testing.T) {
	mem := NewMemStore()
	s := NewFaultyStore(mem, TearAppend(1, 2, errDisk))
	if err := s.AppendBatch(context.Background(), recs(0, 5)); !errors.Is(err, errDisk) {
		t.Fatalf("AppendBatch = %v, want errDisk", err)
	}
	if mem.Len() != 2 {
		t.Fatalf("Len = %d, want the 2 kept records", mem.Len())
	}
}

// The writer is inside the store, and the batch is not durable, until the test
// says so. No sleep decides anything.
//
// Negative control: going to the inner store before waiting on release made
// this fail (Len was 1 before release).
func TestBlockAppendHoldsTheBatch(t *testing.T) {
	mem := NewMemStore()
	entered, release := make(chan struct{}), make(chan struct{})
	s := NewFaultyStore(mem, BlockAppend(1, entered, release))

	done := make(chan error, 1)
	go func() { done <- s.AppendBatch(context.Background(), recs(0, 1)) }()

	<-entered
	if mem.Len() != 0 {
		t.Fatalf("Len = %d while blocked, want 0", mem.Len())
	}
	select {
	case err := <-done:
		t.Fatalf("AppendBatch returned (%v) before release", err)
	default:
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("AppendBatch after release: %v", err)
	}
	if mem.Len() != 1 {
		t.Fatalf("Len = %d after release, want 1", mem.Len())
	}
}

func TestBlockAppendGivesUpOnCancel(t *testing.T) {
	mem := NewMemStore()
	entered, release := make(chan struct{}), make(chan struct{})
	s := NewFaultyStore(mem, BlockAppend(1, entered, release))
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- s.AppendBatch(ctx, recs(0, 1)) }()
	<-entered
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("AppendBatch = %v, want context.Canceled", err)
	}
	if mem.Len() != 0 {
		t.Fatalf("Len = %d after a cancelled block, want 0", mem.Len())
	}
}

func TestFixedClock(t *testing.T) {
	t0 := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	c := NewFixedClock(t0)
	if !c.Now().Equal(t0) {
		t.Fatalf("Now = %v", c.Now())
	}
	c.Advance(time.Second)
	c.Advance(-3 * time.Second)
	if want := t0.Add(-2 * time.Second); !c.Now().Equal(want) {
		t.Fatalf("Now = %v, want %v", c.Now(), want)
	}
	c.Set(t0.Add(-time.Hour))
	if want := t0.Add(-time.Hour); !c.Now().Equal(want) {
		t.Fatalf("Now = %v after Set, want %v", c.Now(), want)
	}
}

// The doubles satisfy the interfaces they stand in for.
var (
	_ tally.Store = (*MemStore)(nil)
	_ tally.Store = (*FaultyStore)(nil)
	_ tally.Clock = (*FixedClock)(nil)
)
