package tally_test

import (
	"context"
	"encoding/base64"
	"errors"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/internal/note"
	"github.com/JonasBorgesLM/tally/tallytest"
)

// cpBody is a checkpoint opened under the published test key and split into
// SPEC §5.2's six lines.
type cpBody struct {
	origin, kind, head, at, state string
	size                          uint64
}

var checkpointTime = regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{9}Z$`)

func openCheckpoint(t *testing.T, cp tally.SignedCheckpoint) cpBody {
	t.Helper()
	v, err := note.NewVerifier(tallytest.TestVerifierKey)
	if err != nil {
		t.Fatal(err)
	}
	n, err := note.Open(cp, []*note.Verifier{v})
	if err != nil {
		t.Fatalf("the checkpoint does not open under the test key: %v\n%s", err, cp)
	}
	lines := strings.Split(strings.TrimSuffix(string(n.Text), "\n"), "\n")
	if len(lines) != 6 {
		t.Fatalf("a checkpoint body has %d lines, want 6:\n%s", len(lines), n.Text)
	}
	size, err := strconv.ParseUint(lines[2], 10, 64)
	if err != nil {
		t.Fatalf("size line %q: %v", lines[2], err)
	}
	return cpBody{origin: lines[0], kind: lines[1], size: size, head: lines[3], at: lines[4], state: lines[5]}
}

func storedCheckpoints(t *testing.T, mem *tallytest.MemStore) []cpBody {
	t.Helper()
	var out []cpBody
	for cp, err := range mem.Checkpoints(context.Background()) {
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, openCheckpoint(t, cp))
	}
	return out
}

// waitFor yields until cond holds. It decides nothing by time: the bound only
// turns a defect into a failure instead of a hang.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		runtime.Gosched()
	}
}

// SPEC §5.2: the body, line by line, signed by the log's key and over the
// durable head.
func TestACheckpointFollowsTheSpec(t *testing.T) {
	mem := tallytest.NewMemStore()
	l := open(t, mem)
	for i := range 2 {
		if _, err := l.Append(context.Background(), event("e"+strconv.Itoa(i))); err != nil {
			t.Fatal(err)
		}
	}
	cp, err := l.Checkpoint(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b := openCheckpoint(t, cp)
	all := bodies(t, mem)
	head := leaf(all[len(all)-1])
	if b.origin != "example.com/log" || b.kind != "tally-chain/v1" || b.size != 3 ||
		b.head != base64.StdEncoding.EncodeToString(head[:]) || b.state != "open" {
		t.Fatalf("checkpoint body %+v", b)
	}
	if !checkpointTime.MatchString(b.at) {
		t.Fatalf("recorded_at %q is not SPEC §5.2's layout", b.at)
	}
	if mem.CheckpointCount() != 1 {
		t.Fatalf("store holds %d checkpoints, want the one returned", mem.CheckpointCount())
	}
}

// RF-06, the entry trigger: a checkpoint every n entries.
//
// Negative control: removing the dueByEntries trigger in the writer made this
// fail (only the closed checkpoint was stored).
func TestACheckpointEveryNEntries(t *testing.T) {
	mem := tallytest.NewMemStore()
	l, err := tally.Open(context.Background(), keepOpen{mem}, testOrigin, tally.WithCheckpointEvery(3, 0), tally.WithMaxBatch(1))
	if err != nil {
		t.Fatal(err)
	}
	for i := range 6 {
		if _, err := l.Append(context.Background(), event("e"+strconv.Itoa(i))); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	stored := storedCheckpoints(t, mem)
	sizes := make([]uint64, 0, len(stored))
	states := make([]string, 0, len(stored))
	for _, b := range stored {
		sizes = append(sizes, b.size)
		states = append(states, b.state)
	}
	// Leaves 0..3 make size 4 after three entries, then 7 after six; Close
	// adds the closed one over the same head.
	if len(sizes) != 3 || sizes[0] != 4 || sizes[1] != 7 || sizes[2] != 7 ||
		states[0] != "open" || states[1] != "open" || states[2] != "closed" {
		t.Fatalf("checkpoints at sizes %v with states %v, want [4 7 7] [open open closed]", sizes, states)
	}
}

// RF-06, the heartbeat: a checkpoint every period of the log's Clock, even
// with no entries, and again every period after. Driven by FixedClock, with no
// sleep.
//
// Negative control: not re-arming the timer after a heartbeat made the second
// heartbeat time out.
func TestAHeartbeatEveryPeriodEvenWithNoEntries(t *testing.T) {
	mem := tallytest.NewMemStore()
	clock := tallytest.NewFixedClock(time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC))
	open(t, mem, tally.WithClock(clock), tally.WithCheckpointEvery(0, time.Minute))

	for want := 1; want <= 2; want++ {
		waitFor(t, "the heartbeat timer to be armed", func() bool { return clock.Timers() == 1 })
		clock.Advance(time.Minute)
		waitFor(t, "a heartbeat checkpoint", func() bool { return mem.CheckpointCount() == want })
	}
	cps := storedCheckpoints(t, mem)
	if cps[0].size != 1 || cps[1].size != 1 || cps[0].at != "2026-11-10T12:01:00.000000000Z" ||
		cps[1].at != "2026-11-10T12:02:00.000000000Z" {
		t.Fatalf("heartbeats %+v, want two over the genesis alone, a minute apart", cps)
	}
}

// RF-06, on Close: a last checkpoint with state "closed", over the head. It is
// what lets an honest restart produce no false heartbeat alarm (ADR-0006).
//
// Negative control: removing the closed checkpoint from the writer's finish
// made this fail.
func TestCloseSignsAClosedCheckpoint(t *testing.T) {
	mem := tallytest.NewMemStore()
	l, err := tally.Open(context.Background(), keepOpen{mem}, testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(context.Background(), event("a")); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	cps := storedCheckpoints(t, mem)
	if len(cps) != 1 || cps[0].state != "closed" || cps[0].size != 2 {
		t.Fatalf("checkpoints after Close %+v, want one closed checkpoint over size 2", cps)
	}
}

// #26: a checkpoint covers durable state only. While a batch is held in the
// store, a Checkpoint request waits behind it and then covers it; a batch the
// store fails is never covered, and a poisoned log signs nothing more.
//
// Negative control: letting checkpoint run on a poisoned log made the
// failed-batch case fail. Signing over anything but l.head is not a mutation
// the code allows: commit advances l.head only after AppendBatch returned.
func TestACheckpointCoversDurableStateOnly(t *testing.T) {
	t.Run("waits for the batch in flight", func(t *testing.T) {
		mem := tallytest.NewMemStore()
		entered, release := make(chan struct{}), make(chan struct{})
		l := open(t, tallytest.NewFaultyStore(mem, tallytest.BlockAppend(2, entered, release)))
		go func() { _, _ = l.Append(context.Background(), event("held")) }()
		<-entered
		got := make(chan tally.SignedCheckpoint, 1)
		go func() {
			cp, err := l.Checkpoint(context.Background())
			if err != nil {
				t.Errorf("Checkpoint: %v", err)
			}
			got <- cp
		}()
		close(release)
		if b := openCheckpoint(t, <-got); b.size != 2 {
			t.Fatalf("checkpoint size %d, want 2: it must cover the batch that was in flight", b.size)
		}
	})
	t.Run("never over a failed batch", func(t *testing.T) {
		mem := tallytest.NewMemStore()
		l := open(t, tallytest.NewFaultyStore(mem, tallytest.FailAppend(2, errDisk)))
		if _, err := l.Append(context.Background(), event("lost")); !errors.Is(err, tally.ErrPoisoned) {
			t.Fatalf("Append = %v, want ErrPoisoned", err)
		}
		if cp, err := l.Checkpoint(context.Background()); !errors.Is(err, tally.ErrPoisoned) || cp != nil {
			t.Fatalf("Checkpoint on a poisoned log = %q, %v; want ErrPoisoned", cp, err)
		}
		if err := l.Close(); err != nil {
			t.Fatalf("Close of a poisoned log: %v", err)
		}
		if n := mem.CheckpointCount(); n != 0 {
			t.Fatalf("a poisoned log stored %d checkpoints, want none", n)
		}
	})
}

// ADR-0009: failing to store a checkpoint is a store error, and poisons.
//
// Negative control: ignoring PutCheckpoint's error made this fail.
func TestAFailedPutCheckpointPoisons(t *testing.T) {
	store := tallytest.NewFaultyStore(tallytest.NewMemStore(), tallytest.FailPutCheckpoint(1, errDisk))
	l := open(t, store)
	if _, err := l.Checkpoint(context.Background()); !errors.Is(err, tally.ErrPoisoned) || !errors.Is(err, errDisk) {
		t.Fatalf("Checkpoint = %v, want ErrPoisoned wrapping the store error", err)
	}
	if _, err := l.Append(context.Background(), event("a")); !errors.Is(err, tally.ErrPoisoned) {
		t.Fatalf("Append after a failed checkpoint = %v, want ErrPoisoned", err)
	}
}

// After a reopen, a checkpoint never claims an earlier time than the last one
// stored, even when the clock has gone back (SPEC §7 step 6), and the entry
// trigger counts from the stored checkpoint.
//
// Negative control: not recovering the last checkpoint in Open made this fail
// (the new checkpoint's time went back).
func TestCheckpointTimesSurviveAReopen(t *testing.T) {
	mem := tallytest.NewMemStore()
	clock := tallytest.NewFixedClock(time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC))
	l1, openErr := tally.Open(context.Background(), keepOpen{mem}, testOrigin, tally.WithClock(clock))
	if openErr != nil {
		t.Fatal(openErr)
	}
	clock.Advance(time.Hour)
	if _, err := l1.Checkpoint(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := l1.Close(); err != nil {
		t.Fatal(err)
	}

	clock.Advance(-2 * time.Hour) // the host clock is now behind the stored checkpoints
	l2 := open(t, keepOpen{mem}, tally.WithClock(clock))
	cp, err := l2.Checkpoint(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := openCheckpoint(t, cp).at; got < "2026-11-10T13:00:00.000000000Z" {
		t.Fatalf("a checkpoint after reopen claims %s, before the stored one at 13:00", got)
	}
}
