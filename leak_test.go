package tally_test

import (
	"context"
	"errors"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/tallytest"
)

// RNF-06: Close leaves no goroutine behind, with appends in flight and with a
// poisoned log. The check needs no third-party library: it snapshots the
// goroutines before a test and, after Close, reports any new one with a frame
// in this module. That catches the writer and any goroutine tally starts later,
// whatever its name.

var goroutineHeader = regexp.MustCompile(`(?m)^goroutine (\d+) \[`)

// goroutines returns every goroutine's stack, by id.
func goroutines() map[string]string {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	out := map[string]string{}
	for _, g := range strings.Split(string(buf), "\n\n") {
		if m := goroutineHeader.FindStringSubmatch(g); m != nil {
			out[m[1]] = g
		}
	}
	return out
}

// leakedSince returns the stacks of goroutines that are not in before and run
// code from this module.
func leakedSince(before map[string]string) []string {
	var leaked []string
	for id, stack := range goroutines() {
		if _, old := before[id]; old {
			continue
		}
		if strings.Contains(stack, "github.com/JonasBorgesLM/tally.") ||
			strings.Contains(stack, "github.com/JonasBorgesLM/tally/") {
			leaked = append(leaked, stack)
		}
	}
	return leaked
}

// checkNoLeaks fails the test if, after it, a goroutine from this module
// survives. A goroutine that has done its work may still be returning from
// its last deferred call when Close returns, so the check yields for a short,
// bounded while before it decides; nothing waits on it when there is no leak.
func checkNoLeaks(t *testing.T) {
	t.Helper()
	before := goroutines()
	t.Cleanup(func() {
		var leaked []string
		for range 1000 {
			if leaked = leakedSince(before); len(leaked) == 0 {
				return
			}
			runtime.Gosched()
			time.Sleep(time.Millisecond)
		}
		t.Errorf("%d goroutine(s) left after Close:\n\n%s", len(leaked), strings.Join(leaked, "\n\n"))
	})
}

func TestNoLeakAfterCloseOfAnIdleLog(t *testing.T) {
	checkNoLeaks(t)
	l, err := tally.Open(context.Background(), tallytest.NewMemStore(), testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNoLeakAfterCloseOfABusyLog(t *testing.T) {
	checkNoLeaks(t)
	l, err := tally.Open(context.Background(), tallytest.NewMemStore(), testOrigin, tally.WithMaxBatch(4))
	if err != nil {
		t.Fatal(err)
	}
	for i := range 50 {
		if _, err := l.Append(context.Background(), event("e"+strconv.Itoa(i))); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// Close while Appends are in flight: one held in the store, others queued or
// waiting to enqueue. Every Append returns, and nothing is left running.
//
// Negative controls (#24, "seen failing with a deliberately leaked
// goroutine"): a goroutine started in Open that never exits made every
// TestNoLeak case fail, naming tally.Open.func1; a writer that never exits,
// with Close not waiting for it, made this and the idle case fail, naming
// tally.(*Log).writer.
func TestNoLeakAfterCloseWithAppendsInFlight(t *testing.T) {
	checkNoLeaks(t)
	entered, release := make(chan struct{}), make(chan struct{})
	store := tallytest.NewFaultyStore(tallytest.NewMemStore(), tallytest.BlockAppend(2, entered, release))
	l, err := tally.Open(context.Background(), store, testOrigin, tally.WithMaxBatch(2))
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := l.Append(context.Background(), event("e"+strconv.Itoa(i)))
			if err != nil && !errors.Is(err, tally.ErrClosed) {
				t.Errorf("Append: %v", err)
			}
		}()
	}
	<-entered // a batch is in the store, others wait behind it

	closed := make(chan error, 1)
	go func() { closed <- l.Close() }()
	close(release)
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	wg.Wait()
}

func TestNoLeakAfterCloseOfAPoisonedLog(t *testing.T) {
	checkNoLeaks(t)
	store := tallytest.NewFaultyStore(tallytest.NewMemStore(), tallytest.FailAppend(2, errDisk))
	l, err := tally.Open(context.Background(), store, testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(context.Background(), event("a")); !errors.Is(err, tally.ErrPoisoned) {
		t.Fatalf("Append = %v, want ErrPoisoned", err)
	}
	if _, err := l.Append(context.Background(), event("b")); !errors.Is(err, tally.ErrPoisoned) {
		t.Fatalf("Append = %v, want ErrPoisoned", err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}

// The check itself must be able to fail: a goroutine started by this module
// and left running is reported. Here the test starts one through tallytest,
// whose BlockAppend waits on a channel nobody closes until after the check.
func TestTheLeakCheckSeesALeak(t *testing.T) {
	before := goroutines()
	entered, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	store := tallytest.NewFaultyStore(tallytest.NewMemStore(), tallytest.BlockAppend(1, entered, release))
	go func() { _ = store.AppendBatch(context.Background(), []tally.Record{{Seq: 0}}) }()
	<-entered

	if leaked := leakedSince(before); len(leaked) != 1 || !strings.Contains(leaked[0], "tallytest.(*FaultyStore).AppendBatch") {
		t.Fatalf("the check found %d leaked goroutine(s), want the blocked AppendBatch:\n%s", len(leaked), strings.Join(leaked, "\n\n"))
	}
}
