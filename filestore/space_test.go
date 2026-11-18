package filestore

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/internal/fsx"
)

// spaceFS is a faultFS whose free space is what its write budget leaves, so
// the disk fills as the log writes, and whose preallocation can be made to
// fail.
type spaceFS struct {
	*faultFS
	preallocErr error

	mu        sync.Mutex
	freeCalls int
	preallocs int
}

func newSpaceFS(budget int64) *spaceFS {
	f := newFaultFS()
	f.budget = budget
	return &spaceFS{faultFS: f}
}

func (s *spaceFS) FreeSpace(string) (uint64, error) {
	s.mu.Lock()
	s.freeCalls++
	s.mu.Unlock()
	s.faultFS.mu.Lock()
	defer s.faultFS.mu.Unlock()
	return uint64(s.budget - s.written), nil // #nosec G115 -- written never exceeds budget
}

func (s *spaceFS) Preallocate(string, int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.preallocs++
	return s.preallocErr
}

// spaceObserver records DiskSpace calls, and the failures the test marks, in
// the order they happen.
type spaceObserver struct {
	mu     sync.Mutex
	events []string
	frees  []uint64
}

func (o *spaceObserver) mark(e string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.events = append(o.events, e)
}

func (*spaceObserver) Batch(int, time.Duration)      {}
func (*spaceObserver) AnchorPublish(error, uint64)   {}
func (*spaceObserver) ClockRegression(time.Duration) {}
func (*spaceObserver) Poisoned(error)                {}
func (*spaceObserver) Recovered(int64)               {}
func (o *spaceObserver) DiskSpace(free uint64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.events = append(o.events, "low")
	o.frees = append(o.frees, free)
}

// Below the threshold, the Observer is told before writes start failing
// (RNF-10, T-16): the disk fills as the log writes, and a DiskSpace report,
// under the threshold, comes before the first failed Append.
//
// Seen failing with both checkSpace calls removed from the Log. Removing only
// the one after a batch leaves the one after a checkpoint to warn in time.
func TestTheObserverHearsOfLowSpaceBeforeWritesFail(t *testing.T) {
	const budget, threshold = 3000, 1000
	ctx := t.Context()
	fsys := newSpaceFS(budget)
	s, err := Open(ctx, logDir(t), withFS(fsys), WithSegmentSize(800), WithFreeSpaceThreshold(threshold))
	if err != nil {
		t.Fatal(err)
	}
	o := &spaceObserver{}
	l, err := tally.Open(ctx, s, signer(t), tally.WithObserver(o), tally.WithCheckpointEvery(3, 0), tally.WithMaxDelay(0))
	if err != nil {
		t.Fatal(err)
	}
	failed := false
	for i := range 100 {
		if _, err := l.Append(ctx, event(fmt.Sprint(i))); err != nil {
			o.mark("fail")
			failed = true
			break
		}
	}
	_ = l.Close()
	if !failed {
		t.Fatal("the disk never filled; the test meant it to")
	}

	o.mu.Lock()
	defer o.mu.Unlock()
	firstLow, firstFail := -1, -1
	for i, e := range o.events {
		if e == "low" && firstLow < 0 {
			firstLow = i
		}
		if e == "fail" && firstFail < 0 {
			firstFail = i
		}
	}
	if firstLow < 0 || firstLow > firstFail {
		t.Fatalf("events %v: the Observer was not told before the first failure", o.events)
	}
	for _, free := range o.frees {
		if free >= threshold {
			t.Errorf("DiskSpace(%d), at or above the threshold %d", free, threshold)
		}
	}
}

// With no threshold the Store never measures, and the Observer hears nothing.
func TestNoThresholdNoReport(t *testing.T) {
	ctx := t.Context()
	fsys := newSpaceFS(1 << 20)
	s, err := Open(ctx, logDir(t), withFS(fsys))
	if err != nil {
		t.Fatal(err)
	}
	o := &spaceObserver{}
	l, err := tally.Open(ctx, s, signer(t), tally.WithObserver(o), tally.WithCheckpointEvery(2, 0), tally.WithMaxDelay(0))
	if err != nil {
		t.Fatal(err)
	}
	for i := range 5 {
		if _, err := l.Append(ctx, event(fmt.Sprint(i))); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if fsys.freeCalls != 0 || len(o.events) != 0 {
		t.Errorf("statfs calls %d, events %v; want none", fsys.freeCalls, o.events)
	}
}

// LowSpace reports a failed preallocation once, whatever the threshold, and a
// failure is not a write error: the log goes on (RNF-10).
//
// Seen failing, on Linux, with the Preallocate call removed from
// startSegment, and with the failure flag no longer reset by LowSpace.
func TestAFailedPreallocationIsReportedOnce(t *testing.T) {
	if !fsx.PreallocationSupported {
		t.Skip("preallocation is Linux only")
	}
	ctx := context.Background()
	fsys := newSpaceFS(1 << 20)
	fsys.preallocErr = errors.New("no room to preallocate")
	s, err := Open(ctx, logDir(t), withFS(fsys), WithPreallocation())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if err := s.AppendBatch(ctx, records(vectorBodies(t), 0)); err != nil {
		t.Fatalf("AppendBatch after a failed preallocation: %v", err)
	}
	if fsys.preallocs != 1 {
		t.Fatalf("%d preallocations, want 1 for the genesis segment", fsys.preallocs)
	}
	if _, low := s.LowSpace(); !low {
		t.Error("the failed preallocation was not reported")
	}
	if _, low := s.LowSpace(); low {
		t.Error("the failed preallocation was reported twice")
	}
}

// On macOS, preallocation would need unsafe: Open refuses the option rather
// than pretend.
//
// Seen failing with the platform check removed from Open.
func TestPreallocationUnsupportedIsRefused(t *testing.T) {
	if fsx.PreallocationSupported {
		t.Skip("preallocation is supported here")
	}
	if _, err := Open(t.Context(), logDir(t), WithPreallocation()); !errors.Is(err, ErrPreallocationUnsupported) {
		t.Fatalf("Open = %v, want ErrPreallocationUnsupported", err)
	}
}
