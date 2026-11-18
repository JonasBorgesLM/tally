package filestore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/internal/fsx"
)

// faultFS is the real filesystem with three faults, each at a position
// counted from the start of a run (RNF-11):
//
//   - budget: writes stop after budget bytes in all. The Write that crosses
//     it writes what fits and fails with ENOSPC (disk full) or, with short
//     set, returns the short count and no error. Negative means unlimited.
//   - failSync: the Sync numbered failSync (0-based) fails with EIO.
//     Negative means never.
//
// Sync never reaches the disk: these tests exercise the code's handling of
// faults, not the medium, and a real fsync per operation would make a sweep
// over every byte take minutes.
type faultFS struct {
	fsx.FS
	mu       sync.Mutex
	budget   int64
	short    bool
	failSync int
	written  int64
	syncs    int
	faulted  bool
}

func newFaultFS() *faultFS { return &faultFS{FS: fsx.OS{}, budget: -1, failSync: -1} }

func (f *faultFS) OpenFile(name string, flag int, perm fs.FileMode) (fsx.File, error) {
	file, err := f.FS.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return &faultFile{File: file, fs: f}, nil
}

type faultFile struct {
	fsx.File
	fs *faultFS
}

func (f *faultFile) Write(p []byte) (int, error) {
	f.fs.mu.Lock()
	n := int64(len(p))
	var err error
	if f.fs.budget >= 0 && f.fs.written+n > f.fs.budget {
		n = f.fs.budget - f.fs.written
		f.fs.faulted = true
		if !f.fs.short {
			err = syscall.ENOSPC
		}
	}
	f.fs.written += n
	f.fs.mu.Unlock()
	w, werr := f.File.Write(p[:n])
	if werr != nil {
		return w, werr
	}
	return w, err
}

func (f *faultFile) Sync() error {
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	i := f.fs.syncs
	f.fs.syncs++
	if i == f.fs.failSync {
		f.fs.faulted = true
		return syscall.EIO
	}
	return nil
}

// countingStore counts the write calls a Store receives after one of them
// failed: after a store error the Log must make none (ADR-0009).
type countingStore struct {
	*Store
	mu     sync.Mutex
	failed bool
	after  int
}

func (c *countingStore) note(err error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failed {
		c.after++
	}
	if err != nil {
		c.failed = true
	}
	return err
}

func (c *countingStore) AppendBatch(ctx context.Context, recs []tally.Record) error {
	return c.note(c.Store.AppendBatch(ctx, recs))
}

func (c *countingStore) PutCheckpoint(ctx context.Context, cp tally.SignedCheckpoint) error {
	return c.note(c.Store.PutCheckpoint(ctx, cp))
}

const faultEvents = 8

// faultRun is what one run of the scenario observed.
type faultRun struct {
	acked  []tally.Receipt
	failed bool // some call returned an error
	after  int  // store write calls after the first store error
}

// runScenario writes faultEvents entries through a Log over a filestore on
// fsys, with a checkpoint every 3 entries and small segments, so the run
// crosses genesis, appends, checkpoints and rotations. It stops at the first
// error, and checks that the Log is then poisoned.
func runScenario(t *testing.T, dir string, fsys fsx.FS) faultRun {
	t.Helper()
	ctx := t.Context()
	var run faultRun
	s, err := Open(ctx, dir, withFS(fsys), WithSegmentSize(300))
	if err != nil {
		run.failed = true
		return run
	}
	cs := &countingStore{Store: s}
	l, err := tally.Open(ctx, cs, signer(t), tally.WithCheckpointEvery(3, 0), tally.WithMaxDelay(0))
	if err != nil {
		run.failed = true
		_ = s.Close()
		run.after = cs.after
		return run
	}
	for i := range faultEvents {
		r, err := l.Append(ctx, event(fmt.Sprint(i)))
		if err != nil {
			run.failed = true
			if _, again := l.Append(ctx, event("again")); !errors.Is(again, tally.ErrPoisoned) {
				t.Errorf("after %v, the next Append = %v, want ErrPoisoned", err, again)
			}
			break
		}
		run.acked = append(run.acked, r)
	}
	if err := l.Close(); err != nil {
		run.failed = true
	}
	run.after = cs.after
	return run
}

// checkSurvivors reopens dir, as a restart would, and checks that the log
// verifies, a Log can open it, and every acknowledged entry is there with
// the leaf hash its receipt named (RF-01).
func checkSurvivors(t *testing.T, dir string, acked []tally.Receipt) {
	t.Helper()
	ctx := t.Context()
	s, err := Open(ctx, dir, withFS(newFaultFS()))
	if err != nil {
		t.Fatalf("reopening: %v", err)
	}
	leaves := map[uint64][32]byte{}
	for r, err := range s.Records(ctx, 0) {
		if err != nil {
			t.Fatalf("reading: %v", err)
		}
		leaves[r.Seq] = tally.LeafHash(r.Body)
	}
	for _, a := range acked {
		if got, ok := leaves[a.Seq]; !ok || got != a.LeafHash {
			t.Errorf("acknowledged entry %d is lost or changed", a.Seq)
		}
	}
	if len(leaves) > 0 {
		rep, verr := tally.Verify(ctx, s, verifiers(t))
		if verr != nil || !rep.OK() {
			t.Fatalf("Verify after reopening = %v, %+v", verr, rep)
		}
	}
	// A Log opens it and goes on: nothing unacknowledged broke the chain.
	l, err := tally.Open(ctx, s, signer(t), tally.WithCheckpointEvery(0, 0), tally.WithMaxDelay(0))
	if err != nil {
		t.Fatalf("tally.Open after reopening: %v", err)
	}
	if _, err := l.Append(ctx, event("after")); err != nil {
		t.Fatalf("Append after reopening: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}

// A clean run, to learn how many bytes and syncs a fault can land on.
func cleanRun(t *testing.T) (written int64, syncs int) {
	t.Helper()
	f := newFaultFS()
	run := runScenario(t, logDir(t), f)
	if run.failed || len(run.acked) != faultEvents {
		t.Fatalf("the clean run failed: %+v", run)
	}
	return f.written, f.syncs
}

// A write that fails at every byte of the log, as disk full (ENOSPC) or as a
// short write with no error: the Log is poisoned, the store sees no further
// write, and after reopening every acknowledged entry is there and the log
// verifies (RF-01, RF-20, ADR-0009, T-12).
//
// Seen failing with the Log's poisoning removed, and with the short-write
// check removed from writeAll. The Store's own sticky error is not reached
// here, since a poisoned Log never calls it again; TestAFaultIsFinal covers it.
func TestAWriteFaultAtEveryByte(t *testing.T) {
	written, _ := cleanRun(t)
	if written < 1000 {
		t.Fatalf("the scenario writes %d bytes; it meant to cross several files", written)
	}
	for _, short := range []bool{false, true} {
		mode := "disk full"
		if short {
			mode = "short write"
		}
		t.Run(mode, func(t *testing.T) {
			ran, faulted := 0, 0
			for k := range written {
				ran++
				f := newFaultFS()
				f.budget, f.short = k, short
				dir := logDir(t)
				run := runScenario(t, dir, f)
				if !f.faulted {
					t.Fatalf("byte %d: no fault was injected", k)
				}
				faulted++
				if !run.failed {
					t.Fatalf("byte %d: the fault was not reported", k)
				}
				if run.after != 0 {
					t.Fatalf("byte %d: the store saw %d writes after its error", k, run.after)
				}
				checkSurvivors(t, dir, run.acked)
				if t.Failed() {
					t.Fatalf("at byte %d of %d", k, written)
				}
			}
			if int64(ran) != written || faulted != ran || ran == 0 {
				t.Fatalf("ran %d offsets, %d faulted, want %d", ran, faulted, written)
			}
		})
	}
}

// An fsync error at every sync of the log poisons it, and the store sees no
// further write; after reopening, every acknowledged entry is there (RF-01,
// ADR-0009). The unacknowledged record may survive too, from the page cache
// (R-31): it must not break the chain.
//
// Seen failing with the Sync error ignored in AppendBatch.
func TestAnFsyncErrorAtEverySync(t *testing.T) {
	_, syncs := cleanRun(t)
	ran := 0
	for i := range syncs {
		ran++
		f := newFaultFS()
		f.failSync = i
		dir := logDir(t)
		run := runScenario(t, dir, f)
		if !run.failed {
			t.Fatalf("sync %d: the fault was not reported", i)
		}
		if run.after != 0 {
			t.Fatalf("sync %d: the store saw %d writes after its error", i, run.after)
		}
		checkSurvivors(t, dir, run.acked)
		if t.Failed() {
			t.Fatalf("at sync %d of %d", i, syncs)
		}
	}
	if ran != syncs || ran < 10 {
		t.Fatalf("ran %d syncs, want %d (and at least 10)", ran, syncs)
	}
}

// segSizeForCrash is between segment 0's size at the first checkpoint and
// segment 4's at the second, so the first rotates and the second does not.
var segSizeForCrash int64 = 460

// noFinalCheckpoint drops the checkpoint a Log stores on Close, as a crash
// before it would.
type noFinalCheckpoint struct {
	*Store
	closing bool
}

func (n *noFinalCheckpoint) PutCheckpoint(ctx context.Context, cp tally.SignedCheckpoint) error {
	if n.closing {
		return nil
	}
	return n.Store.PutCheckpoint(ctx, cp)
}

// crashedLog writes faultEvents entries with a checkpoint every 3, and stops
// as a crash would, before the closing checkpoint. Its segments rotate at the
// first checkpoint and not at the second, so the last segment holds records
// the last checkpoint covers and records past it. It returns the directory
// and the last segment's name.
func crashedLog(t *testing.T) (dir, last string) {
	t.Helper()
	ctx := t.Context()
	dir = logDir(t)
	s := &noFinalCheckpoint{Store: mustOpen(t, dir, withFS(newFaultFS()), WithSegmentSize(segSizeForCrash))}
	l, err := tally.Open(ctx, s, signer(t), tally.WithCheckpointEvery(3, 0), tally.WithMaxDelay(0))
	if err != nil {
		t.Fatal(err)
	}
	for i := range faultEvents {
		if _, err := l.Append(ctx, event(fmt.Sprint(i))); err != nil {
			t.Fatal(err)
		}
	}
	s.closing = true
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	firsts := segmentFirsts(t, dir)
	reader := mustOpen(t, dir)
	defer func() { _ = reader.Close() }()
	var floor uint64
	for cp, err := range reader.Checkpoints(ctx) {
		if err != nil {
			t.Fatal(err)
		}
		floor = checkpointSize(t, cp)
	}
	lastFirst := firsts[len(firsts)-1]
	if len(firsts) < 2 || lastFirst >= floor || floor >= faultEvents+1 {
		t.Fatalf("segments %v, last checkpoint %d: the scenario meant a last segment that starts below the "+
			"last checkpoint and holds records past it", firsts, floor)
	}
	return dir, segmentName(lastFirst)
}

// A crash can leave the last segment or the checkpoints file cut at any
// byte. Truncated at every one, the log either reopens to exactly the frames
// complete before the cut and verifies, or, when the cut removes a record the
// last checkpoint covers, refuses to open (RF-20, T-12, T-22).
//
// Seen failing with the checkpoint floor removed from recovery: the log then
// opens below its checkpoint, and Verify reports TruncatedBelowCheckpoint.
func TestTruncatedAtEveryByte(t *testing.T) {
	src, last := crashedLog(t)

	for _, name := range []string{last, checkpointsName} {
		t.Run(name, func(t *testing.T) {
			orig, err := os.ReadFile(filepath.Join(src, name)) // #nosec G304 -- a test's own file
			if err != nil {
				t.Fatal(err)
			}
			// The offset at which each complete frame of a segment ends.
			var ends []int
			if name != checkpointsName {
				r := bytes.NewReader(orig[segmentHeaderLen:])
				end := segmentHeaderLen
				for {
					body, err := readFrame(r, tally.MaxRecordLen)
					if err != nil {
						break
					}
					end += frameOverhead + len(body)
					ends = append(ends, end)
				}
			}
			first, _, _ := parseSegmentName(name)
			ran, opened, refused := 0, 0, 0
			for cut := range len(orig) {
				ran++
				dir := filepath.Join(t.TempDir(), "log")
				if err := os.CopyFS(dir, os.DirFS(src)); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(dir, 0o700); err != nil { // #nosec G302 -- a directory needs x; 0700 is what filestore requires
					t.Fatal(err)
				}
				writeFile(t, filepath.Join(dir, name), orig[:cut])

				s, err := Open(t.Context(), dir, withFS(newFaultFS()))
				if errors.Is(err, errBelowCheckpoint) {
					refused++
					if name == checkpointsName {
						t.Fatalf("cut %d: cutting the checkpoints file refused: %v", cut, err)
					}
					continue
				}
				if err != nil {
					t.Fatalf("cut %d: Open = %v", cut, err)
				}
				opened++
				rep, err := tally.Verify(t.Context(), s, verifiers(t))
				_ = s.Close()
				if err != nil || !rep.OK() {
					t.Fatalf("cut %d: Verify = %v, %+v", cut, err, rep)
				}
				if name != checkpointsName {
					complete := uint64(0)
					for _, e := range ends {
						if e <= cut {
							complete++
						}
					}
					if want := first + complete; rep.Size != want {
						t.Fatalf("cut %d: %d leaves after recovery, want %d", cut, rep.Size, want)
					}
				}
			}
			if ran != len(orig) || ran == 0 || opened == 0 {
				t.Fatalf("ran %d cuts (%d opened, %d refused), want %d", ran, opened, refused, len(orig))
			}
			t.Logf("%d cuts: %d opened, %d refused below the checkpoint", ran, opened, refused)
			if name == last && refused == 0 {
				t.Errorf("no cut of %s was refused; the scenario meant a checkpoint inside it", name)
			}
		})
	}
}
