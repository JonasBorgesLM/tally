package filestore

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/internal/note"
	"github.com/JonasBorgesLM/tally/tallytest"
)

// Benchmarks for RNF-03's targets (#49), over the file store on whatever disk
// the temporary directory is on. The results recorded in REQUIREMENTS.md name
// the hardware, the filesystem and the Go version; a number without them says
// nothing, since an fsync costs what the disk makes it cost.
//
//	go test ./filestore -run '^$' -bench . -count 6 | tee new.txt
//
// TMPDIR picks the disk.

// benchEntries is the size of the log that BenchmarkReopen and
// BenchmarkVerify read: large enough that per-entry work dominates opening
// files, small enough to write in seconds.
const benchEntries = 100_000

// batchCounter counts AppendBatch calls: each is one fsync of the segment,
// so entries per call is the batch the group commit achieved (ADR-0008).
type batchCounter struct {
	*Store
	batches atomic.Int64
}

func (c *batchCounter) AppendBatch(ctx context.Context, recs []tally.Record) error {
	c.batches.Add(1)
	return c.Store.AppendBatch(ctx, recs)
}

func benchSigner(b *testing.B) tally.Signer {
	b.Helper()
	s, err := note.NewSigner(tallytest.TestSignerKey)
	if err != nil {
		b.Fatal(err)
	}
	return s
}

func benchEvent(id string) tally.Event {
	return tally.Event{ID: tally.EventID(id), OccurredAt: time.Unix(1_700_000_000, 0), Actor: tally.System(),
		Action: "invoice.read", Resource: "invoice/" + id, Outcome: tally.OutcomeSuccess}
}

// appendAll appends n events from writers goroutines and returns each
// Append's latency, in no particular order.
func appendAll(b *testing.B, l *tally.Log, n, writers int) []time.Duration {
	b.Helper()
	var next atomic.Int64
	lat := make([][]time.Duration, writers)
	errs := make(chan error, writers)
	var wg sync.WaitGroup
	for w := range writers {
		wg.Go(func() {
			for {
				i := next.Add(1) - 1
				if i >= int64(n) {
					return
				}
				start := time.Now()
				if _, err := l.Append(context.Background(), benchEvent(fmt.Sprint(i))); err != nil {
					errs <- err
					return
				}
				lat[w] = append(lat[w], time.Since(start))
			}
		})
	}
	wg.Wait()
	close(errs)
	if err := <-errs; err != nil {
		b.Fatal(err)
	}
	return slices.Concat(lat...)
}

// percentile is the q-th quantile of d, which it sorts.
func percentile(d []time.Duration, q float64) time.Duration {
	if len(d) == 0 {
		return 0
	}
	slices.Sort(d)
	return d[min(len(d)-1, int(float64(len(d))*q))]
}

// Durable appends, each Append returning only once its entry is fsynced
// (RF-01), from a number of concurrent callers, under the default MaxBatch
// (256) and checkpoint policy. One caller is the worst case: one fsync per
// entry, and with the default MaxDelay, 2 ms more spent waiting for entries
// that do not come; maxdelay=0 shows that floor without the wait. With more
// callers, the group commit shares each fsync among the entries queued
// meanwhile.
//
// Reported: entries/s (RNF-03: >= 10k batched), the p99 latency of one
// Append, and entries/batch, the batch achieved: one segment fsync each.
func BenchmarkAppend(b *testing.B) {
	for _, c := range []struct {
		writers  int
		maxDelay time.Duration
	}{{1, 0}, {1, 2 * time.Millisecond}, {16, 2 * time.Millisecond}, {256, 2 * time.Millisecond}} {
		writers := c.writers
		b.Run(fmt.Sprintf("writers=%d/maxdelay=%v", c.writers, c.maxDelay), func(b *testing.B) {
			st, err := Open(b.Context(), filepath.Join(b.TempDir(), "log"))
			if err != nil {
				b.Fatal(err)
			}
			cs := &batchCounter{Store: st}
			l, err := tally.Open(b.Context(), cs, benchSigner(b), tally.WithMaxDelay(c.maxDelay))
			if err != nil {
				b.Fatal(err)
			}
			defer func() { _ = l.Close() }()
			cs.batches.Store(0) // not the genesis

			b.ResetTimer()
			start := time.Now()
			lat := appendAll(b, l, b.N, writers)
			elapsed := time.Since(start)
			b.StopTimer()

			b.ReportMetric(float64(b.N)/elapsed.Seconds(), "entries/s")
			b.ReportMetric(float64(percentile(lat, 0.99).Microseconds())/1000, "p99-ms")
			b.ReportMetric(float64(b.N)/float64(max(cs.batches.Load(), 1)), "entries/batch")
		})
	}
}

// benchLog writes a log of benchEntries entries, with the default checkpoint
// policy, and returns its directory. The log is closed cleanly.
func benchLog(b *testing.B) string {
	b.Helper()
	dir := filepath.Join(b.TempDir(), "log")
	st, err := Open(b.Context(), dir)
	if err != nil {
		b.Fatal(err)
	}
	l, err := tally.Open(b.Context(), st, benchSigner(b))
	if err != nil {
		b.Fatal(err)
	}
	appendAll(b, l, benchEntries, 512)
	if err := l.Close(); err != nil {
		b.Fatal(err)
	}
	return dir
}

// lastSegment is the path of the segment with the highest first seq.
func lastSegment(b *testing.B, dir string) string {
	b.Helper()
	names, err := filepath.Glob(filepath.Join(dir, "*"+segmentExt))
	if err != nil || len(names) == 0 {
		b.Fatalf("no segments in %s: %v", dir, err)
	}
	slices.Sort(names) // fixed-width hex first seqs sort as numbers
	return names[len(names)-1]
}

// Reopening after a crash: the file store recovers a torn tail (SPEC §3.3),
// quarantining it, and tally.Open reads and rehashes every stored entry to
// rebuild the head and the idempotency window. That read is O(entries), so
// the time to restart grows with the log until a prune (#35).
//
// Reported: entries/s, the log's size over the time to reopen.
func BenchmarkReopen(b *testing.B) {
	dir := benchLog(b)
	seg := lastSegment(b, dir)
	torn := []byte{0x00, 0x00, 0x01} // part of a frame header: what a crash mid-write leaves
	signer := benchSigner(b)

	for b.Loop() {
		b.StopTimer()
		f, err := os.OpenFile(seg, os.O_WRONLY|os.O_APPEND, 0) // #nosec G304 -- a benchmark's own file
		if err != nil {
			b.Fatal(err)
		}
		if _, err = f.Write(torn); err != nil {
			b.Fatal(err)
		}
		if err = f.Close(); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()

		st, err := Open(b.Context(), dir)
		if err != nil {
			b.Fatal(err)
		}
		l, err := tally.Open(b.Context(), st, signer)
		if err != nil {
			b.Fatal(err)
		}

		b.StopTimer()
		if err = l.Close(); err != nil {
			b.Fatal(err)
		}
		q, _ := filepath.Glob(filepath.Join(dir, "quarantine-*"))
		if len(q) != 1 {
			b.Fatalf("want the torn tail quarantined once; quarantine files %q", q)
		}
		if err = os.Remove(q[0]); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
	}
	b.ReportMetric(float64(benchEntries)*float64(b.N)/b.Elapsed().Seconds(), "entries/s")
}

// Verifying a stored log through OpenReader, as tally verify does: reading
// the segments, checking every frame and decoding, re-encoding and chaining
// every record, and every checkpoint's signature. Verify runs on one
// goroutine, so the rate is per core. The files are in the page cache after
// the first iteration: this measures the verifier, not the disk.
//
// Reported: entries/s (RNF-03: >= 100k per core).
func BenchmarkVerify(b *testing.B) {
	dir := benchLog(b)
	keys, err := tally.NewVerifiers(tallytest.TestVerifierKey)
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		r, err := OpenReader(dir)
		if err != nil {
			b.Fatal(err)
		}
		rep, err := tally.Verify(b.Context(), r, keys, tally.WithRequireFullyAttested())
		if err != nil || !rep.OK() || rep.Size != benchEntries+1 {
			b.Fatalf("Verify = %v, %+v", err, rep)
		}
	}
	b.ReportMetric(float64(benchEntries)*float64(b.N)/b.Elapsed().Seconds(), "entries/s")
}
