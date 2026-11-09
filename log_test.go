package tally_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/tallytest"
)

// nameSigner is a Signer that only has a name: #17 needs no signature yet.
type nameSigner string

func (s nameSigner) Name() string                  { return string(s) }
func (nameSigner) KeyHash() uint32                 { return 0 }
func (nameSigner) Sign(msg []byte) ([]byte, error) { return nil, errors.New("not a real signer") }

const testOrigin = nameSigner("example.com/log")

var errDisk = errors.New("disk on fire")

func event(id string) tally.Event {
	return tally.Event{
		ID:         tally.EventID(id),
		OccurredAt: time.Unix(1_700_000_000, 0),
		Actor:      tally.System(),
		Action:     "user.login",
		Outcome:    tally.OutcomeSuccess,
	}
}

func open(t *testing.T, s tally.Store, opts ...tally.Option) *tally.Log {
	t.Helper()
	l, err := tally.Open(context.Background(), s, testOrigin, opts...)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

// keepOpen hides Close from the Log, so that a test can reopen the same store.
type keepOpen struct{ tally.Store }

func (keepOpen) Close() error { return nil }

func bodies(t *testing.T, s tally.Source) [][]byte {
	t.Helper()
	var out [][]byte
	for r, err := range s.Records(context.Background(), 0) {
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, r.Body)
	}
	return out
}

// leaf is SPEC §2.3, computed here rather than by the package under test.
func leaf(body []byte) [32]byte {
	return sha256.Sum256(append([]byte{0x00}, body...))
}

// verifyStored checks that the stored log is a valid chain by reopening it:
// Open reads it back by the verifier's rules and refuses a broken one. It also
// checks that the last stored leaf is want, and returns the number of records.
func verifyStored(t *testing.T, mem *tallytest.MemStore, want [32]byte) int {
	t.Helper()
	all := bodies(t, mem)
	if got := leaf(all[len(all)-1]); got != want {
		t.Fatalf("the last stored leaf is %x, want %x", got, want)
	}
	l, err := tally.Open(context.Background(), keepOpen{mem}, testOrigin)
	if err != nil {
		t.Fatalf("the stored log does not verify: %v", err)
	}
	_ = l.Close()
	return len(all)
}

func TestOpenWritesGenesis(t *testing.T) {
	mem := tallytest.NewMemStore()
	id := bytes.Repeat([]byte{0xA5}, 16)
	l := open(t, mem, tally.WithRand(bytes.NewReader(id)))

	if mem.Len() != 1 {
		t.Fatalf("store holds %d records after Open, want the genesis", mem.Len())
	}
	if got := l.ID(); !bytes.Equal(got[:], id) {
		t.Fatalf("ID = %x, want the bytes read from the random source", got)
	}
	g := bodies(t, mem)[0]
	if g[0] != 1 || g[1] != 0x01 || !bytes.Equal(g[2:18], id) || !bytes.HasSuffix(g, []byte(testOrigin)) {
		t.Fatalf("genesis = %x: want version 1, type GENESIS, the log_id and origin %q", g, testOrigin)
	}
}

func TestOpenRefusesAnOriginThatIsNotAKeyName(t *testing.T) {
	_, err := tally.Open(context.Background(), tallytest.NewMemStore(), nameSigner("has space"))
	var ve *tally.ValidationError
	if !errors.As(err, &ve) || ve.Field != "origin" {
		t.Fatalf("Open = %v, want a ValidationError on origin", err)
	}
}

func TestAppendStoresTheEntry(t *testing.T) {
	mem := tallytest.NewMemStore()
	l := open(t, mem)
	r, err := l.Append(context.Background(), event("e1"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Seq != 1 || r.Duplicate {
		t.Fatalf("Receipt = %+v, want seq 1", r)
	}
	if mem.Len() != 2 {
		t.Fatalf("store holds %d records, want 2", mem.Len())
	}
	if got := leaf(bodies(t, mem)[1]); got != r.LeafHash {
		t.Fatalf("Receipt.LeafHash %x is not the stored entry's %x", r.LeafHash, got)
	}
}

func TestAppendValidatesOnTheCallersGoroutine(t *testing.T) {
	mem := tallytest.NewMemStore()
	faulty := tallytest.NewFaultyStore(mem)
	l := open(t, faulty)
	ev := event("e1")
	ev.Resource = "user/joao@example.com"
	_, err := l.Append(context.Background(), ev)
	var ve *tally.ValidationError
	if !errors.As(err, &ve) || ve.Field != "resource" {
		t.Fatalf("Append = %v, want a ValidationError on resource", err)
	}
	if faulty.AppendCalls() != 1 {
		t.Fatalf("the store was called for an invalid event (%d calls)", faulty.AppendCalls())
	}
}

// RF-01, the invariant this library exists for: no Receipt before the batch is
// durable. The store holds the batch until the test releases it, and the
// receipt arrives only after.
//
// This test cannot prove the negative on its own: a reply sent too early may
// not have been read when the check runs, so the early-reply mutation passed
// here. TestAFailedBatchNeverYieldsAReceipt is the deterministic guard.
func TestNoReceiptBeforeTheBatchIsDurable(t *testing.T) {
	mem := tallytest.NewMemStore()
	entered, release := make(chan struct{}), make(chan struct{})
	// Call 1 is the genesis, written by Open.
	l := open(t, tallytest.NewFaultyStore(mem, tallytest.BlockAppend(2, entered, release)))

	type result struct {
		r   tally.Receipt
		err error
	}
	done := make(chan result, 1)
	go func() {
		r, err := l.Append(context.Background(), event("e1"))
		done <- result{r, err}
	}()

	<-entered
	select {
	case res := <-done:
		t.Fatalf("Append returned before the batch was durable: %+v", res)
	default:
	}
	if mem.Len() != 1 {
		t.Fatalf("store holds %d records while the batch is held, want 1", mem.Len())
	}
	close(release)
	res := <-done
	if res.err != nil || res.r.Seq != 1 || mem.Len() != 2 {
		t.Fatalf("after release: %+v, store %d records", res, mem.Len())
	}
}

// seq is unique and gap-free under concurrent Append, and the stored log is a
// valid chain whose last leaf is a receipt's (run under -race).
func TestConcurrentAppendsAreGapFree(t *testing.T) {
	mem := tallytest.NewMemStore()
	l := open(t, mem, tally.WithMaxBatch(8))
	const goroutines, each = 32, 25

	var (
		mu       sync.Mutex
		receipts = map[uint64]tally.Receipt{}
		wg       sync.WaitGroup
	)
	for g := range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range each {
				r, err := l.Append(context.Background(), event(strconv.Itoa(g)+"-"+strconv.Itoa(i)))
				if err != nil {
					t.Errorf("Append: %v", err)
					return
				}
				mu.Lock()
				if _, dup := receipts[r.Seq]; dup {
					t.Errorf("seq %d issued twice", r.Seq)
				}
				receipts[r.Seq] = r
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	const n = goroutines * each
	if len(receipts) != n {
		t.Fatalf("%d receipts, want %d", len(receipts), n)
	}
	for seq := uint64(1); seq <= n; seq++ {
		if _, ok := receipts[seq]; !ok {
			t.Fatalf("seq %d missing: the sequence has a gap", seq)
		}
	}
	if size := verifyStored(t, mem, receipts[n].LeafHash); size != n+1 {
		t.Fatalf("the stored log holds %d records, want %d", size, n+1)
	}
}

// Reopening continues the chain: seq and prev_hash follow the stored head.
func TestReopenContinuesTheChain(t *testing.T) {
	mem := tallytest.NewMemStore()
	l1, err := tally.Open(context.Background(), keepOpen{mem}, testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b"} {
		if _, aerr := l1.Append(context.Background(), event(id)); aerr != nil {
			t.Fatal(aerr)
		}
	}
	id := l1.ID()
	if cerr := l1.Close(); cerr != nil {
		t.Fatal(cerr)
	}

	l2 := open(t, mem)
	if l2.ID() != id {
		t.Fatalf("reopened log has ID %x, want %x", l2.ID(), id)
	}
	r, err := l2.Append(context.Background(), event("c"))
	if err != nil || r.Seq != 3 {
		t.Fatalf("Append after reopen = %+v, %v; want seq 3", r, err)
	}
	if size := verifyStored(t, mem, r.LeafHash); size != 4 {
		t.Fatalf("after reopen the store holds %d records, want 4", size)
	}
}

func TestReopenRefusesAnotherOrigin(t *testing.T) {
	mem := tallytest.NewMemStore()
	l, err := tally.Open(context.Background(), keepOpen{mem}, testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	if _, err := tally.Open(context.Background(), mem, nameSigner("other.example/log")); err == nil {
		t.Fatal("Open accepted a signer whose name is not the log's origin")
	}
}

// A log whose stored chain is broken does not open: the writer would extend a
// history no verifier accepts.
//
// Negative control: skipping the chain check in Open made this fail.
func TestReopenRefusesABrokenChain(t *testing.T) {
	mem := tallytest.NewMemStore()
	l, err := tally.Open(context.Background(), keepOpen{mem}, testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(context.Background(), event("a")); err != nil {
		t.Fatal(err)
	}
	_ = l.Close()

	broken := tallytest.NewMemStore()
	recs := bodies(t, mem)
	recs[1] = bytes.Clone(recs[1])
	recs[1][len(recs[1])-1] ^= 1 // the entry's prev_hash
	for i, b := range recs {
		if err := broken.AppendBatch(context.Background(), []tally.Record{{Seq: uint64(i), Body: b}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tally.Open(context.Background(), broken, testOrigin); err == nil {
		t.Fatal("Open accepted a store whose chain is broken")
	}
}

// Any store error poisons the log: the waiters fail, later Appends return
// ErrPoisoned, and the store is never called again (ADR-0009). The full suite
// and the Observer event are #20.
//
// Negative control: letting the writer call AppendBatch while poisoned made
// this fail (AppendCalls went to 3).
func TestAStoreErrorPoisons(t *testing.T) {
	faulty := tallytest.NewFaultyStore(tallytest.NewMemStore(), tallytest.FailAppend(2, errDisk))
	l := open(t, faulty)
	_, err := l.Append(context.Background(), event("a"))
	if !errors.Is(err, tally.ErrPoisoned) || !errors.Is(err, errDisk) {
		t.Fatalf("the failing Append = %v, want ErrPoisoned wrapping the store error", err)
	}
	if _, err := l.Append(context.Background(), event("b")); !errors.Is(err, tally.ErrPoisoned) {
		t.Fatalf("a later Append = %v, want ErrPoisoned", err)
	}
	if got := faulty.AppendCalls(); got != 2 {
		t.Fatalf("AppendCalls = %d, want 2: the store was called after poisoning", got)
	}
}

func TestCloseIsIdempotentAndFinal(t *testing.T) {
	mem := tallytest.NewMemStore()
	l, err := tally.Open(context.Background(), mem, testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := l.Append(context.Background(), event("a")); !errors.Is(err, tally.ErrClosed) {
		t.Fatalf("Append after Close = %v, want ErrClosed", err)
	}
	if err := mem.AppendBatch(context.Background(), nil); !errors.Is(err, tally.ErrClosed) {
		t.Fatal("Close did not close the store it owns")
	}
}

// Close racing with Appends: every Append returns, with a Receipt or
// ErrClosed, and none hangs. An Append that lands in the queue after the
// writer has stopped must still be answered.
//
// A stress test, and statistical: the race it guards against cannot be forced
// without hooks. The guarantee is by construction (see Log.senders): an Append
// enqueues only as a registered sender, and Close waits for registered senders
// before stopping the writer. 3000 rounds did not provoke a hang in the
// earlier design either, so this test alone would not have caught it.
func TestCloseRacingAppendsAnswersEveryCaller(t *testing.T) {
	for round := range 200 {
		mem := tallytest.NewMemStore()
		l, err := tally.Open(context.Background(), mem, testOrigin, tally.WithMaxBatch(2), tally.WithMaxDelay(0))
		if err != nil {
			t.Fatal(err)
		}
		const callers = 16
		results := make(chan error, callers)
		for i := range callers {
			go func() {
				_, err := l.Append(context.Background(), event("e"+strconv.Itoa(i)))
				results <- err
			}()
		}
		if err := l.Close(); err != nil {
			t.Fatal(err)
		}
		for range callers {
			select {
			case err := <-results:
				if err != nil && !errors.Is(err, tally.ErrClosed) {
					t.Fatalf("round %d: Append = %v, want a Receipt or ErrClosed", round, err)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("round %d: an Append was never answered after Close", round)
			}
		}
	}
}

// RF-01, deterministically: if the writer replied before AppendBatch returned,
// a batch that then fails would already have handed out a Receipt for an
// entry that is not durable. A torn batch is the sharpest case: the record IS
// in the store, and still no Receipt may be issued, because the store said the
// write failed.
//
// Negative control: replying to the waiters before calling AppendBatch made
// every case fail ("Append = <nil>").
func TestAFailedBatchNeverYieldsAReceipt(t *testing.T) {
	for name, fault := range map[string]tallytest.Fault{
		"failed": tallytest.FailAppend(2, errDisk),
		"torn":   tallytest.TearAppend(2, 1, errDisk),
	} {
		t.Run(name, func(t *testing.T) {
			l := open(t, tallytest.NewFaultyStore(tallytest.NewMemStore(), fault))
			r, err := l.Append(context.Background(), event("e1"))
			if err == nil {
				t.Fatalf("Append = <nil> with Receipt %+v for a batch the store failed", r)
			}
			if r != (tally.Receipt{}) {
				t.Fatalf("Append returned a non-zero Receipt %+v with its error", r)
			}
		})
	}
}
