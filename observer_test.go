package tally_test

import (
	"context"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/tallytest"
)

// recorder is an Observer that keeps what it is told. Embedding it in another
// type lets a test override one method.
type recorder struct {
	mu      sync.Mutex
	batches []int
}

func (r *recorder) Batch(n int, _ time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.batches = append(r.batches, n)
}
func (*recorder) AnchorPublish(error, uint64)   {}
func (*recorder) DiskSpace(uint64)              {}
func (*recorder) ClockRegression(time.Duration) {}
func (*recorder) Poisoned(error)                {}
func (*recorder) Recovered(int64)               {}

func (r *recorder) total() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, b := range r.batches {
		n += b
	}
	return n
}

// RF-16: the Observer never receives a payload, by the shape of its types. Every
// parameter of every method is one of a few scalar types that cannot carry an
// event's bytes. error is allowed because errors are the store's and the
// anchor's, never an event's; the store contract says so.
//
// Negative control: adding a []byte parameter to Observer.Batch made this fail.
func TestObserverCannotReceiveAPayload(t *testing.T) {
	allowed := map[reflect.Type]bool{
		reflect.TypeFor[int]():           true,
		reflect.TypeFor[int64]():         true,
		reflect.TypeFor[uint64]():        true,
		reflect.TypeFor[time.Duration](): true,
		reflect.TypeFor[error]():         true,
	}
	typ := reflect.TypeFor[tally.Observer]()
	checked := 0
	for i := range typ.NumMethod() {
		m := typ.Method(i)
		for j := range m.Type.NumIn() {
			if in := m.Type.In(j); !allowed[in] {
				t.Errorf("Observer.%s takes a %v, which could carry a payload", m.Name, in)
			}
			checked++
		}
		if m.Type.NumOut() != 0 {
			t.Errorf("Observer.%s returns a value; an observer must not influence the log", m.Name)
		}
	}
	if typ.NumMethod() != 6 || checked == 0 {
		t.Fatalf("checked %d methods and %d parameters", typ.NumMethod(), checked)
	}
}

func TestBatchReportsEveryEntry(t *testing.T) {
	rec := &recorder{}
	l := open(t, tallytest.NewMemStore(), tally.WithObserver(rec))
	for i := range 5 {
		if _, err := l.Append(context.Background(), event("e"+strconv.Itoa(i))); err != nil {
			t.Fatal(err)
		}
	}
	// The Observer is called after the replies, so an Append returning does
	// not mean its event was delivered. Close waits for the writer to stop.
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if got := rec.total(); got != 5 {
		t.Fatalf("Batch reported %d entries, want 5 (the genesis is not an Append)", got)
	}
}

// panicky panics on the first Batch call only, then records normally.
type panicky struct {
	recorder
	once sync.Once
}

func (p *panicky) Batch(n int, d time.Duration) {
	p.once.Do(func() { panic("a bug in the metrics code") })
	p.recorder.Batch(n, d)
}

// ADR-0017: a panicking Observer does not take the process down, does not cost
// the entry its Receipt, does not poison the log, is counted, and is still
// called for later events.
//
// Negative control: removing the recover in the observer wrapper made the test
// binary crash with "a bug in the metrics code".
func TestAPanickingObserverIsRecovered(t *testing.T) {
	p := &panicky{}
	l := open(t, tallytest.NewMemStore(), tally.WithObserver(p))

	r, err := l.Append(context.Background(), event("a"))
	if err != nil || r.Seq != 1 {
		t.Fatalf("Append with a panicking observer = %+v, %v; want a Receipt", r, err)
	}
	// One writer: when the second Append returns, the first batch's Observer
	// call, made after its reply, has finished. Close then waits for the
	// second batch's.
	if _, err := l.Append(context.Background(), event("b")); err != nil {
		t.Fatalf("the log stopped after an observer panic: %v", err)
	}
	if got := l.ObserverPanics(); got != 1 {
		t.Fatalf("ObserverPanics = %d, want 1", got)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if got := p.total(); got != 1 {
		t.Fatalf("after the panic the observer saw %d entries, want 1: it must still be called", got)
	}
}

func TestNoObserverIsFine(t *testing.T) {
	l := open(t, tallytest.NewMemStore(), tally.WithObserver(nil))
	if _, err := l.Append(context.Background(), event("a")); err != nil {
		t.Fatal(err)
	}
	if l.ObserverPanics() != 0 {
		t.Fatal("ObserverPanics without an observer")
	}
}
