package tally

import (
	"context"
	"iter"
	"runtime"
	"testing"
)

// genSource yields a valid chain of n entries after genesis, built as it is
// read, so the log itself takes no memory. Every sampleEvery records it
// collects garbage and keeps the peak of the live heap.
type genSource struct {
	n, sampleEvery int
	peak           uint64
}

func (s *genSource) Checkpoints(context.Context) iter.Seq2[SignedCheckpoint, error] {
	return func(func(SignedCheckpoint, error) bool) {}
}

func (s *genSource) Records(_ context.Context, from uint64) iter.Seq2[Record, error] {
	return func(yield func(Record, error) bool) {
		g := &genesis{logID: [16]byte{7}, createdAt: 1, origin: "example.com/log"}
		body, err := encodeRecord(g)
		if err != nil {
			yield(Record{}, err)
			return
		}
		prev := leafHash(body)
		if from == 0 && !yield(Record{Seq: 0, Body: body}, nil) {
			return
		}
		for i := 1; i <= s.n; i++ {
			e := &entry{logID: g.logID, seq: uint64(i), recordedAt: int64(i) + 1, eventID: []byte("e"),
				actorKind: actorSystem, actorID: []byte{}, action: "user.login", outcome: OutcomeSuccess,
				subjectRef: []byte{}, payload: []byte{}, prevHash: prev}
			body, err := encodeRecord(e)
			if err != nil {
				yield(Record{}, err)
				return
			}
			prev = leafHash(body)
			if !yield(Record{Seq: uint64(i), Body: body}, nil) {
				return
			}
			if i%s.sampleEvery == 0 {
				runtime.GC()
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				s.peak = max(s.peak, m.HeapInuse)
			}
		}
	}
}

// RNF-04: Verify's memory is constant in the number of records. It is
// measured, not assumed: the live heap's peak while verifying 50,000 records
// stays within a fixed margin of the peak for 5,000.
//
// Negative control: keeping every record body in Verify (as a non-streaming
// verifier would) made the 50,000-record peak exceed the margin.
func TestVerifyMemoryIsConstantInLogSize(t *testing.T) {
	measure := func(n uint64) uint64 {
		src := &genSource{n: int(n), sampleEvery: 1000} // #nosec G115 -- n is 5,000 or 50,000.
		rep, err := Verify(context.Background(), src, Verifiers{})
		if err != nil || !rep.OK() || rep.Size != n+1 {
			t.Fatalf("Verify of %d generated records: %+v, %v", n, rep, err)
		}
		return src.peak
	}
	small, large := measure(5_000), measure(50_000)
	// 45,000 more records of about 100 bytes would add over 4 MiB if they
	// were kept; 1 MiB of margin absorbs the runtime's own variation.
	const margin = 1 << 20
	if large > small+margin {
		t.Fatalf("peak live heap %d bytes for 50,000 records against %d for 5,000: memory grows with the log", large, small)
	}
	t.Logf("peak live heap: %d bytes for 5,000 records, %d for 50,000", small, large)
}
