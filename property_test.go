package tally

import (
	"bytes"
	"math/rand/v2"
	"reflect"
	"testing"
)

// gen produces random records that satisfy every record-local rule of SPEC §2,
// from a fixed seed so a failure is reproducible.
type gen struct{ r *rand.Rand }

// A fixed seed, so that a failure reproduces: this is test data, not a secret.
func newGen() gen { return gen{rand.New(rand.NewPCG(14, 2026))} } // #nosec G404 -- reproducible test data.

// small returns a uniform value in [0, n), for n of at most 256.
func (g gen) small(n uint) uint8 {
	return uint8(g.r.UintN(n)) // #nosec G115 -- below n, which is at most 256.
}

func (g gen) bytes(minLen, maxLen int) []byte {
	b := make([]byte, minLen+g.r.IntN(maxLen-minLen+1))
	for i := range b {
		b[i] = g.small(256)
	}
	return b
}

// text draws from an alphabet with multi-byte characters, so that byte length
// and character count differ, but never a forbidden code point or '@'.
func (g gen) text(maxBytes int) string {
	alphabet := []string{"a", "z", "0", "9", "-", "_", ".", "/", ":", "ç", "ã", "日", "本", "€"}
	var s []byte
	for {
		c := alphabet[g.r.IntN(len(alphabet))]
		if len(s)+len(c) > maxBytes || g.r.IntN(12) == 0 {
			return string(s)
		}
		s = append(s, c...)
	}
}

func (g gen) action() string {
	seg := func() string {
		n := g.r.IntN(8)
		b := make([]byte, 1, 1+n)
		b[0] = 'a' + g.small(26)
		for range n {
			b = append(b, "abcxyz0189_"[g.r.IntN(11)])
		}
		return string(b)
	}
	s := seg()
	for range 1 + g.r.IntN(3) {
		s += "." + seg()
	}
	return s
}

func (g gen) entry() *entry {
	e := &entry{
		seq:        g.r.Uint64(),
		recordedAt: int64(g.r.Uint64()), // #nosec G115 -- any bit pattern is a valid int64 here.
		occurredAt: int64(g.r.Uint64()), // #nosec G115 -- as above.
		eventID:    g.bytes(1, maxEventID),
		action:     g.action(),
		resource:   g.text(maxResource),
		outcome:    Outcome(1 + g.small(4)),
		subjectRef: []byte{},
		payload:    []byte{},
	}
	copy(e.logID[:], g.bytes(16, 16))
	copy(e.prevHash[:], g.bytes(32, 32))

	switch e.actorKind = actorKind(1 + g.small(3)); e.actorKind {
	case actorSubject:
		e.actorID = g.bytes(16, 16)
	case actorService:
		e.actorID = []byte("svc-" + g.text(maxActorID-4))
	case actorSystem:
		e.actorID = []byte{}
	}
	switch e.payloadKind = payloadKind(g.small(3)); e.payloadKind {
	case payloadNone:
	case payloadPlain:
		e.payload = g.bytes(1, 512)
	case payloadSealed:
		e.subjectRef = g.bytes(16, 16)
		e.payload = append([]byte{sealFormatV1}, g.bytes(sealedMin-1, 512)...)
	}
	return e
}

func (g gen) genesis() *genesis {
	gn := &genesis{createdAt: int64(g.r.Uint64()), origin: "o-" + g.text(maxOrigin-2)} // #nosec G115 -- any int64.
	copy(gn.logID[:], g.bytes(16, 16))
	return gn
}

// decode(encode(r)) == r for every valid record. Encoding is therefore
// injective as well: if encode(a) == encode(b), then a == decode(encode(a)) ==
// decode(encode(b)) == b. TestBoundaryShiftsEncodeDifferently is a concrete
// witness of that for the case a length prefix exists to prevent.
//
// Negative control: making decodeFields read occurred_at before recorded_at
// made this fail.
func TestDecodeAfterEncodeIsIdentity(t *testing.T) {
	g := newGen()
	const n = 3000
	ran := 0
	for i := range n {
		var r record = g.entry()
		if i%10 == 0 {
			r = g.genesis()
		}
		b, err := encodeRecord(r)
		if err != nil {
			t.Fatalf("case %d: a generated record did not encode: %v\n%#v", i, err, r)
		}
		got, err := decodeRecord(b)
		if err != nil {
			t.Fatalf("case %d: decode: %v", i, err)
		}
		if !reflect.DeepEqual(got, r) {
			t.Fatalf("case %d: decode(encode(r)) != r\n got %#v\nwant %#v", i, got, r)
		}
		ran++
	}
	if ran != n {
		t.Fatalf("ran %d, want %d", ran, n)
	}
}

// Without length prefixes, moving bytes from the end of one variable field to
// the start of the next would give the same encoding: the ambiguity RS-19
// rules out for the AAD and SPEC §1 for every record.
func TestBoundaryShiftsEncodeDifferently(t *testing.T) {
	type pair struct {
		name string
		a, b func(e *entry)
	}
	pairs := []pair{
		{"event_id | actor_id",
			func(e *entry) { e.eventID, e.actorKind, e.actorID = []byte("ab"), actorService, []byte("c") },
			func(e *entry) { e.eventID, e.actorKind, e.actorID = []byte("a"), actorService, []byte("bc") }},
		{"action | resource",
			func(e *entry) { e.action, e.resource = "a.bc", "d" },
			func(e *entry) { e.action, e.resource = "a.b", "cd" }},
		{"subject_ref | payload",
			func(e *entry) {
				e.payloadKind, e.subjectRef = payloadSealed, bytes.Repeat([]byte{1}, 16)
				e.payload = append([]byte{sealFormatV1}, make([]byte, 29)...)
			},
			func(e *entry) {
				e.payloadKind, e.subjectRef = payloadSealed, bytes.Repeat([]byte{1}, 16)
				e.payload = append([]byte{sealFormatV1}, make([]byte, 28)...)
			}},
	}
	for _, p := range pairs {
		t.Run(p.name, func(t *testing.T) {
			ea, eb := goldenEntry(t), goldenEntry(t)
			p.a(ea)
			p.b(eb)
			ba, err := encodeRecord(ea)
			if err != nil {
				t.Fatal(err)
			}
			bb, err := encodeRecord(eb)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(ba, bb) {
				t.Fatalf("two different records share an encoding: %x", ba)
			}
		})
	}
}

// Random bytes almost never decode, and when they do they must re-encode to
// themselves: decoding is the inverse of encoding on its whole domain, not only
// on what the encoder produced. A cheap stand-in until the fuzz target (#16).
func TestRandomBytesNeverDecodeNonCanonically(t *testing.T) {
	g := newGen()
	const n = 20000
	ran, decoded := 0, 0
	for range n {
		var b []byte
		if g.r.IntN(2) == 0 {
			// A valid record with a few bytes changed, which reaches past the
			// first field checks far more often than noise does.
			valid, _ := encodeRecord(g.entry())
			b = valid
			for range 1 + g.r.IntN(3) {
				b[g.r.IntN(len(b))] ^= 1 + g.small(255)
			}
		} else {
			b = g.bytes(0, 128)
		}
		ran++
		r, err := decodeRecord(b)
		if err != nil {
			continue
		}
		decoded++
		again, err := encodeRecord(r)
		if err != nil || !bytes.Equal(again, b) {
			t.Fatalf("decoded %x but it re-encodes to %x (%v)", b, again, err)
		}
	}
	if ran != n {
		t.Fatalf("ran %d, want %d", ran, n)
	}
	t.Logf("%d inputs, %d decoded", ran, decoded)
}
