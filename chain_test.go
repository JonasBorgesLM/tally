package tally

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"testing"
)

// logBuilder writes a framed log from leaf 0, chaining prev_hash and seq the
// way an honest writer does, so a test can break exactly one rule.
type logBuilder struct {
	t      *testing.T
	buf    []byte
	frames []frameSpan
	prev   [32]byte
	seq    uint64
	time   int64
}

// frameSpan locates one frame in the log: [start, start+4) is len,
// [start+4, crc) is the body, [crc, crc+4) is the CRC.
type frameSpan struct{ start, crc int }

func newLog(t *testing.T) *logBuilder {
	t.Helper()
	b := &logBuilder{t: t, time: goldenGenesis().createdAt}
	b.raw(goldenGenesis())
	return b
}

// raw frames r as it is, without touching seq or prev_hash.
func (b *logBuilder) raw(r record) {
	b.t.Helper()
	body, err := encodeFields(r)
	if err != nil {
		b.t.Fatalf("encode: %v", err)
	}
	start := len(b.buf)
	b.buf = appendFrame(b.buf, body)
	b.frames = append(b.frames, frameSpan{start: start, crc: len(b.buf) - 4})
	b.prev = leafHash(body)
}

// entry appends an honest successor, after mutate has had its say.
func (b *logBuilder) entry(mutate func(e *entry)) {
	b.t.Helper()
	b.seq++
	b.time += 10
	e := goldenEntry(b.t)
	e.seq, e.recordedAt, e.prevHash = b.seq, b.time, b.prev
	if mutate != nil {
		mutate(e)
	}
	b.raw(e)
}

func (b *logBuilder) head() *trustedHead {
	return &trustedHead{size: b.seq + 1, hash: b.prev}
}

// smallLog is genesis and three entries covering every actor and payload kind.
func smallLog(t *testing.T) *logBuilder {
	t.Helper()
	ref := SubjectRef{0xAA, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	b := newLog(t)
	b.entry(func(e *entry) { e.actorKind, e.actorID = actorSubject, ref[:] })
	b.entry(func(e *entry) {
		e.actorKind, e.actorID = actorService, []byte("billing-api")
		e.payloadKind, e.payload = payloadPlain, []byte(`{"ip":"10.0.0.1"}`)
	})
	b.entry(func(e *entry) {
		e.outcome = OutcomeDenied
		e.payloadKind, e.subjectRef = payloadSealed, ref[:]
		e.payload = append([]byte{sealFormatV1}, bytes.Repeat([]byte{0x5A}, 40)...)
	})
	return b
}

func recomputeCRC(log []byte, f frameSpan) {
	body := log[f.start+4 : f.crc]
	binary.BigEndian.PutUint32(log[f.crc:], crc32.Checksum(body, crc32.MakeTable(crc32.Castagnoli)))
}

func TestHonestLogVerifies(t *testing.T) {
	b := smallLog(t)
	size, v := verifyFrames(b.buf, b.head())
	if v != nil {
		t.Fatalf("honest log: %v", v)
	}
	if size != 4 {
		t.Fatalf("size = %d, want 4", size)
	}
}

// R-28, T-01. Every body byte of every frame is changed, the CRC is recomputed
// as an attacker would, and verification must fail. Without recomputing, the
// CRC would catch every change and the hash chain would never be tested. The
// trusted head plays the checkpoint, without which the last entry is not
// covered (TestTailIsUncoveredWithoutAHead asserts that limit).
//
// Negative controls: removing the prev_hash comparison in checkChain made this
// fail at genesis's created_at, whose change only the next prev_hash sees;
// removing the head comparison made it fail in the last entry.
func TestEveryBodyByteMutatedWithCRCRecomputed(t *testing.T) {
	b := smallLog(t)
	head := b.head()
	masks := []byte{0x01, 0x80, 0xFF}

	ran, kinds := 0, map[failureKind]int{}
	for fi, f := range b.frames {
		for i := f.start + 4; i < f.crc; i++ {
			for _, m := range masks {
				log := bytes.Clone(b.buf)
				log[i] ^= m
				recomputeCRC(log, f)
				_, v := verifyFrames(log, head)
				ran++
				if v == nil {
					t.Fatalf("frame %d, byte %d ^ %#x: verification passed", fi, i, m)
				}
				if errors.Is(v.err, errFrameCRC) {
					t.Fatalf("frame %d, byte %d: caught by the CRC, so the chain was never tested", fi, i)
				}
				kinds[v.kind]++
			}
		}
	}

	want := 0
	for _, f := range b.frames {
		want += (f.crc - f.start - 4) * len(masks)
	}
	if ran != want || want == 0 {
		t.Fatalf("ran %d mutations, want %d", ran, want)
	}
	// The chain is what caught them, not only the decoder.
	if kinds[kindPrevHashMismatch] == 0 || kinds[kindCheckpointMismatch] == 0 {
		t.Fatalf("no PrevHashMismatch or CheckpointMismatch among %v", kinds)
	}
	t.Logf("%d mutations, by kind: %v", ran, kinds)
}

// The frame layer on its own: a changed len or CRC byte, or a body byte with
// the CRC left alone, is MalformedRecord. This is the case R-28 keeps
// separate, so that the test above cannot pass on the CRC.
//
// Negative control: removing the CRC comparison in readFrame made the CRC and
// unrecomputed body cases fail.
func TestFrameBytesMutatedWithoutRecompute(t *testing.T) {
	b := smallLog(t)
	ran := 0
	for fi, f := range b.frames {
		for i := f.start; i < f.crc+4; i++ {
			log := bytes.Clone(b.buf)
			log[i] ^= 0x01
			_, v := verifyFrames(log, b.head())
			ran++
			if v == nil || v.kind != kindMalformedRecord {
				t.Fatalf("frame %d, byte %d: %v, want MalformedRecord", fi, i, v)
			}
			if inBody := i >= f.start+4 && i < f.crc; inBody && !errors.Is(v.err, errFrameCRC) {
				t.Fatalf("frame %d, body byte %d: %v, want the CRC to catch it", fi, i, v.err)
			}
		}
	}
	if want := len(b.buf); ran != want {
		t.Fatalf("ran %d, want %d (every byte of the log)", ran, want)
	}
}

// T-01's residual, asserted so the docs cannot overclaim: with no checkpoint
// over the head, the last entry can be rewritten undetected, even without the
// key, because nothing follows it.
func TestTailIsUncoveredWithoutAHead(t *testing.T) {
	b := smallLog(t)
	last := b.frames[len(b.frames)-1]
	log := bytes.Clone(b.buf)
	occurredAt := last.start + 4 + 2 + 16 + 8 + 8 // version, type, log_id, seq, recorded_at
	log[occurredAt] ^= 0x01
	recomputeCRC(log, last)

	if _, v := verifyFrames(log, nil); v != nil {
		t.Fatalf("without a head the tail change was caught (%v): the residual changed, update T-01", v)
	}
	if _, v := verifyFrames(log, b.head()); v == nil || v.kind != kindCheckpointMismatch {
		t.Fatalf("with the head: %v, want CheckpointMismatch", v)
	}
}

// Each chain rule of SPEC §2.2, broken alone, with the kind §7.2 names and the
// verified prefix §7 step 4 defines.
//
// Negative controls, each seen failing with its check removed: log_id, the
// seq comparison (both directions), recorded_at, genesis placement, and the
// head comparison.
func TestChainRules(t *testing.T) {
	cases := []struct {
		name     string
		build    func(b *logBuilder)
		head     func(b *logBuilder) *trustedHead
		kind     failureKind
		size     uint64
		wantSeqs uint64
	}{
		{"seq skips one", func(b *logBuilder) {
			b.entry(nil)
			b.seq++
			b.entry(nil)
		}, nil, kindSeqGap, 2, 2},
		{"seq repeats", func(b *logBuilder) {
			b.entry(nil)
			b.seq--
			b.entry(nil)
		}, nil, kindSeqRegression, 2, 2},
		{"recorded_at goes back", func(b *logBuilder) {
			b.entry(nil)
			b.entry(func(e *entry) { e.recordedAt = 1 })
		}, nil, kindTimeRegression, 2, 2},
		{"first entry before genesis created_at", func(b *logBuilder) {
			b.entry(func(e *entry) { e.recordedAt = goldenGenesis().createdAt - 1 })
		}, nil, kindTimeRegression, 1, 1},
		{"prev_hash wrong", func(b *logBuilder) {
			b.entry(nil)
			b.entry(func(e *entry) { e.prevHash[0] ^= 1 })
		}, nil, kindPrevHashMismatch, 2, 2},
		{"log_id of another log", func(b *logBuilder) {
			b.entry(func(e *entry) { e.logID[0] ^= 1 })
		}, nil, kindMalformedRecord, 1, 1},
		{"a second genesis", func(b *logBuilder) {
			b.entry(nil)
			b.raw(goldenGenesis())
		}, nil, kindMalformedRecord, 2, 2},
		{"a record-local rule", func(b *logBuilder) {
			b.entry(func(e *entry) { e.action = "Login" })
		}, nil, kindMalformedRecord, 1, 1},
		{"seq and prev_hash both wrong: seq is listed first", func(b *logBuilder) {
			b.entry(nil)
			b.seq++
			b.entry(func(e *entry) { e.prevHash[0] ^= 1 })
		}, nil, kindSeqGap, 2, 2},
		{"truncated below the head", func(b *logBuilder) {
			b.entry(nil)
			b.entry(nil)
		}, func(b *logBuilder) *trustedHead {
			h := b.head()
			h.size++
			return h
		}, kindTruncatedBelowCheckpoint, 3, 3},
		{"head names a different leaf", func(b *logBuilder) {
			b.entry(nil)
		}, func(b *logBuilder) *trustedHead {
			h := b.head()
			h.hash[0] ^= 1
			return h
		}, kindCheckpointMismatch, 2, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := newLog(t)
			tc.build(b)
			var head *trustedHead
			if tc.head != nil {
				head = tc.head(b)
			}
			size, v := verifyFrames(b.buf, head)
			if v == nil {
				t.Fatalf("passed, want %v", tc.kind)
			}
			if v.kind != tc.kind || size != tc.size || v.seq != tc.wantSeqs {
				t.Fatalf("got %v at seq %d with size %d; want %v at seq %d with size %d",
					v.kind, v.seq, size, tc.kind, tc.wantSeqs, tc.size)
			}
		})
	}
}

func TestFirstRecordMustBeGenesis(t *testing.T) {
	b := newLog(t)
	b.entry(nil)
	withoutGenesis := b.buf[b.frames[1].start:]
	size, v := verifyFrames(withoutGenesis, nil)
	if v == nil || v.kind != kindMalformedRecord || size != 0 {
		t.Fatalf("got size %d, %v; want size 0, MalformedRecord", size, v)
	}
}

// An entry at leaf 0 whose every other field agrees with an empty chain: zero
// log_id, seq 0, zero prev_hash, time 0. Only the genesis rule rejects it, which
// the case above cannot show, since its log_id check fails as well.
//
// Negative control: removing the index == 0 case in checkChain made this fail.
func TestEntryAtLeafZeroIsNotAGenesis(t *testing.T) {
	e := goldenEntry(t)
	e.logID, e.seq, e.prevHash, e.recordedAt = [16]byte{}, 0, [32]byte{}, 0
	body, err := encodeFields(e)
	if err != nil {
		t.Fatal(err)
	}
	size, v := verifyFrames(appendFrame(nil, body), nil)
	if v == nil || v.kind != kindMalformedRecord || size != 0 {
		t.Fatalf("got size %d, %v; want size 0, MalformedRecord", size, v)
	}
}

// Stop at the first violation (ADR-0016): a head beyond a broken record is
// not evaluated, so it is not also reported as a truncation, and the verified
// prefix stops at the break.
func TestStopsAtTheFirstViolation(t *testing.T) {
	b := newLog(t)
	b.entry(nil)
	b.entry(func(e *entry) { e.prevHash[0] ^= 1 })
	b.entry(nil)
	head := b.head()
	head.size += 10

	size, v := verifyFrames(b.buf, head)
	if v == nil || v.kind != kindPrevHashMismatch || size != 2 {
		t.Fatalf("got size %d, %v; want size 2, PrevHashMismatch", size, v)
	}
}

func TestEmptyLogIsNotAVerifiedLog(t *testing.T) {
	if size, v := verifyFrames(nil, nil); v == nil || size != 0 {
		t.Fatalf("empty log: size %d, %v; want a violation", size, v)
	}
}

// A frame length over the SPEC §6 ceiling is refused before the body is read.
//
// Negative control: removing the ceiling check in readFrame made this fail.
func TestFrameLengthCeiling(t *testing.T) {
	log := binary.BigEndian.AppendUint32(nil, maxFrameLen+1)
	_, _, err := readFrame(log)
	if !errors.Is(err, errFrameTooLong) {
		t.Fatalf("readFrame = %v, want errFrameTooLong", err)
	}
}
