package wire

import (
	"bytes"
	"errors"
	"math"
	"testing"
)

func encode(t *testing.T, f func(e *Encoder)) []byte {
	t.Helper()
	var e Encoder
	f(&e)
	b, err := e.Result()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return b
}

func TestRoundTrip(t *testing.T) {
	id := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	b := encode(t, func(e *Encoder) {
		e.Uint8(0xAB)
		e.Uint32(0xDEADBEEF)
		e.Uint64(math.MaxUint64)
		e.Int64(math.MinInt64)
		e.Fixed(id[:])
		e.Bytes([]byte{}, 4)
		e.Bytes([]byte{0xFF, 0x00}, 4)
		e.String("ação", 8)
	})

	d := NewDecoder(b)
	if got := d.Uint8(); got != 0xAB {
		t.Errorf("Uint8 = %#x", got)
	}
	if got := d.Uint32(); got != 0xDEADBEEF {
		t.Errorf("Uint32 = %#x", got)
	}
	if got := d.Uint64(); got != math.MaxUint64 {
		t.Errorf("Uint64 = %#x", got)
	}
	if got := d.Int64(); got != math.MinInt64 {
		t.Errorf("Int64 = %d", got)
	}
	var gotID [16]byte
	d.Fixed(gotID[:])
	if gotID != id {
		t.Errorf("Fixed = %x", gotID)
	}
	if got := d.Bytes(4); got == nil || len(got) != 0 {
		t.Errorf("empty Bytes = %#v, want non-nil empty", got)
	}
	if got := d.Bytes(4); !bytes.Equal(got, []byte{0xFF, 0x00}) {
		t.Errorf("Bytes = %x", got)
	}
	if got := d.String(8); got != "ação" {
		t.Errorf("String = %q", got)
	}
	if err := d.Finish(); err != nil {
		t.Fatalf("Finish: %v", err)
	}
}

// The layout is SPEC §1's, byte for byte: fixed width, big-endian, a uint32
// length before bytes. A round trip alone would pass a little-endian codec.
func TestLayoutIsBigEndianFixedWidth(t *testing.T) {
	b := encode(t, func(e *Encoder) {
		e.Uint8(0x01)
		e.Uint32(0x02030405)
		e.Uint64(0x060708090A0B0C0D)
		e.Int64(-2)
		e.Bytes([]byte("hi"), 2)
		e.String("", 0)
	})
	want := []byte{
		0x01,
		0x02, 0x03, 0x04, 0x05,
		0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
		0x00, 0x00, 0x00, 0x02, 'h', 'i',
		0x00, 0x00, 0x00, 0x00,
	}
	if !bytes.Equal(b, want) {
		t.Fatalf("encoding\n got %x\nwant %x", b, want)
	}
}

// The decoder copies: a record must not alias the frame buffer it came from,
// which the caller reuses for the next frame.
func TestBytesDoesNotAliasInput(t *testing.T) {
	in := encode(t, func(e *Encoder) { e.Bytes([]byte("abc"), 3) })
	d := NewDecoder(in)
	got := d.Bytes(3)
	in[len(in)-1] = 'X'
	if string(got) != "abc" {
		t.Fatalf("Bytes aliases its input: %q", got)
	}
}

// Negative control: removing the trailing-bytes check in Finish made this fail
// (Finish returned nil).
func TestFinishRejectsTrailingBytes(t *testing.T) {
	b := encode(t, func(e *Encoder) { e.Uint32(7) })
	b = append(b, 0x00)

	d := NewDecoder(b)
	if got := d.Uint32(); got != 7 {
		t.Fatalf("Uint32 = %d", got)
	}
	if err := d.Finish(); !errors.Is(err, ErrTrailingBytes) {
		t.Fatalf("Finish = %v, want ErrTrailingBytes", err)
	}
}

// Negative control: removing the utf8.Valid check in Decoder.String made this
// fail (the invalid string was returned with a nil error).
func TestStringRejectsInvalidUTF8(t *testing.T) {
	invalid := [][]byte{
		{0xFF},             // never valid
		{0xC0, 0x80},       // overlong NUL
		{0xED, 0xA0, 0x80}, // surrogate U+D800
		{0xE2, 0x82},       // truncated sequence
	}
	for _, s := range invalid {
		in := encode(t, func(e *Encoder) { e.Bytes(s, 8) })
		d := NewDecoder(in)
		if got := d.String(8); got != "" {
			t.Errorf("%x: String = %q, want empty on error", s, got)
		}
		if err := d.Finish(); !errors.Is(err, ErrInvalidUTF8) {
			t.Errorf("%x: Finish = %v, want ErrInvalidUTF8", s, err)
		}
	}
}

// The encoder must not produce what the decoder rejects: a writer that could
// would commit a record no verifier accepts.
func TestEncoderRejectsInvalidUTF8(t *testing.T) {
	var e Encoder
	e.String("\xff", 8)
	if _, err := e.Result(); !errors.Is(err, ErrInvalidUTF8) {
		t.Fatalf("Result = %v, want ErrInvalidUTF8", err)
	}
}

// Negative control: removing the limit check in Decoder.Bytes made this fail
// (the over-limit field was returned).
func TestBytesRejectsOverLimit(t *testing.T) {
	for _, tc := range []struct {
		name  string
		read  func(d *Decoder)
		limit uint32
	}{
		{"bytes", func(d *Decoder) { d.Bytes(3) }, 3},
		{"string", func(d *Decoder) { d.String(3) }, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// One byte over the limit, and the bytes are present, so only the
			// limit can reject it.
			in := encode(t, func(e *Encoder) { e.Bytes([]byte("abcd"), 4) })
			d := NewDecoder(in)
			tc.read(&d)
			if err := d.Finish(); !errors.Is(err, ErrTooLong) {
				t.Fatalf("Finish = %v, want ErrTooLong", err)
			}
		})
	}
}

// The limit is inclusive: SPEC §6 says a verifier MUST accept the ceiling.
func TestBytesAcceptsExactlyTheLimit(t *testing.T) {
	in := encode(t, func(e *Encoder) { e.Bytes([]byte("abc"), 3) })
	d := NewDecoder(in)
	if got := d.Bytes(3); string(got) != "abc" {
		t.Fatalf("Bytes = %q", got)
	}
	if err := d.Finish(); err != nil {
		t.Fatalf("Finish: %v", err)
	}
}

func TestEncoderRejectsOverLimit(t *testing.T) {
	var e Encoder
	e.Bytes([]byte("abcd"), 3)
	if _, err := e.Result(); !errors.Is(err, ErrTooLong) {
		t.Fatalf("Result = %v, want ErrTooLong", err)
	}
}

// RS-05. A length prefix of 0xFFFFFFFF with no bytes behind it must be refused
// without allocating: a decoder that trusts the length and calls make is the
// denial of service.
//
// Negative control: moving the limit check after the allocation in
// Decoder.Bytes made this fail (AllocsPerRun reported 1).
func TestNoAllocationBeforeLimitCheck(t *testing.T) {
	cases := map[string][]byte{
		"over the limit":           {0xFF, 0xFF, 0xFF, 0xFF},
		"under the limit, no body": {0x00, 0x00, 0x00, 0x08, 'a'},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			var err error
			allocs := testing.AllocsPerRun(100, func() {
				d := NewDecoder(in)
				d.Bytes(16)
				err = d.Finish()
			})
			if err == nil {
				t.Fatal("Finish = nil, want an error")
			}
			if allocs != 0 {
				t.Fatalf("rejecting %x allocated %v times, want 0", in, allocs)
			}
		})
	}
}

// A field cut short is an error, never a zero value that decodes on.
//
// Negative control: removing the remaining-bytes check in Decoder.next made this
// fail (a slice-bounds panic on the first short prefix).
func TestTruncatedInput(t *testing.T) {
	full := encode(t, func(e *Encoder) {
		e.Uint8(1)
		e.Uint32(2)
		e.Uint64(3)
		e.Int64(4)
		e.Fixed(make([]byte, 16))
		e.Bytes([]byte("xy"), 2)
		e.String("z", 1)
	})
	read := func(d *Decoder) {
		d.Uint8()
		d.Uint32()
		d.Uint64()
		d.Int64()
		d.Fixed(make([]byte, 16))
		d.Bytes(2)
		d.String(1)
	}
	ran := 0
	for n := range len(full) {
		d := NewDecoder(full[:n])
		read(&d)
		if err := d.Finish(); !errors.Is(err, ErrTruncated) {
			t.Errorf("prefix of %d bytes: Finish = %v, want ErrTruncated", n, err)
		}
		ran++
	}
	// Zero iterations would pass silently (CLAUDE.md, Testing).
	if want := len(full); ran != want || want == 0 {
		t.Fatalf("checked %d prefixes, want %d", ran, want)
	}
}

// After the first error every read returns a zero value and does not advance,
// so a caller can decode a whole record and check once.
func TestErrorIsSticky(t *testing.T) {
	d := NewDecoder([]byte{0x00, 0x00, 0x00, 0x09, 0x01, 0x02, 0x03, 0x04, 0x05})
	if got := d.Bytes(4); got != nil {
		t.Fatalf("over-limit Bytes = %x, want nil", got)
	}
	if got := d.Uint32(); got != 0 {
		t.Fatalf("Uint32 after an error = %#x, want 0", got)
	}
	if err := d.Finish(); !errors.Is(err, ErrTooLong) {
		t.Fatalf("Finish = %v, want the first error, ErrTooLong", err)
	}
}

func TestEmptyInputFinishes(t *testing.T) {
	d := NewDecoder(nil)
	if err := d.Finish(); err != nil {
		t.Fatalf("Finish on empty input = %v", err)
	}
}
