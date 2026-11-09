// Package wire is the strict, fixed-width encoding of SPEC §1: big-endian
// integers of a fixed size, fixed-size byte arrays, and length-prefixed bytes and
// strings. There is no varint, because a varint admits several encodings of one
// value (ADR-0003), and no optional field.
//
// Both sides take a limit for every variable-length field. The Decoder checks it
// against the length prefix before it allocates or reads (RS-05), and the Encoder
// refuses to write what the Decoder would refuse to read.
//
// Errors are sticky: after the first one every read returns a zero value and
// nothing advances, so a record is decoded field by field and checked once, at
// Finish. The errors are sentinels, so rejecting hostile input allocates nothing.
//
// Record layouts, enum values and the re-encoding check of SPEC §1 rule 4 belong
// to the record layer above this package.
package wire

import (
	"encoding/binary"
	"errors"
	"unicode/utf8"
)

// Errors returned by Encoder.Result and Decoder.Finish. Compare them with
// errors.Is.
var (
	// ErrTruncated means the input ended inside a field.
	ErrTruncated = errors.New("wire: input ends inside a field")
	// ErrTooLong means a length prefix, or a value being encoded, exceeds the
	// field's limit.
	ErrTooLong = errors.New("wire: field longer than its limit")
	// ErrInvalidUTF8 means a string field is not valid UTF-8.
	ErrInvalidUTF8 = errors.New("wire: string is not valid UTF-8")
	// ErrTrailingBytes means bytes remain after the last field.
	ErrTrailingBytes = errors.New("wire: trailing bytes after the last field")
)

// Encoder appends fields to a buffer. The zero value is ready to use.
type Encoder struct {
	buf []byte
	err error
}

// Uint8 appends v.
func (e *Encoder) Uint8(v uint8) {
	if e.err == nil {
		e.buf = append(e.buf, v)
	}
}

// Uint32 appends v, big-endian.
func (e *Encoder) Uint32(v uint32) {
	if e.err == nil {
		e.buf = binary.BigEndian.AppendUint32(e.buf, v)
	}
}

// Uint64 appends v, big-endian.
func (e *Encoder) Uint64(v uint64) {
	if e.err == nil {
		e.buf = binary.BigEndian.AppendUint64(e.buf, v)
	}
}

// Int64 appends v as its two's complement, big-endian.
func (e *Encoder) Int64(v int64) {
	e.Uint64(uint64(v)) // #nosec G115 -- the bit pattern is the encoding; no value is lost.
}

// Fixed appends b with no length prefix, for a [n]byte field. The record layout
// fixes n, so the caller passes exactly n bytes.
func (e *Encoder) Fixed(b []byte) {
	if e.err == nil {
		e.buf = append(e.buf, b...)
	}
}

// Bytes appends a uint32 length and then b. A b longer than limit fails the
// encoding with ErrTooLong.
func (e *Encoder) Bytes(b []byte, limit uint32) {
	if e.err != nil {
		return
	}
	if uint64(len(b)) > uint64(limit) {
		e.err = ErrTooLong
		return
	}
	e.buf = binary.BigEndian.AppendUint32(e.buf, uint32(len(b))) // #nosec G115 -- bounded by limit, a uint32, just above.
	e.buf = append(e.buf, b...)
}

// String appends s as Bytes does. An s that is not valid UTF-8 fails the
// encoding with ErrInvalidUTF8.
func (e *Encoder) String(s string, limit uint32) {
	if e.err != nil {
		return
	}
	if !utf8.ValidString(s) {
		e.err = ErrInvalidUTF8
		return
	}
	if uint64(len(s)) > uint64(limit) {
		e.err = ErrTooLong
		return
	}
	e.buf = binary.BigEndian.AppendUint32(e.buf, uint32(len(s))) // #nosec G115 -- bounded by limit, a uint32, just above.
	e.buf = append(e.buf, s...)
}

// Result returns the encoded bytes, or the first error. On an error the bytes
// are nil: a partial encoding is never usable.
func (e *Encoder) Result() ([]byte, error) {
	if e.err != nil {
		return nil, e.err
	}
	return e.buf, nil
}

// Decoder reads fields from a buffer in order. It is a value, so a decoder
// local to a function stays on the stack.
type Decoder struct {
	b   []byte
	off int
	err error
}

// NewDecoder returns a Decoder reading b. It does not copy b, and b must not
// change while the Decoder is in use.
func NewDecoder(b []byte) Decoder {
	return Decoder{b: b}
}

// next returns the next n bytes, a slice of the input, or nil after setting
// ErrTruncated. n is a uint64 so that a uint32 length prefix is compared before
// any conversion to int, which on a 32-bit platform would turn a length at or
// above 2^31 negative.
func (d *Decoder) next(n uint64) []byte {
	if d.err != nil {
		return nil
	}
	if n > uint64(len(d.b)-d.off) { // #nosec G115 -- off never exceeds len(d.b), so the difference is not negative.
		d.err = ErrTruncated
		return nil
	}
	end := d.off + int(n) // #nosec G115 -- n is at most len(d.b)-d.off, an int, checked just above.
	s := d.b[d.off:end]
	d.off = end
	return s
}

// Uint8 reads a uint8.
func (d *Decoder) Uint8() uint8 {
	s := d.next(1)
	if s == nil {
		return 0
	}
	return s[0]
}

// Uint32 reads a big-endian uint32.
func (d *Decoder) Uint32() uint32 {
	s := d.next(4)
	if s == nil {
		return 0
	}
	return binary.BigEndian.Uint32(s)
}

// Uint64 reads a big-endian uint64.
func (d *Decoder) Uint64() uint64 {
	s := d.next(8)
	if s == nil {
		return 0
	}
	return binary.BigEndian.Uint64(s)
}

// Int64 reads a big-endian two's complement int64.
func (d *Decoder) Int64() int64 {
	return int64(d.Uint64()) // #nosec G115 -- the bit pattern is the encoding; no value is lost.
}

// Fixed fills dst from the next len(dst) bytes, for a [n]byte field. On an
// error dst is left unchanged.
func (d *Decoder) Fixed(dst []byte) {
	if s := d.next(uint64(len(dst))); s != nil {
		copy(dst, s)
	}
}

// field reads a uint32 length and returns that many bytes as a slice of the
// input. The length is checked against limit, and then against what remains,
// before anything else happens: nothing is allocated for a length the input
// cannot back (RS-05).
func (d *Decoder) field(limit uint32) []byte {
	if d.err != nil {
		return nil
	}
	n := d.Uint32()
	if d.err != nil {
		return nil
	}
	if n > limit {
		d.err = ErrTooLong
		return nil
	}
	return d.next(uint64(n))
}

// Bytes reads a length-prefixed field of at most limit bytes and returns a copy,
// so the result does not alias the input. An empty field is a non-nil empty
// slice; nil means an error, reported by Finish.
func (d *Decoder) Bytes(limit uint32) []byte {
	s := d.field(limit)
	if s == nil {
		return nil
	}
	out := make([]byte, len(s))
	copy(out, s)
	return out
}

// String reads a length-prefixed field of at most limit bytes that must be
// valid UTF-8. It is not normalised (SPEC §1).
func (d *Decoder) String(limit uint32) string {
	s := d.field(limit)
	if s == nil {
		return ""
	}
	if !utf8.Valid(s) {
		d.err = ErrInvalidUTF8
		return ""
	}
	return string(s)
}

// Finish returns the first error, or ErrTrailingBytes if input remains after
// the last field read. A record is valid only if Finish returns nil.
func (d *Decoder) Finish() error {
	if d.err != nil {
		return d.err
	}
	if d.off != len(d.b) {
		return ErrTrailingBytes
	}
	return nil
}
