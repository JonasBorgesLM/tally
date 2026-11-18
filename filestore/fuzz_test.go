package filestore

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// FuzzFrame drives SPEC §3.2's frame reader with arbitrary bytes, as a segment
// after its header (RS-04, RS-05). Invariants:
//
//   - the reader stops only on io.EOF, exactly between frames, or on one of
//     the format errors a verifier reports (errShortFrame, errEmptyFrame,
//     errFrameTooLong, errFrameCRC), never on anything else;
//   - every accepted body is within the limit, checked before allocating;
//   - every accepted frame re-encodes to exactly the bytes it was read from,
//     so a reader and a writer agree byte for byte;
//   - a clean end has consumed the whole input.
//
// The limit is small here so that the fuzzer explores lengths around it
// rather than allocating megabytes per input.
//
// Negative controls: removing the CRC check failed at once, a frame no longer
// re-encoding to its bytes; removing the ceiling check failed on the seed one
// byte over the limit.
func FuzzFrame(f *testing.F) {
	const limit = 4096
	f.Add(appendFrame(nil, []byte("a record")))
	f.Add(appendFrame(appendFrame(nil, []byte("one")), []byte("two")))
	f.Add(appendFrame(nil, nil))
	f.Add([]byte{0, 0, 0x10, 0x01, 1, 2, 3})                  // a length over the limit, cut short
	f.Add(appendFrame(nil, bytes.Repeat([]byte{7}, limit+1))) // a whole frame one byte over it
	f.Add(appendFrame(nil, []byte("cut"))[:5])
	f.Fuzz(func(t *testing.T, in []byte) {
		r := bytes.NewReader(in)
		consumed := 0
		for {
			body, err := readFrame(r, limit)
			if errors.Is(err, io.EOF) {
				if consumed != len(in) {
					t.Fatalf("a clean end after %d of %d bytes", consumed, len(in))
				}
				return
			}
			if err != nil {
				if !errors.Is(err, errShortFrame) && !errors.Is(err, errEmptyFrame) && !errors.Is(err, errFrameTooLong) && !errors.Is(err, errFrameCRC) {
					t.Fatalf("an error outside the format's: %v", err)
				}
				return
			}
			if len(body) > limit {
				t.Fatalf("a body of %d bytes, over the limit of %d", len(body), limit)
			}
			frame := appendFrame(nil, body)
			if !bytes.Equal(frame, in[consumed:consumed+len(frame)]) {
				t.Fatalf("a frame read at %d does not re-encode to its bytes", consumed)
			}
			consumed += len(frame)
		}
	})
}
