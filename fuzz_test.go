package tally

import (
	"bytes"
	"errors"
	"testing"
)

// FuzzDecode drives the record decoder with arbitrary bytes (RS-04, RS-05,
// T-13). Not panicking is the least of it. The invariants are:
//
//   - a rejection is one of the record layer's errors, so the verifier can
//     classify it (SPEC §7.2) and never mistakes it for an IO failure;
//   - anything accepted re-encodes to exactly the bytes it came from, so that
//     no two byte strings decode to one record (SPEC §1);
//   - the decoded record does not alias its input, which a reader reuses.
//
// The seed corpus is committed in testdata/fuzz/FuzzDecode: the published
// vectors and boundary cases. go test runs it as an ordinary test; the CI fuzz
// job finds this target by name and fuzzes it.
//
// Negative control: letting decodeFields accept trailing bytes and removing
// the re-encoding comparison in decodeStrictWith, together, made this fail: at
// once on the trailing-byte seed, and with that seed removed, the fuzzer found
// an input with an appended byte within a second.
func FuzzDecode(f *testing.F) {
	f.Fuzz(func(t *testing.T, in []byte) {
		b := bytes.Clone(in)
		r, err := decodeRecord(b)
		if err != nil {
			if !errors.Is(err, errMalformed) && !errors.Is(err, errNonCanonical) {
				t.Fatalf("rejection outside the record layer's errors: %v", err)
			}
			if r != nil {
				t.Fatalf("a rejected input returned a record: %#v", r)
			}
			return
		}

		// Overwrite the input before re-encoding: a record that aliases it
		// would now encode differently.
		for i := range b {
			b[i] ^= 0xFF
		}
		again, err := encodeRecord(r)
		if err != nil {
			t.Fatalf("an accepted record does not encode: %v\ninput %x", err, in)
		}
		if !bytes.Equal(again, in) {
			t.Fatalf("an accepted record re-encodes differently\ninput     %x\nreencoded %x", in, again)
		}
	})
}
