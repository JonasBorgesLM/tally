package tally

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
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

// vectorCheckpointNote is the signed note of testdata/vectors/checkpoints.json
// and vectorVerifierKey its key, as seeds: the fuzzer starts from an accepted
// checkpoint and mutates it.
const vectorVerifierKey = "example.com/log+d455c521+AQOhB7/zzhC+HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4"

func vectorCheckpointNote(f *testing.F) []byte {
	f.Helper()
	raw, err := os.ReadFile(checkpointVectorsPath)
	if err != nil {
		f.Fatal(err)
	}
	var v checkpointVectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		f.Fatal(err)
	}
	return []byte(v.Checkpoints[0].Note) // the tally-chain/v1 one; the other bodies are seeded below
}

// FuzzCheckpoint drives SPEC §5.4, a whole signed checkpoint, with arbitrary
// bytes (RS-04, RS-05). Invariants: a rejection is a Failure of a kind §7.2
// names for a checkpoint, never a panic or an error outside them; and an
// accepted checkpoint's text is exactly what tally would write for its fields,
// so no two texts are accepted as one checkpoint.
//
// Negative control: reporting the note layer's rejections as HeartbeatGap made
// this fail on its first input.
func FuzzCheckpoint(f *testing.F) {
	keys, err := NewVerifiers(vectorVerifierKey)
	if err != nil {
		f.Fatal(err)
	}
	seed := vectorCheckpointNote(f)
	f.Add(seed)
	f.Add(seed[:len(seed)/2])
	f.Add(bytes.Replace(seed, []byte("\n\n"), []byte("\n"), 1))
	f.Fuzz(func(t *testing.T, in []byte) {
		c, fail := readCheckpoint(bytes.Clone(in), keys)
		if fail != nil {
			switch fail.Kind {
			case MalformedRecord, NonCanonicalEncoding, BadSignature, UnknownKey:
			default:
				t.Fatalf("a checkpoint rejected as %v, which §7.2 does not give a checkpoint", fail.Kind)
			}
			return
		}
		state := stateOpen
		if c.closed {
			state = stateClosed
		}
		text := checkpointText(c.origin, c.size, c.head, c.at, state)
		if !bytes.HasPrefix(in, []byte(text+"\n")) {
			t.Fatalf("an accepted checkpoint's text is not the canonical one\ninput %q\nwant  %q", in, text)
		}
	})
}

// FuzzCheckpointBody drives SPEC §5.2's body parser directly, which the
// signature keeps FuzzCheckpoint from reaching (RS-04). Invariant: an
// accepted body is exactly the canonical text of the fields it parsed to.
//
// Its first run found a recorded_at in the year 0000 accepted, which
// UnixNano wrapped to 1753: testdata/fuzz/FuzzCheckpointBody keeps that input,
// and removing the range check fails on it. Removing only the check against a
// leading zero in the size is not caught, and need not be: the size's round
// trip through FormatUint refuses it as well.
func FuzzCheckpointBody(f *testing.F) {
	seed := vectorCheckpointNote(f)
	f.Add(seed[:bytes.Index(seed, []byte("\n\n"))+1])
	f.Add([]byte("example.com/log\ntally-chain/v1\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n2026-11-16T12:00:00.000000000Z\nopen\n"))
	f.Add([]byte("example.com/log\ntally-heartbeat/v1\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n2026-11-16T12:00:00.000000000Z\nclosed\n"))
	f.Add([]byte("example.com/log\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"))
	f.Fuzz(func(t *testing.T, in []byte) {
		c, fail := parseCheckpointBody(bytes.Clone(in))
		if fail != nil {
			if fail.Kind != MalformedRecord && fail.Kind != NonCanonicalEncoding {
				t.Fatalf("a body rejected as %v", fail.Kind)
			}
			return
		}
		state := stateOpen
		if c.closed {
			state = stateClosed
		}
		var text string
		switch {
		case c.hasHead && c.hasRoot:
			text = heartbeatText(c.origin, c.size, c.head, c.root, c.at, state)
		case c.hasHead:
			text = checkpointText(c.origin, c.size, c.head, c.at, state)
		default:
			text = tlogText(c.origin, c.size, c.root)
		}
		if text != string(in) {
			t.Fatalf("an accepted body is not canonical\ninput %q\nwant  %q", in, text)
		}
	})
}
