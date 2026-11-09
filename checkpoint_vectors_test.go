package tally

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"iter"
	"os"
	"testing"

	"github.com/JonasBorgesLM/tally/internal/note"
)

// The published checkpoint vector (SPEC §5.2, §8): one checkpoint over the
// head of records.json, signed with the key of keys.json. Written once with
// -write-vectors and committed, like the others.

const checkpointVectorsPath = "testdata/vectors/checkpoints.json"

type checkpointVectorFile struct {
	Comment     string             `json:"comment"`
	Checkpoints []checkpointVector `json:"checkpoints"`
}

type checkpointVector struct {
	Size    uint64 `json:"size,string"`
	HeadHex string `json:"head_hex"`
	Text    string `json:"text"`
	Note    string `json:"note"`
}

// vectorSource serves the record vectors and a checkpoint to Verify.
type vectorSource struct {
	bodies [][]byte
	cps    []SignedCheckpoint
}

func (s vectorSource) Records(_ context.Context, from uint64) iter.Seq2[Record, error] {
	return func(yield func(Record, error) bool) {
		for i, b := range s.bodies {
			if uint64(i) >= from && !yield(Record{Seq: uint64(i), Body: b}, nil) {
				return
			}
		}
	}
}

func (s vectorSource) Checkpoints(context.Context) iter.Seq2[SignedCheckpoint, error] {
	return func(yield func(SignedCheckpoint, error) bool) {
		for _, cp := range s.cps {
			if !yield(cp, nil) {
				return
			}
		}
	}
}

func makeCheckpointVector(t *testing.T, bodies [][]byte) checkpointVector {
	t.Helper()
	keys := makeKeyVectors(t)
	s, err := note.NewSigner(keys.Keys[0].SignerKey)
	if err != nil {
		t.Fatal(err)
	}
	head := leafHash(bodies[len(bodies)-1])
	// recorded_at: the head entry's, from records.json, in SPEC §5.2's layout.
	text := checkpointText("example.com/log", uint64(len(bodies)), head, 0x0102030405060708+40, stateClosed)
	msg, err := note.Sign([]byte(text), s)
	if err != nil {
		t.Fatal(err)
	}
	return checkpointVector{Size: uint64(len(bodies)), HeadHex: hex.EncodeToString(head[:]), Text: text, Note: string(msg)}
}

// The committed checkpoint is what this implementation signs, and Verify over
// the record vectors and it, under the published key, is OK with the whole
// log attested.
//
// Negative control: signing the vector over the second-to-last leaf made the
// committed file disagree with what this implementation signs.
func TestCheckpointVectors(t *testing.T) {
	var recs vectorFile
	raw, err := os.ReadFile(recordVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	if uerr := json.Unmarshal(raw, &recs); uerr != nil {
		t.Fatal(uerr)
	}
	bodies := make([][]byte, 0, len(recs.Records))
	for _, r := range recs.Records {
		b, herr := hex.DecodeString(r.BodyHex)
		if herr != nil {
			t.Fatal(herr)
		}
		bodies = append(bodies, b)
	}

	want := makeCheckpointVector(t, bodies)
	if *writeVectors {
		out, merr := json.MarshalIndent(checkpointVectorFile{
			Comment:     "tally SPEC v1 checkpoint vector over records.json, signed with the PUBLIC test key of keys.json. See README.md.",
			Checkpoints: []checkpointVector{want},
		}, "", "  ")
		if merr != nil {
			t.Fatal(merr)
		}
		if werr := os.WriteFile(checkpointVectorsPath, append(out, '\n'), 0o600); werr != nil {
			t.Fatal(werr)
		}
		t.Logf("wrote %s: review the diff before committing", checkpointVectorsPath)
	}
	raw, err = os.ReadFile(checkpointVectorsPath)
	if err != nil {
		t.Fatalf("reading the committed checkpoint vectors: %v", err)
	}
	var got checkpointVectorFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if derr := dec.Decode(&got); derr != nil {
		t.Fatal(derr)
	}
	if len(got.Checkpoints) != 1 || got.Checkpoints[0] != want {
		t.Fatalf("the committed checkpoint vector differs from what this implementation signs")
	}

	keys, err := NewVerifiers(makeKeyVectors(t).Keys[0].VerifierKey)
	if err != nil {
		t.Fatal(err)
	}
	src := vectorSource{bodies: bodies, cps: []SignedCheckpoint{SignedCheckpoint(got.Checkpoints[0].Note)}}
	rep, err := Verify(context.Background(), src, keys)
	if err != nil || !rep.OK() || rep.Size != 5 || rep.AttestedSize != 5 {
		t.Fatalf("Verify over the vectors = %+v, %v; want OK with all 5 leaves attested", rep, err)
	}
}
