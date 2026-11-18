package tally

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"iter"
	"os"
	"slices"
	"testing"

	"github.com/JonasBorgesLM/tally/internal/merkle"
	"github.com/JonasBorgesLM/tally/internal/note"
)

// The published checkpoint vectors (SPEC §5.2, §8): over the five leaves of
// records.json, signed with the key of keys.json, one of each body: the v0.1
// tally-chain/v1 checkpoint, and v0.2's tally-heartbeat/v1 note and
// tlog-checkpoint (#60), whose root is merkle.json's root of 5. Written once
// with -write-vectors and committed, like the others.

const checkpointVectorsPath = "testdata/vectors/checkpoints.json"

type checkpointVectorFile struct {
	Comment     string             `json:"comment"`
	Checkpoints []checkpointVector `json:"checkpoints"`
}

type checkpointVector struct {
	Kind    string `json:"kind"`
	Size    uint64 `json:"size,string"`
	HeadHex string `json:"head_hex,omitempty"`
	RootHex string `json:"root_hex,omitempty"`
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

func makeCheckpointVectors(t *testing.T, bodies [][]byte) []checkpointVector {
	t.Helper()
	keys := makeKeyVectors(t)
	s, err := note.NewSigner(keys.Keys[0].SignerKey)
	if err != nil {
		t.Fatal(err)
	}
	size := uint64(len(bodies))
	head := LeafHash(bodies[len(bodies)-1])
	tree := new(merkle.Range)
	for _, b := range bodies {
		tree.Append(LeafHash(b))
	}
	root, err := tree.Root()
	if err != nil {
		t.Fatal(err)
	}
	// recorded_at: the head entry's, from records.json, in SPEC §5.2's layout.
	at := int64(0x0102030405060708 + 40)
	sign := func(kind, text string, withHead, withRoot bool) checkpointVector {
		msg, err := note.Sign([]byte(text), s)
		if err != nil {
			t.Fatal(err)
		}
		v := checkpointVector{Kind: kind, Size: size, Text: text, Note: string(msg)}
		if withHead {
			v.HeadHex = hex.EncodeToString(head[:])
		}
		if withRoot {
			v.RootHex = hex.EncodeToString(root[:])
		}
		return v
	}
	return []checkpointVector{
		sign(bodyChainV1, checkpointText("example.com/log", size, head, at, stateClosed), true, false),
		sign(bodyHeartbeatV1, heartbeatText("example.com/log", size, head, root, at, stateClosed), true, true),
		sign("tlog-checkpoint", tlogText("example.com/log", size, root), false, true),
	}
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

	want := makeCheckpointVectors(t, bodies)
	if *writeVectors {
		out, merr := json.MarshalIndent(checkpointVectorFile{
			Comment: "tally SPEC checkpoint vectors over records.json, one of each body (tally-chain/v1, tally-heartbeat/v1, " +
				"tlog-checkpoint), signed with the PUBLIC test key of keys.json. See README.md.",
			Checkpoints: want,
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
	if !slices.Equal(got.Checkpoints, want) {
		t.Fatalf("the committed checkpoint vectors differ from what this implementation signs")
	}

	keys, err := NewVerifiers(makeKeyVectors(t).Keys[0].VerifierKey)
	if err != nil {
		t.Fatal(err)
	}
	// Each body alone attests the whole log, and so do the three together.
	ran := 0
	for _, set := range [][]checkpointVector{got.Checkpoints[:1], got.Checkpoints[1:2], got.Checkpoints[2:], got.Checkpoints} {
		cps := make([]SignedCheckpoint, 0, len(set))
		for _, v := range set {
			cps = append(cps, SignedCheckpoint(v.Note))
		}
		rep, err := Verify(context.Background(), vectorSource{bodies: bodies, cps: cps}, keys)
		if err != nil || !rep.OK() || rep.Size != 5 || rep.AttestedSize != 5 {
			t.Fatalf("Verify over the vectors with %d of them = %+v, %v; want OK with all 5 leaves attested", len(set), rep, err)
		}
		ran++
	}
	if ran != 4 {
		t.Fatalf("ran %d sets, want 4", ran)
	}
}

// CheckpointSize reads the size of the published checkpoint, and refuses
// bytes that are not a checkpoint. It does not verify the signature: a Store
// reads back only what it stored itself.
func TestCheckpointSize(t *testing.T) {
	raw, err := os.ReadFile(checkpointVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var f checkpointVectorFile
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Checkpoints) != 3 {
		t.Fatalf("%d checkpoint vectors, want 3", len(f.Checkpoints))
	}
	for _, v := range f.Checkpoints {
		got, err := CheckpointSize(SignedCheckpoint(v.Note))
		if err != nil || got != v.Size {
			t.Fatalf("%s: CheckpointSize = %d, %v; want %d", v.Kind, got, err, v.Size)
		}
	}
	for _, bad := range []string{"", "not a note", "a\nb\n\n— sig\n"} {
		if _, err := CheckpointSize(SignedCheckpoint(bad)); err == nil {
			t.Errorf("CheckpointSize(%q) succeeded", bad)
		}
	}
}

// VerifyCheckpoint accepts the published checkpoint under its key, and refuses
// it under another key or with a byte changed (SPEC §5.4).
func TestVerifyCheckpoint(t *testing.T) {
	raw, err := os.ReadFile(checkpointVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var f checkpointVectorFile
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	cp := SignedCheckpoint(f.Checkpoints[0].Note)
	keys, err := NewVerifiers("example.com/log+d455c521+AQOhB7/zzhC+HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4")
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyCheckpoint(cp, keys); err != nil {
		t.Fatalf("VerifyCheckpoint(vector) = %v", err)
	}
	tampered := bytes.Clone(cp)
	tampered[len("example.com/log\ntally-chain/v1\n")] = '6' // the size line
	if err = VerifyCheckpoint(tampered, keys); err == nil {
		t.Error("a tampered checkpoint was accepted")
	}
	_, other, err := note.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{3}, 32)), "example.com/log")
	if err != nil {
		t.Fatal(err)
	}
	otherKeys, err := NewVerifiers(other)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCheckpoint(cp, otherKeys); err == nil {
		t.Error("a checkpoint was accepted under a key that did not sign it")
	}
}
