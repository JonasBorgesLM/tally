package tally

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/JonasBorgesLM/tally/internal/note"
)

// The published witness vector (SPEC §5.5, §8, ADR-0021): a PUBLIC test
// witness key, from the seed 20 21 … 3f, and the tlog-checkpoint of
// checkpoints.json cosigned with it at a fixed time. Written once with
// -write-vectors and committed, like the others.

const witnessVectorsPath = "testdata/vectors/witness.json"

type witnessVectorFile struct {
	Comment     string `json:"comment"`
	Name        string `json:"name"`
	SeedHex     string `json:"seed_hex"`
	KeyIDHex    string `json:"key_id_hex"`
	VerifierKey string `json:"verifier_key"`
	SignerKey   string `json:"signer_key"`
	Time        int64  `json:"time,string"`
	Line        string `json:"cosignature_line"`
	Note        string `json:"note"`
}

func makeWitnessVector(t *testing.T, tlog string) witnessVectorFile {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(0x20 + i)
	}
	const name = "witness.example"
	skey, vkey, err := note.GenerateCosignerKey(bytes.NewReader(seed), name)
	if err != nil {
		t.Fatal(err)
	}
	c, err := note.NewCosigner(skey)
	if err != nil {
		t.Fatal(err)
	}
	const at = 1_790_000_000
	text, _, _ := strings.Cut(tlog, "\n\n")
	line, err := note.Cosign([]byte(text+"\n"), c, time.Unix(at, 0))
	if err != nil {
		t.Fatal(err)
	}
	return witnessVectorFile{
		Comment: "tally SPEC witness vector: a PUBLIC test witness key, never for real use, and the tlog-checkpoint of " +
			"checkpoints.json cosigned with it (cosignature/v1). See README.md.",
		Name: name, SeedHex: hex.EncodeToString(seed), KeyIDHex: strings.Split(vkey, "+")[1],
		VerifierKey: vkey, SignerKey: skey, Time: at, Line: line, Note: tlog + line,
	}
}

// The committed witness vector is what this implementation cosigns, and
// Verify over records.json with it, trusting the witness, is witnessed to 5.
func TestWitnessVectors(t *testing.T) {
	var cps checkpointVectorFile
	raw, err := os.ReadFile(checkpointVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &cps); err != nil {
		t.Fatal(err)
	}
	var tlog string
	for _, c := range cps.Checkpoints {
		if c.Kind == "tlog-checkpoint" {
			tlog = c.Note
		}
	}
	if tlog == "" {
		t.Fatal("checkpoints.json holds no tlog-checkpoint")
	}
	want := makeWitnessVector(t, tlog)
	if *writeVectors {
		out, merr := json.MarshalIndent(want, "", "  ")
		if merr != nil {
			t.Fatal(merr)
		}
		if werr := os.WriteFile(witnessVectorsPath, append(out, '\n'), 0o600); werr != nil {
			t.Fatal(werr)
		}
	}
	raw, err = os.ReadFile(witnessVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var got witnessVectorFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatal("the committed witness vector differs from what this implementation cosigns")
	}

	var recs vectorFile
	if raw, err = os.ReadFile(recordVectorsPath); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &recs); err != nil {
		t.Fatal(err)
	}
	bodies := make([][]byte, 0, len(recs.Records))
	for _, r := range recs.Records {
		b, herr := hex.DecodeString(r.BodyHex)
		if herr != nil {
			t.Fatal(herr)
		}
		bodies = append(bodies, b)
	}
	keys, err := NewVerifiers(makeKeyVectors(t).Keys[0].VerifierKey)
	if err != nil {
		t.Fatal(err)
	}
	witnesses, err := NewVerifiers(got.VerifierKey)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Verify(context.Background(), vectorSource{bodies: bodies, cps: []SignedCheckpoint{SignedCheckpoint(got.Note)}},
		keys, WithWitnesses(witnesses, 1), WithRequireWitnessed())
	if err != nil || !rep.OK() || rep.WitnessedSize != 5 {
		t.Fatalf("Verify over the vectors with the witness = %+v, %v; want OK, witnessed to 5", rep, err)
	}
}
