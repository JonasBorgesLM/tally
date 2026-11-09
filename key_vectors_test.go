package tally

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/JonasBorgesLM/tally/internal/note"
)

// The published key vectors (SPEC §5.3, §8): a test key in both encodings and
// a note it signed. Written once with -write-vectors and committed; the suite
// only compares, like records.json.

const keyVectorsPath = "testdata/vectors/keys.json"

type keyVectorFile struct {
	Comment string       `json:"comment"`
	Keys    []keyVector  `json:"keys"`
	Notes   []noteVector `json:"notes"`
}

type keyVector struct {
	Name        string `json:"name"`
	SeedHex     string `json:"seed_hex"`
	KeyIDHex    string `json:"key_id_hex"`
	VerifierKey string `json:"verifier_key"`
	SignerKey   string `json:"signer_key"`
}

type noteVector struct {
	Key  string `json:"key"`
	Text string `json:"text"`
	Note string `json:"note"`
}

// testKeySeed is the test key's seed: bytes 0x00 to 0x1f. It is published, so
// the key it makes must never sign anything real.
func testKeySeed() []byte {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	return seed
}

func makeKeyVectors(t *testing.T) keyVectorFile {
	t.Helper()
	const name = "example.com/log" // the origin of records.json's genesis
	skey, vkey, err := note.GenerateKey(bytes.NewReader(testKeySeed()), name)
	if err != nil {
		t.Fatal(err)
	}
	s, err := note.NewSigner(skey)
	if err != nil {
		t.Fatal(err)
	}
	text := "example.com/log\ntally-chain/v1\n1\nkEU++Y2Ts+2XCWruXmNj2tv/uNjIiZ5EaG4s5anGgw8=\n2026-11-09T12:00:00.000000000Z\nopen\n"
	msg, err := note.Sign([]byte(text), s)
	if err != nil {
		t.Fatal(err)
	}
	return keyVectorFile{
		Comment: "tally SPEC v1 key vectors: a PUBLIC test key, never for real use. See README.md in this directory.",
		Keys: []keyVector{{
			Name: name, SeedHex: hex.EncodeToString(testKeySeed()),
			KeyIDHex:    fmt.Sprintf("%08x", s.KeyHash()),
			VerifierKey: vkey, SignerKey: skey,
		}},
		Notes: []noteVector{{Key: name, Text: text, Note: string(msg)}},
	}
}

// The committed key vectors are what this implementation produces, and the
// note in them opens under the published verifier key.
//
// Negative control: changing the key id derivation in internal/note (the
// separator byte) made this fail on the committed file.
func TestKeyVectors(t *testing.T) {
	want := makeKeyVectors(t)
	if *writeVectors {
		out, err := json.MarshalIndent(want, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyVectorsPath, append(out, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s: review the diff before committing", keyVectorsPath)
	}
	raw, err := os.ReadFile(keyVectorsPath)
	if err != nil {
		t.Fatalf("reading the committed key vectors: %v", err)
	}
	var got keyVectorFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if derr := dec.Decode(&got); derr != nil {
		t.Fatal(derr)
	}
	if len(got.Keys) != 1 || got.Keys[0] != want.Keys[0] || len(got.Notes) != 1 || got.Notes[0] != want.Notes[0] {
		t.Fatalf("committed key vectors differ from what this implementation produces\n got %+v\nwant %+v", got, want)
	}
	v, err := note.NewVerifier(got.Keys[0].VerifierKey)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := note.Open([]byte(got.Notes[0].Note), []*note.Verifier{v})
	if err != nil || string(opened.Text) != got.Notes[0].Text {
		t.Fatalf("the committed note does not open under the committed key: %v", err)
	}
}
