package tallytest

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/JonasBorgesLM/tally/internal/note"
)

// The test keys are the published vectors' key, and they are a valid pair.
func TestTestKeysAreThePublishedPair(t *testing.T) {
	raw, err := os.ReadFile("../testdata/vectors/keys.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Keys []struct {
			VerifierKey string `json:"verifier_key"`
			SignerKey   string `json:"signer_key"`
		} `json:"keys"`
	}
	if uerr := json.Unmarshal(raw, &f); uerr != nil {
		t.Fatal(uerr)
	}
	if len(f.Keys) != 1 || f.Keys[0].SignerKey != TestSignerKey || f.Keys[0].VerifierKey != TestVerifierKey {
		t.Fatalf("the tallytest keys differ from testdata/vectors/keys.json")
	}
	s, err := note.NewSigner(TestSignerKey)
	if err != nil {
		t.Fatal(err)
	}
	v, err := note.NewVerifier(TestVerifierKey)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := note.Sign([]byte("test\n"), s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := note.Open(msg, []*note.Verifier{v}); err != nil {
		t.Fatalf("a note signed with TestSignerKey does not open under TestVerifierKey: %v", err)
	}
}
