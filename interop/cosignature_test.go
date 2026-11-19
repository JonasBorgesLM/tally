package interop

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"

	xnote "golang.org/x/mod/sumdb/note"

	tdnote "github.com/transparency-dev/formats/note"

	tnote "github.com/JonasBorgesLM/tally/internal/note"
	"github.com/JonasBorgesLM/tally/tallytest"
)

// Differential tests of tally's witness cosignatures (internal/note, #61,
// ADR-0021) against github.com/transparency-dev/formats/note, an independent
// implementation of c2sp.org/tlog-cosignature's cosignature/v1: the same key
// ids, and each side's cosignatures accepted by the other, with their time.

const cosigText = "example.com/log\n7\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"

func keysForCosig(t *testing.T) (logSkey, logVkey, witSkey, witVkey string) {
	t.Helper()
	logSkey, logVkey, err := tnote.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{5}, 32)), "example.com/log")
	if err != nil {
		t.Fatal(err)
	}
	witSkey, witVkey, err = tnote.GenerateCosignerKey(bytes.NewReader(bytes.Repeat([]byte{6}, 32)), "witness.example")
	if err != nil {
		t.Fatal(err)
	}
	return logSkey, logVkey, witSkey, witVkey
}

// tally's cosignature opens under transparency-dev's verifier, at its time.
//
// Negative control: with the cosignature message's header changed to
// "cosignature/v2", transparency-dev refused it. Verified by hand, restored.
func TestTallyCosignaturesOpenUnderTransparencyDev(t *testing.T) {
	logSkey, logVkey, witSkey, witVkey := keysForCosig(t)
	ls, err := tnote.NewSigner(logSkey)
	if err != nil {
		t.Fatal(err)
	}
	ws, err := tnote.NewCosigner(witSkey)
	if err != nil {
		t.Fatal(err)
	}
	n, err := tnote.Sign([]byte(cosigText), ls)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1_790_000_123, 0)
	line, err := tnote.Cosign([]byte(cosigText), ws, at)
	if err != nil {
		t.Fatal(err)
	}
	n = append(n, line...)

	xlog, err := xnote.NewVerifier(logVkey)
	if err != nil {
		t.Fatal(err)
	}
	twit, err := tdnote.NewVerifierForCosignatureV1(witVkey)
	if err != nil {
		t.Fatalf("transparency-dev reads tally's witness key: %v", err)
	}
	opened, err := xnote.Open(n, xnote.VerifierList(xlog, twit))
	if err != nil {
		t.Fatalf("transparency-dev refuses tally's cosigned note: %v", err)
	}
	var found bool
	for _, s := range opened.Sigs {
		if s.Name == "witness.example" {
			found = true
			got, err := tdnote.CoSigV1Timestamp(s)
			if err != nil || !got.Equal(at) {
				t.Fatalf("transparency-dev reads the time as %v, %v; want %v", got, err, at)
			}
		}
	}
	if !found {
		t.Fatal("the witness's cosignature was not among the verified signatures")
	}
}

// transparency-dev's cosignature opens under tally, at its time, and both
// sides name the witness's key with the same id.
func TestTransparencyDevCosignaturesOpenUnderTally(t *testing.T) {
	logSkey, logVkey, witSkey, witVkey := keysForCosig(t)
	xlog, err := xnote.NewSigner(logSkey)
	if err != nil {
		t.Fatal(err)
	}
	twit, err := tdnote.NewSignerForCosignatureV1(witSkey)
	if err != nil {
		t.Fatalf("transparency-dev reads tally's witness signer key: %v", err)
	}
	before := time.Now().Unix()
	n, err := xnote.Sign(&xnote.Note{Text: cosigText}, xlog, twit)
	if err != nil {
		t.Fatal(err)
	}
	after := time.Now().Unix()

	lv, err := tnote.NewVerifier(logVkey)
	if err != nil {
		t.Fatal(err)
	}
	wv, err := tnote.NewVerifier(witVkey)
	if err != nil {
		t.Fatal(err)
	}
	if wv.KeyHash() != twit.KeyHash() {
		t.Fatalf("key id: tally %08x, transparency-dev %08x", wv.KeyHash(), twit.KeyHash())
	}
	opened, err := tnote.Open(n, []*tnote.Verifier{lv, wv})
	if err != nil {
		t.Fatalf("tally refuses transparency-dev's cosigned note: %v", err)
	}
	if len(opened.Cosignatures) != 1 || opened.Cosignatures[0].Time < before || opened.Cosignatures[0].Time > after {
		t.Fatalf("cosignatures %+v, want one dated between %d and %d", opened.Cosignatures, before, after)
	}
}

// testdata/vectors/witness.json, which tally writes, opens under
// transparency-dev with the published log and witness keys, at its time.
func TestWitnessVectorOpensUnderTransparencyDev(t *testing.T) {
	raw, err := os.ReadFile("../testdata/vectors/witness.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		VerifierKey string `json:"verifier_key"`
		Time        int64  `json:"time,string"`
		Note        string `json:"note"`
	}
	if err = json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	xlog, err := xnote.NewVerifier(tallytest.TestVerifierKey)
	if err != nil {
		t.Fatal(err)
	}
	twit, err := tdnote.NewVerifierForCosignatureV1(v.VerifierKey)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := xnote.Open([]byte(v.Note), xnote.VerifierList(xlog, twit))
	if err != nil {
		t.Fatalf("transparency-dev refuses the vector: %v", err)
	}
	cosigned := 0
	for _, s := range opened.Sigs {
		if s.Hash == twit.KeyHash() {
			at, err := tdnote.CoSigV1Timestamp(s)
			if err != nil || at.Unix() != v.Time {
				t.Fatalf("time %v, %v; want %d", at, err, v.Time)
			}
			cosigned++
		}
	}
	if cosigned != 1 {
		t.Fatalf("%d cosignatures verified, want 1", cosigned)
	}
}
