package note

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func testPair(t *testing.T, seed byte, name string, witness bool) (skey, vkey string) {
	t.Helper()
	gen := GenerateKey
	if witness {
		gen = GenerateCosignerKey
	}
	skey, vkey, err := gen(bytes.NewReader(bytes.Repeat([]byte{seed}, 32)), name)
	if err != nil {
		t.Fatal(err)
	}
	return skey, vkey
}

func mustVerifier(t *testing.T, vkey string) *Verifier {
	t.Helper()
	v, err := NewVerifier(vkey)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// cosignedNote is a checkpoint signed by the log and cosigned by the witness
// at the given time.
func cosignedNote(t *testing.T, at time.Time) (note []byte, logV, witV *Verifier) {
	t.Helper()
	lsk, lvk := testPair(t, 1, "example.com/log", false)
	wsk, wvk := testPair(t, 2, "witness.example", true)
	ls, err := NewSigner(lsk)
	if err != nil {
		t.Fatal(err)
	}
	ws, err := NewCosigner(wsk)
	if err != nil {
		t.Fatal(err)
	}
	text := []byte("example.com/log\n5\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n")
	n, err := Sign(text, ls)
	if err != nil {
		t.Fatal(err)
	}
	line, err := Cosign(text, ws, at)
	if err != nil {
		t.Fatal(err)
	}
	return append(n, line...), mustVerifier(t, lvk), mustVerifier(t, wvk)
}

// A cosignature verifies under the witness's key, with its time, beside the
// log's signature; the note's signers are the log's keys only.
func TestACosignatureVerifies(t *testing.T) {
	at := time.Unix(1_790_000_000, 0)
	n, logV, witV := cosignedNote(t, at)
	got, err := Open(n, []*Verifier{logV, witV})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.SignedBy) != 1 || got.SignedBy[0] != logV {
		t.Fatalf("signed by %v, want the log's key only", got.SignedBy)
	}
	if len(got.Cosignatures) != 1 || got.Cosignatures[0].Witness != witV || got.Cosignatures[0].Time != at.Unix() {
		t.Fatalf("cosignatures %+v, want the witness's at %d", got.Cosignatures, at.Unix())
	}
	// Without the witness's key, its line is an unknown key's, ignored.
	if got, err = Open(n, []*Verifier{logV}); err != nil || len(got.Cosignatures) != 0 {
		t.Fatalf("without the witness key: %v, %+v", err, got)
	}
}

// A cosignature alone is not a signature of the note, and a bad one from a
// trusted witness fails the note, as a bad log signature does: with its time
// changed, its signature changed, or over another text.
//
// Negative control: with Open accepting a note signed only by a witness, the
// first case opened. Verified by hand, restored before committing.
func TestABadOrLoneCosignatureIsRefused(t *testing.T) {
	n, logV, witV := cosignedNote(t, time.Unix(1_790_000_000, 0))
	split := bytes.LastIndex(n, []byte("\n\n"))
	text, sigs := n[:split+1], strings.Split(strings.TrimSuffix(string(n[split+2:]), "\n"), "\n")
	if len(sigs) != 2 {
		t.Fatalf("%d signature lines, want 2", len(sigs))
	}
	lone := append(append(bytes.Clone(text), '\n'), sigs[1]+"\n"...)
	if _, err := Open(lone, []*Verifier{logV, witV}); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("a note with only the witness's cosignature: %v, want ErrUnknownKey", err)
	}

	name, b64, _ := strings.Cut(strings.TrimPrefix(sigs[1], sigPrefix), " ")
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	tamper := func(what string, f func([]byte)) {
		t.Helper()
		r := bytes.Clone(raw)
		f(r)
		msg := append(append(bytes.Clone(n[:split+2]), sigs[0]+"\n"...), sigPrefix+name+" "+base64.StdEncoding.EncodeToString(r)+"\n"...)
		if _, err := Open(msg, []*Verifier{logV, witV}); !errors.Is(err, ErrBadSignature) {
			t.Errorf("%s: %v, want ErrBadSignature", what, err)
		}
	}
	tamper("the time moved a second", func(r []byte) { r[11]++ })
	tamper("the signature changed", func(r []byte) { r[len(r)-1] ^= 1 })
	tamper("the time past int64", func(r []byte) { r[4] = 0x80 })
	other := bytes.Replace(n, []byte("\n5\n"), []byte("\n6\n"), 1)
	if _, err := Open(other, []*Verifier{witV}); err == nil {
		t.Error("a cosignature over another text opened")
	}
}

// A witness's key cannot sign as a log, and a log's key cannot cosign: each
// constructor takes its own type only.
func TestKeyTypesDoNotCross(t *testing.T) {
	wsk, _ := testPair(t, 3, "witness.example", true)
	lsk, _ := testPair(t, 4, "example.com/log", false)
	if _, err := NewSigner(wsk); !errors.Is(err, ErrMalformed) {
		t.Errorf("NewSigner on a witness key: %v", err)
	}
	if _, err := NewCosigner(lsk); !errors.Is(err, ErrMalformed) {
		t.Errorf("NewCosigner on a log key: %v", err)
	}
	if _, wvk := testPair(t, 3, "witness.example", true); !mustVerifier(t, wvk).Witness() {
		t.Error("a witness's verifier key is not marked as one")
	}
}

// A Cosigner, like a Signer, prints no key under any verb (RS-07).
func TestACosignerNeverPrintsItsKey(t *testing.T) {
	skey, _ := testPair(t, 0xAB, "witness.example", true)
	c, err := NewCosigner(skey)
	if err != nil {
		t.Fatal(err)
	}
	leaks := [][]byte{[]byte(strings.SplitN(skey, "+", 5)[4]), []byte("171 171 171 171"), []byte("abababab"), []byte("ABABABAB")}
	values := map[string]any{"*Cosigner": c, "Cosigner": *c, "struct{c *Cosigner}": struct{ c *Cosigner }{c}}
	checked := 0
	for name, v := range values {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
			out := []byte(fmt.Sprintf(verb, v))
			checked++
			for _, l := range leaks {
				if bytes.Contains(out, l) {
					t.Errorf("%s with %s prints %q: %s", name, verb, l, out)
				}
			}
		}
	}
	if checked != 24 {
		t.Fatalf("checked %d prints, want 24", checked)
	}
}
