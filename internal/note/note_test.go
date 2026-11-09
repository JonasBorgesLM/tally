package note

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// seededKey returns a key pair from a fixed seed, so that failures reproduce.
func seededKey(t *testing.T, name string, seed byte) (*Signer, *Verifier) {
	t.Helper()
	skey, vkey, err := GenerateKey(bytes.NewReader(bytes.Repeat([]byte{seed}, 32)), name)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	s, err := NewSigner(skey)
	if err != nil {
		t.Fatalf("NewSigner(%q): %v", skey, err)
	}
	v, err := NewVerifier(vkey)
	if err != nil {
		t.Fatalf("NewVerifier(%q): %v", vkey, err)
	}
	return s, v
}

const text = "example.com/log\ntally-chain/v1\n1\n\n"

func sign(t *testing.T, msg string, signers ...KeySigner) []byte {
	t.Helper()
	b, err := Sign([]byte(msg), signers...)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return b
}

// SPEC §5.1: key_id = SHA-256(name || 0x0A || 0x01 || public_key)[:4],
// computed here independently of keyID.
func TestKeyIDFollowsTheSpec(t *testing.T) {
	s, v := seededKey(t, "example.com/log", 7)
	pub := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)).Public().(ed25519.PublicKey)
	h := sha256.Sum256(append([]byte("example.com/log\n\x01"), pub...))
	want := binary.BigEndian.Uint32(h[:4])
	if v.KeyHash() != want || s.KeyHash() != want {
		t.Fatalf("key ids %08x and %08x, want %08x", v.KeyHash(), s.KeyHash(), want)
	}
}

func TestSignAndOpen(t *testing.T) {
	s, v := seededKey(t, "example.com/log", 1)
	msg := sign(t, "line one\nline two\n", s)
	got, err := Open(msg, []*Verifier{v})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(got.Text) != "line one\nline two\n" || len(got.SignedBy) != 1 || got.SignedBy[0] != v {
		t.Fatalf("Open = %+v", got)
	}
	if !strings.HasSuffix(string(msg), "\n") || !strings.Contains(string(msg), "\n\n\u2014 example.com/log ") {
		t.Fatalf("note layout:\n%s", msg)
	}
}

// The signed message is the text, final newline included, blank line
// excluded (SPEC §5.1). A signature over anything else does not verify.
func TestTheSignedMessageIsTheText(t *testing.T) {
	s, _ := seededKey(t, "k", 3)
	msg := sign(t, "abc\n", s)
	line := strings.Split(strings.TrimSuffix(string(msg), "\n"), "\n")[2]
	raw, err := base64.StdEncoding.DecodeString(strings.Fields(line)[2])
	if err != nil {
		t.Fatal(err)
	}
	pub := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32)).Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, []byte("abc\n"), raw[4:]) {
		t.Fatal("the signature is not over the text with its final newline")
	}
}

// RF-10: a signature from a key nobody trusts is ignored, and a note no trusted
// key signed is UnknownKey: its text is never returned.
func TestOnlyUnknownSignaturesIsUnknownKey(t *testing.T) {
	s, _ := seededKey(t, "a", 1)
	_, other := seededKey(t, "b", 2)
	got, err := Open(sign(t, text, s), []*Verifier{other})
	if !errors.Is(err, ErrUnknownKey) || got != nil {
		t.Fatalf("Open = %+v, %v; want ErrUnknownKey and no text", got, err)
	}
}

// Unknown signatures beside a trusted one are ignored.
func TestUnknownSignaturesBesideATrustedOneAreIgnored(t *testing.T) {
	sa, va := seededKey(t, "a", 1)
	sb, _ := seededKey(t, "b", 2)
	got, err := Open(sign(t, text, sb, sa), []*Verifier{va})
	if err != nil || len(got.SignedBy) != 1 || got.SignedBy[0] != va {
		t.Fatalf("Open = %+v, %v; want accepted, signed by a", got, err)
	}
}

// SPEC §5.4 step 2: one bad signature from a trusted key fails the note, even
// with a good one from another trusted key.
//
// Negative control: skipping a trusted signature that fails, instead of
// failing the note, made this fail.
func TestABadTrustedSignatureFailsTheNote(t *testing.T) {
	sa, va := seededKey(t, "a", 1)
	sb, vb := seededKey(t, "b", 2)
	good := sign(t, text, sa)
	forged := sign(t, "other text\n", sb) // b's signature over different text
	msg := append(bytes.Clone(good), forged[bytes.LastIndex(forged, []byte("\n\n"))+2:]...)

	got, err := Open(msg, []*Verifier{va, vb})
	if !errors.Is(err, ErrBadSignature) || got != nil {
		t.Fatalf("Open = %+v, %v; want ErrBadSignature and no text", got, err)
	}
}

// Text is untrusted until a trusted signature has verified: on any error, Open
// returns no text at all (#25).
//
// Negative control: returning the parsed text alongside UnknownKey made the
// unknown-key case fail.
func TestNoTextWithoutATrustedSignature(t *testing.T) {
	s, v := seededKey(t, "a", 1)
	_, stranger := seededKey(t, "z", 9)
	good := sign(t, text, s)
	tampered := bytes.Replace(bytes.Clone(good), []byte("tally-chain"), []byte("tally-chaim"), 1)
	for name, tc := range map[string]struct {
		msg     []byte
		trusted []*Verifier
	}{
		"tampered text": {tampered, []*Verifier{v}},
		"unknown key":   {good, []*Verifier{stranger}},
		"malformed":     {[]byte("no signatures\n"), []*Verifier{v}},
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := Open(tc.msg, tc.trusted); err == nil || got != nil {
				t.Fatalf("Open = %+v, %v; want an error and nothing else", got, err)
			}
		})
	}
}

// SPEC §5.4 step 1: everything about the envelope is decided before any key is
// looked up, and is MalformedRecord, or NonCanonicalEncoding for base64.
//
// Negative controls: removing the control-character check, the 64 KiB limit,
// the 16-line limit and the canonical re-encoding each made its case fail.
func TestEnvelopeRules(t *testing.T) {
	s, v := seededKey(t, "a", 1)
	good := string(sign(t, text, s))
	sigLine := good[strings.LastIndex(good, "\n\n")+2:]

	nonCanonical := func() string {
		// Flip the low bits of the last base64 character before the padding:
		// it still decodes to the same bytes, so only canonicality differs.
		fields := strings.Fields(strings.TrimSuffix(sigLine, "\n"))
		b64 := fields[2]
		i := strings.IndexByte(b64, '=') - 1
		alpha := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
		c := strings.IndexByte(alpha, b64[i])
		mutated := b64[:i] + string(alpha[c|1]) + b64[i+1:]
		if mutated == b64 {
			mutated = b64[:i] + string(alpha[c&^1]) + b64[i+1:]
		}
		return good[:strings.LastIndex(good, "\n\n")+2] + fields[0] + " " + fields[1] + " " + mutated + "\n"
	}()

	cases := map[string]struct {
		msg  string
		want error
	}{
		"no blank line":          {"text\n" + sigLine, ErrMalformed},
		"no signature":           {text + "\n", ErrMalformed},
		"no final newline":       {strings.TrimSuffix(good, "\n"), ErrMalformed},
		"wrong prefix":           {text + "\n- a AAAA\n", ErrMalformed},
		"control character":      {"a\x01b\n\n" + sigLine, ErrMalformed},
		"carriage return":        {strings.Replace(good, "\n", "\r\n", 1), ErrMalformed},
		"invalid UTF-8":          {"a\xffb\n\n" + sigLine, ErrMalformed},
		"name with a space":      {text + "\n\u2014 a b " + strings.Fields(sigLine)[2] + "\n", ErrMalformed},
		"name with a plus":       {text + "\n\u2014 a+b " + strings.Fields(sigLine)[2] + "\n", ErrMalformed},
		"base64 that is not":     {text + "\n\u2014 a !!!!\n", ErrMalformed},
		"signature too short":    {text + "\n\u2014 a AAAA\n", ErrMalformed},
		"over 64 KiB":            {strings.Repeat("x", 64<<10) + "\n" + good, ErrMalformed},
		"17 signature lines":     {good + strings.Repeat(sigLine, 16), ErrMalformed},
		"non-canonical base64":   {nonCanonical, ErrNonCanonical},
		"empty signature base64": {text + "\n\u2014 a \n", ErrMalformed},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := Open([]byte(tc.msg), []*Verifier{v})
			if !errors.Is(err, tc.want) || got != nil {
				t.Fatalf("Open = %+v, %v; want %v", got, err, tc.want)
			}
		})
	}
}

// Sixteen lines is the limit, inclusive, and repeated identical lines count
// toward it; the key still appears once in SignedBy (SPEC §5.1, §5.4).
func TestSixteenSignatureLinesAreAccepted(t *testing.T) {
	s, v := seededKey(t, "a", 1)
	good := string(sign(t, text, s))
	sigLine := good[strings.LastIndex(good, "\n\n")+2:]
	got, err := Open([]byte(good+strings.Repeat(sigLine, 15)), []*Verifier{v})
	if err != nil || len(got.SignedBy) != 1 {
		t.Fatalf("Open with 16 identical lines = %+v, %v; want accepted, signed once", got, err)
	}
}

// The text and signatures are split at the last blank line, so a text that
// itself contains a blank line still opens (SPEC §5.1).
func TestSplitAtTheLastBlankLine(t *testing.T) {
	s, v := seededKey(t, "a", 1)
	got, err := Open(sign(t, "a\n\nb\n", s), []*Verifier{v})
	if err != nil || string(got.Text) != "a\n\nb\n" {
		t.Fatalf("Open = %+v, %v", got, err)
	}
}

func TestSignRefusesABadText(t *testing.T) {
	s, _ := seededKey(t, "a", 1)
	for name, txt := range map[string]string{
		"no final newline":  "abc",
		"control character": "a\x01\n",
		"empty":             "",
	} {
		if _, err := Sign([]byte(txt), s); err == nil {
			t.Errorf("%s: Sign accepted %q", name, txt)
		}
	}
	if _, err := Sign([]byte("abc\n")); err == nil {
		t.Error("Sign with no signer succeeded")
	}
}

// SPEC §5.3: the key encodings, strictly. The key_id in a key string must
// match the one computed, the hex is 8 lowercase digits, the base64 is
// canonical, and the algorithm byte is Ed25519's.
//
// Negative control: removing the key_id comparison in NewVerifier made the
// "wrong key_id" case fail.
func TestKeyEncodingsAreStrict(t *testing.T) {
	skey, vkey, err := GenerateKey(bytes.NewReader(bytes.Repeat([]byte{5}, 32)), "example.com/log")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(vkey, "+")
	name, id, key := parts[0], parts[1], parts[2]
	wrongID := fmt.Sprintf("%08x", 0xdeadbeef)
	rawKey, _ := base64.StdEncoding.DecodeString(key)

	for label, bad := range map[string]string{
		"wrong key_id":      name + "+" + wrongID + "+" + key,
		"uppercase hex":     name + "+" + strings.ToUpper(id) + "+" + key,
		"short hex":         name + "+" + id[:7] + "+" + key,
		"other algorithm":   name + "+" + id + "+" + base64.StdEncoding.EncodeToString(append([]byte{0x02}, rawKey[1:]...)),
		"short key":         name + "+" + id + "+" + base64.StdEncoding.EncodeToString(rawKey[:20]),
		"missing part":      name + "+" + id,
		"name with a space": "a b+" + id + "+" + key,
		"empty name":        "+" + id + "+" + key,
	} {
		if _, err := NewVerifier(bad); err == nil {
			t.Errorf("%s: NewVerifier accepted %q", label, bad)
		}
	}
	if _, err := NewSigner(vkey); err == nil {
		t.Error("NewSigner accepted a verifier key")
	}
	if _, err := NewSigner(strings.Replace(skey, "PRIVATE+KEY", "PUBLIC+KEY", 1)); err == nil {
		t.Error("NewSigner accepted a key without the PRIVATE+KEY prefix")
	}
	sparts := strings.Split(skey, "+")
	if _, err := NewSigner(strings.Join([]string{sparts[0], sparts[1], sparts[2], wrongID, sparts[4]}, "+")); err == nil {
		t.Error("NewSigner accepted a key_id that does not match its seed")
	}
}

// Stricter than x/mod by design: a second, bad signature from a trusted key
// whose first one verified still fails the note. x/mod skips a key's later
// lines once one has verified, so it would accept this note.
//
// Negative control: skipping a key's lines after its first good one made this
// fail.
func TestEveryTrustedLineIsVerified(t *testing.T) {
	s, v := seededKey(t, "a", 1)
	good := sign(t, text, s)
	other := sign(t, "other\n", s) // same key, signature over other text
	msg := append(bytes.Clone(good), other[bytes.LastIndex(other, []byte("\n\n"))+2:]...)
	if got, err := Open(msg, []*Verifier{v}); !errors.Is(err, ErrBadSignature) || got != nil {
		t.Fatalf("Open = %+v, %v; want ErrBadSignature", got, err)
	}
}

// Base64 uses '+', and a key string also separates its parts with '+': only
// the separators before the key may split it. The published test key's
// encoding contains '+', which is how this was found.
//
// Negative control: splitting on every '+' made this fail.
func TestAKeyWhoseBase64ContainsAPlus(t *testing.T) {
	found := 0
	for seed := range 256 {
		skey, vkey, err := GenerateKey(bytes.NewReader(bytes.Repeat([]byte{byte(seed)}, 32)), "k")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(vkey, "+") < 3 && strings.Count(skey, "+") < 5 {
			continue
		}
		found++
		if _, err := NewVerifier(vkey); err != nil {
			t.Fatalf("NewVerifier(%q): %v", vkey, err)
		}
		if _, err := NewSigner(skey); err != nil {
			t.Fatalf("NewSigner(%q): %v", skey, err)
		}
	}
	if found == 0 {
		t.Fatal("no seed gave a key with '+' in its base64; the test checked nothing")
	}
}
