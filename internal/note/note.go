// Package note is a minimal implementation of C2SP signed notes
// (https://c2sp.org/signed-note) with Ed25519 keys, as SPEC §5 restates them.
//
// It is the standard library only (RNF-01). golang.org/x/mod/sumdb/note is
// the reference, and the interop module tests this package against it (#30).
// Where the two differ, this package is stricter, never looser (SPEC §5):
//
//   - at most 16 signature lines and 64 KiB per note (SPEC §6);
//   - base64 must be canonical, in signatures and in keys;
//   - every signature line from a trusted key is verified, so a second, bad
//     signature from a key whose first one was good still fails the note;
//     x/mod skips a key's later lines once one has verified.
//
// A note's text is untrusted until a trusted signature has verified: Open
// returns it only then. Parsing the text, such as a checkpoint body, is the
// caller's job.
package note

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Errors from Open, in SPEC §5.4's order. They map to SPEC §7.2's kinds:
// ErrMalformed to MalformedRecord, ErrNonCanonical to NonCanonicalEncoding,
// and the other two to the kinds of the same name.
var (
	ErrMalformed    = errors.New("note: malformed")
	ErrNonCanonical = errors.New("note: non-canonical base64")
	ErrBadSignature = errors.New("note: a trusted key's signature does not verify")
	ErrUnknownKey   = errors.New("note: no signature from a trusted key")
)

const (
	algEd25519 = 0x01
	// algCosignatureV1 is c2sp.org/tlog-cosignature's timestamped Ed25519
	// cosignature (signed-note type 0x04): a witness's key (#61, ADR-0021).
	algCosignatureV1 = 0x04

	// MaxSize is the largest note, in bytes (SPEC §6).
	MaxSize = 64 << 10
	// MaxSignatures is the most signature lines a note may carry, counted
	// from any key (SPEC §6).
	MaxSignatures = 16

	sigPrefix = "— " // EM DASH, space
)

// keyID is SPEC §5.1's key id: SHA-256(name || 0x0A || alg || public key)[:4],
// alg 0x01 for a log's key and 0x04 for a witness's.
func keyID(name string, alg byte, pub ed25519.PublicKey) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{'\n', alg})
	h.Write(pub)
	return binary.BigEndian.Uint32(h.Sum(nil))
}

// validName is golang.org/x/mod/sumdb/note's rule for a key name: non-empty,
// valid UTF-8, no space and no '+'. A tally origin must satisfy the stricter
// SPEC §2.1 rule, which the record layer enforces at genesis.
func validName(name string) bool {
	return name != "" && utf8.ValidString(name) &&
		strings.IndexFunc(name, unicode.IsSpace) < 0 && !strings.Contains(name, "+")
}

// decode64 decodes standard padded base64, telling a string that is not base64
// (ErrMalformed) from one that decodes but is not the canonical encoding of
// its bytes (ErrNonCanonical).
func decode64(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || s == "" {
		return nil, ErrMalformed
	}
	if base64.StdEncoding.EncodeToString(b) != s {
		return nil, ErrNonCanonical
	}
	return b, nil
}

// Verifier is a trusted public key: a log's (type 0x01), whose signatures
// Open returns in SignedBy, or a witness's (type 0x04), whose cosignatures it
// returns in Cosignatures.
type Verifier struct {
	name string
	id   uint32
	alg  byte
	pub  ed25519.PublicKey
}

// Witness reports whether the key is a witness's cosignature key (type 0x04).
func (v *Verifier) Witness() bool { return v.alg == algCosignatureV1 }

// Name is the key's name, which for tally is the log's origin.
func (v *Verifier) Name() string { return v.name }

// KeyHash is the key id.
func (v *Verifier) KeyHash() uint32 { return v.id }

// NewVerifier parses a verifier key, `<name>+<key_id hex>+<base64(alg || public key)>`
// (SPEC §5.3), alg 0x01 for a log's key or 0x04 for a witness's. The key id
// must match the one computed from the name, alg and key.
func NewVerifier(vkey string) (*Verifier, error) {
	// SplitN, not Split: base64 uses '+', so the key part may contain it.
	parts := strings.SplitN(vkey, "+", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: a verifier key has three parts", ErrMalformed)
	}
	name, id, alg, key, err := parseKeyParts(parts[0], parts[1], parts[2])
	if err != nil {
		return nil, err
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: an Ed25519 public key is %d bytes", ErrMalformed, ed25519.PublicKeySize)
	}
	pub := ed25519.PublicKey(key)
	if keyID(name, alg, pub) != id {
		return nil, fmt.Errorf("%w: the key id does not match the name and key", ErrMalformed)
	}
	return &Verifier{name: name, id: id, alg: alg, pub: pub}, nil
}

// parseKeyParts checks the parts common to both key encodings and returns the
// algorithm byte and the key bytes after it.
func parseKeyParts(name, idHex, key64 string) (keyName string, id uint32, alg byte, key []byte, err error) {
	if !validName(name) {
		return "", 0, 0, nil, fmt.Errorf("%w: invalid key name", ErrMalformed)
	}
	if len(idHex) != 8 || strings.ToLower(idHex) != idHex {
		return "", 0, 0, nil, fmt.Errorf("%w: a key id is 8 lowercase hex digits", ErrMalformed)
	}
	id64, perr := strconv.ParseUint(idHex, 16, 32)
	if perr != nil {
		return "", 0, 0, nil, fmt.Errorf("%w: a key id is 8 lowercase hex digits", ErrMalformed)
	}
	raw, derr := decode64(key64)
	if derr != nil {
		return "", 0, 0, nil, derr
	}
	if len(raw) < 1 || (raw[0] != algEd25519 && raw[0] != algCosignatureV1) {
		return "", 0, 0, nil, fmt.Errorf("%w: only Ed25519 keys (0x01) and Ed25519 cosignature/v1 keys (0x04) are supported", ErrMalformed)
	}
	return name, uint32(id64), raw[0], raw[1:], nil
}

// Signer holds a private key. Its error messages never include the key, and
// no fmt verb prints it, on a *Signer, a Signer, or a struct holding one,
// exported or not (RS-07).
type Signer struct {
	name string
	id   uint32
	// sign closes over the private key, which is held nowhere else. fmt
	// prints a func as an address under every verb and at every depth, so
	// no way of printing a Signer, or a struct holding one in any field,
	// reaches the key. A byte slice, even behind a pointer or a type with
	// a Format method, was reachable (by %d, a bad verb, or an unexported
	// field), which is what this rules out.
	sign func(msg []byte) []byte
}

// Format implements fmt.Formatter for every verb, %d and %x included, with the
// key's name and id only.
func (s Signer) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, s.String()) //nolint:errcheck // Format has no error to return; a failed write prints less, never the key
}

// Name is the key's name.
func (s *Signer) Name() string { return s.name }

// KeyHash is the key id.
func (s *Signer) KeyHash() uint32 { return s.id }

// Sign returns the Ed25519 signature of msg.
func (s *Signer) Sign(msg []byte) ([]byte, error) {
	return s.sign(msg), nil
}

// String keeps the private key out of %v and %+v (RS-07). It has a value
// receiver, so a Signer prints the same as a *Signer.
func (s Signer) String() string { return fmt.Sprintf("note.Signer(%s+%08x)", s.name, s.id) }

// GoString keeps the private key out of %#v (RS-07).
func (s Signer) GoString() string { return s.String() }

// NewSigner parses a signer key,
// `PRIVATE+KEY+<name>+<key_id hex>+<base64(0x01 || 32-byte seed)>` (SPEC §5.3).
// The key id must match the public key derived from the seed.
func NewSigner(skey string) (*Signer, error) {
	// A witness's key signs cosignatures only: as a note signer it would pass
	// for a log's key under another name (ADR-0021).
	name, id, priv, err := parseSignerKey(skey, algEd25519, "a note signer key is Ed25519 (0x01); use NewCosigner for a witness's")
	if err != nil {
		return nil, err
	}
	return &Signer{name: name, id: id, sign: func(msg []byte) []byte { return ed25519.Sign(priv, msg) }}, nil
}

// parseSignerKey parses `PRIVATE+KEY+<name>+<key_id hex>+<base64(alg || seed)>`
// for the one alg the caller accepts, wrongAlg saying why another is refused,
// and checks the key id against the key the seed derives.
func parseSignerKey(skey string, alg byte, wrongAlg string) (name string, id uint32, priv ed25519.PrivateKey, err error) {
	parts := strings.SplitN(skey, "+", 5)
	if len(parts) != 5 || parts[0] != "PRIVATE" || parts[1] != "KEY" {
		return "", 0, nil, fmt.Errorf("%w: a signer key is PRIVATE+KEY+<name>+<id>+<key>", ErrMalformed)
	}
	name, id, got, seed, err := parseKeyParts(parts[2], parts[3], parts[4])
	if err != nil {
		return "", 0, nil, err
	}
	if got != alg {
		return "", 0, nil, fmt.Errorf("%w: %s", ErrMalformed, wrongAlg)
	}
	if len(seed) != ed25519.SeedSize {
		return "", 0, nil, fmt.Errorf("%w: an Ed25519 seed is %d bytes", ErrMalformed, ed25519.SeedSize)
	}
	priv = ed25519.NewKeyFromSeed(seed)
	if keyID(name, alg, publicKey(priv)) != id {
		return "", 0, nil, fmt.Errorf("%w: the key id does not match the key", ErrMalformed)
	}
	return name, id, priv, nil
}

// publicKey is the public half of priv. An Ed25519 private key is its seed
// followed by its public key (crypto/ed25519, RFC 8032), so this is a copy of
// the last 32 bytes, with no type assertion that could fail.
func publicKey(priv ed25519.PrivateKey) ed25519.PublicKey {
	return ed25519.PublicKey(bytes.Clone(priv[ed25519.SeedSize:]))
}

// GenerateKey creates a key pair named name, with a seed read from rand, and
// returns it in SPEC §5.3's encodings.
func GenerateKey(rand io.Reader, name string) (skey, vkey string, err error) {
	if !validName(name) {
		return "", "", fmt.Errorf("%w: invalid key name", ErrMalformed)
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(rand, seed); err != nil {
		return "", "", fmt.Errorf("note: reading a seed: %w", err)
	}
	return encodeKeyPair(name, algEd25519, seed), encodeVerifier(name, algEd25519, seed), nil
}

// KeySigner is what Sign needs: a named key that signs. *Signer is one, and so
// is any tally.Signer, such as a KMS.
type KeySigner interface {
	Name() string
	KeyHash() uint32
	Sign(msg []byte) ([]byte, error)
}

// checkText applies SPEC §5.1's rules to a note's text, or to a whole note:
// valid UTF-8, and no control character other than '\n'.
func checkText(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for _, c := range b {
		if c < 0x20 && c != '\n' {
			return false
		}
	}
	return true
}

// Sign signs text with every signer and returns the note. text must end in
// '\n' and follow SPEC §5.1's rules.
func Sign(text []byte, signers ...KeySigner) ([]byte, error) {
	if len(text) == 0 || text[len(text)-1] != '\n' || !checkText(text) {
		return nil, fmt.Errorf("%w: a note's text is valid UTF-8 without controls and ends in a newline", ErrMalformed)
	}
	if len(signers) == 0 || len(signers) > MaxSignatures {
		return nil, fmt.Errorf("%w: a note has 1 to %d signatures", ErrMalformed, MaxSignatures)
	}
	var buf bytes.Buffer
	buf.Write(text)
	buf.WriteByte('\n')
	for _, s := range signers {
		if !validName(s.Name()) {
			return nil, fmt.Errorf("%w: invalid key name", ErrMalformed)
		}
		sig, err := s.Sign(text)
		if err != nil {
			return nil, fmt.Errorf("note: signing: %w", err)
		}
		if len(sig) != ed25519.SignatureSize {
			return nil, fmt.Errorf("note: the signer returned %d bytes, want %d", len(sig), ed25519.SignatureSize)
		}
		raw := binary.BigEndian.AppendUint32(nil, s.KeyHash())
		fmt.Fprintf(&buf, "%s%s %s\n", sigPrefix, s.Name(), base64.StdEncoding.EncodeToString(append(raw, sig...)))
	}
	if buf.Len() > MaxSize {
		return nil, fmt.Errorf("%w: the note would exceed %d bytes", ErrMalformed, MaxSize)
	}
	return buf.Bytes(), nil
}

// Note is an opened note: its text, the trusted log keys whose signatures
// verified, and the trusted witnesses whose cosignatures verified.
type Note struct {
	Text         []byte
	SignedBy     []*Verifier
	Cosignatures []Cosignature
}

type sigLine struct {
	name string
	id   uint32
	sig  []byte
}

// Open checks msg's envelope and signatures against the trusted keys, in
// SPEC §5.4's order:
//
//  1. the envelope parses and is within the limits, else ErrMalformed, or
//     ErrNonCanonical for base64 that decodes but is not canonical;
//  2. every signature from a trusted key verifies, else ErrBadSignature;
//  3. at least one does, else ErrUnknownKey.
//
// Signatures from keys not in trusted are ignored. On any error Open returns
// no text: it is untrusted until a trusted signature has verified.
func Open(msg []byte, trusted []*Verifier) (*Note, error) {
	text, lines, err := parseEnvelope(msg)
	if err != nil {
		return nil, err
	}

	// A key appears once however many of its lines verify: a line repeated
	// verbatim adds nothing (SPEC §5.4).
	var (
		signedBy []*Verifier
		cosigs   []Cosignature
	)
	for _, l := range lines {
		v := find(trusted, l.name, l.id)
		if v == nil {
			continue
		}
		if v.Witness() {
			at, ok := verifyCosignature(v, text, l.sig)
			if !ok {
				return nil, fmt.Errorf("%w: witness %s+%08x", ErrBadSignature, l.name, l.id)
			}
			if !cosignedBy(cosigs, v) {
				cosigs = append(cosigs, Cosignature{Witness: v, Time: at})
			}
			continue
		}
		if len(l.sig) != ed25519.SignatureSize || !ed25519.Verify(v.pub, text, l.sig) {
			return nil, fmt.Errorf("%w: key %s+%08x", ErrBadSignature, l.name, l.id)
		}
		if !contains(signedBy, v) {
			signedBy = append(signedBy, v)
		}
	}
	// A cosignature alone is not a signature of the note: a witness vouches
	// for consistency, never for the log's content (ADR-0021).
	if len(signedBy) == 0 {
		return nil, ErrUnknownKey
	}
	return &Note{Text: bytes.Clone(text), SignedBy: signedBy, Cosignatures: cosigs}, nil
}

// parseEnvelope is SPEC §5.4 step 1: everything decided before a key is looked
// up.
func parseEnvelope(msg []byte) ([]byte, []sigLine, error) {
	if len(msg) > MaxSize {
		return nil, nil, fmt.Errorf("%w: over %d bytes", ErrMalformed, MaxSize)
	}
	if !checkText(msg) {
		return nil, nil, fmt.Errorf("%w: not valid UTF-8, or holds a control character", ErrMalformed)
	}
	split := bytes.LastIndex(msg, []byte("\n\n"))
	if split < 0 {
		return nil, nil, fmt.Errorf("%w: no blank line before the signatures", ErrMalformed)
	}
	text, sigs := msg[:split+1], msg[split+2:]
	if len(sigs) == 0 || sigs[len(sigs)-1] != '\n' {
		return nil, nil, fmt.Errorf("%w: the signatures do not end in a newline", ErrMalformed)
	}
	raw := strings.Split(string(sigs[:len(sigs)-1]), "\n")
	if len(raw) > MaxSignatures {
		return nil, nil, fmt.Errorf("%w: more than %d signature lines", ErrMalformed, MaxSignatures)
	}
	lines := make([]sigLine, 0, len(raw))
	for _, line := range raw {
		rest, ok := strings.CutPrefix(line, sigPrefix)
		if !ok {
			return nil, nil, fmt.Errorf("%w: a signature line starts with an em dash and a space", ErrMalformed)
		}
		name, b64, ok := strings.Cut(rest, " ")
		if !ok || !validName(name) {
			return nil, nil, fmt.Errorf("%w: a signature line names a key", ErrMalformed)
		}
		sig, err := decode64(b64)
		if err != nil {
			return nil, nil, err
		}
		if len(sig) < 5 {
			return nil, nil, fmt.Errorf("%w: a signature is a key id and at least one byte", ErrMalformed)
		}
		lines = append(lines, sigLine{name: name, id: binary.BigEndian.Uint32(sig), sig: sig[4:]})
	}
	return text, lines, nil
}

func find(vs []*Verifier, name string, id uint32) *Verifier {
	for _, v := range vs {
		if v.name == name && v.id == id {
			return v
		}
	}
	return nil
}

func contains(vs []*Verifier, v *Verifier) bool {
	for _, w := range vs {
		if w == v {
			return true
		}
	}
	return false
}
