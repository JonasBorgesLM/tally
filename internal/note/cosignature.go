package note

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"strconv"
	"time"
)

// Witness cosignatures, c2sp.org/tlog-cosignature's cosignature/v1 over
// Ed25519 (signed-note type 0x04), for #61 (ADR-0021).
//
// The signed message is "cosignature/v1\ntime <unix seconds>\n" followed by
// the checkpoint's text; the signature bytes after the key id are the time
// as 8 bytes big-endian, then the 64-byte Ed25519 signature. A cosignature
// says the witness saw this checkpoint consistent with every other it
// cosigned for the log, as the largest so far, at that time.

const cosignatureSize = 8 + ed25519.SignatureSize

// Cosignature is a witness's verified cosignature of a note.
type Cosignature struct {
	Witness *Verifier
	// Time is the witness's claim of when it cosigned, in Unix seconds.
	Time int64
}

// cosignatureMessage is what a witness signs over a note's text.
func cosignatureMessage(text []byte, at uint64) []byte {
	return append([]byte("cosignature/v1\ntime "+strconv.FormatUint(at, 10)+"\n"), text...)
}

// verifyCosignature checks sig, the bytes after the key id, as v's
// cosignature of text.
func verifyCosignature(v *Verifier, text, sig []byte) (int64, bool) {
	if len(sig) != cosignatureSize {
		return 0, false
	}
	at := binary.BigEndian.Uint64(sig[:8])
	if at > math.MaxInt64 {
		return 0, false
	}
	if !ed25519.Verify(v.pub, cosignatureMessage(text, at), sig[8:]) {
		return 0, false
	}
	return int64(at), true
}

func cosignedBy(cs []Cosignature, v *Verifier) bool {
	for _, c := range cs {
		if c.Witness == v {
			return true
		}
	}
	return false
}

// Cosigner is a witness's private key. As Signer, no fmt verb prints the key
// (RS-07): it lives only in a closure.
type Cosigner struct {
	name string
	id   uint32
	sign func(msg []byte) []byte
}

// Format implements fmt.Formatter for every verb with the key's name and id
// only.
func (c Cosigner) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, c.String()) //nolint:errcheck // Format has no error to return; a failed write prints less, never the key
}

// String keeps the private key out of %v and %+v (RS-07).
func (c Cosigner) String() string { return fmt.Sprintf("note.Cosigner(%s+%08x)", c.name, c.id) }

// GoString keeps the private key out of %#v (RS-07).
func (c Cosigner) GoString() string { return c.String() }

// Name is the witness's name.
func (c *Cosigner) Name() string { return c.name }

// NewCosigner parses a witness's signer key,
// `PRIVATE+KEY+<name>+<key_id hex>+<base64(0x04 || 32-byte seed)>`.
func NewCosigner(skey string) (*Cosigner, error) {
	name, id, priv, err := parseSignerKey(skey, algCosignatureV1, "a witness's key is an Ed25519 cosignature/v1 key (0x04)")
	if err != nil {
		return nil, err
	}
	return &Cosigner{name: name, id: id, sign: func(msg []byte) []byte { return ed25519.Sign(priv, msg) }}, nil
}

// GenerateCosignerKey creates a witness's key pair named name, with a seed
// read from rand.
func GenerateCosignerKey(rand io.Reader, name string) (skey, vkey string, err error) {
	if !validName(name) {
		return "", "", fmt.Errorf("%w: invalid key name", ErrMalformed)
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(rand, seed); err != nil {
		return "", "", fmt.Errorf("note: reading a seed: %w", err)
	}
	return encodeKeyPair(name, algCosignatureV1, seed), encodeVerifier(name, algCosignatureV1, seed), nil
}

// Cosign returns c's cosignature line over text at time at, `— <name>
// <base64(key id || time || signature)>\n`, to append to the note. text must
// follow SPEC §5.1's rules and end in '\n'.
func Cosign(text []byte, c *Cosigner, at time.Time) (string, error) {
	if len(text) == 0 || text[len(text)-1] != '\n' || !checkText(text) {
		return "", fmt.Errorf("%w: a note's text is valid UTF-8 without controls and ends in a newline", ErrMalformed)
	}
	sec := at.Unix()
	if sec < 0 {
		return "", fmt.Errorf("%w: a cosignature's time is after the epoch", ErrMalformed)
	}
	raw := binary.BigEndian.AppendUint32(nil, c.id)
	raw = binary.BigEndian.AppendUint64(raw, uint64(sec))
	raw = append(raw, c.sign(cosignatureMessage(text, uint64(sec)))...)
	return sigPrefix + c.name + " " + base64.StdEncoding.EncodeToString(raw) + "\n", nil
}

// encodeKeyPair and encodeVerifier are SPEC §5.3's encodings of a seed's keys.
func encodeKeyPair(name string, alg byte, seed []byte) string {
	pub := publicKey(ed25519.NewKeyFromSeed(seed))
	return fmt.Sprintf("PRIVATE+KEY+%s+%08x+%s", name, keyID(name, alg, pub),
		base64.StdEncoding.EncodeToString(append([]byte{alg}, seed...)))
}

func encodeVerifier(name string, alg byte, seed []byte) string {
	pub := publicKey(ed25519.NewKeyFromSeed(seed))
	return fmt.Sprintf("%s+%08x+%s", name, keyID(name, alg, pub),
		base64.StdEncoding.EncodeToString(append([]byte{alg}, pub...)))
}
