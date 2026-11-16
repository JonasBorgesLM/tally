package seal

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"io/fs"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/internal/wire"
)

// Vault maps identifiers to refs and seals payloads under each ref's DEK
// (RF-11). FileVault is one. Shred joins it with #45.
type Vault interface {
	// Resolve returns the identifier's ref, creating it on first use.
	Resolve(ctx context.Context, identifier []byte) (tally.SubjectRef, error)
	// Seal encrypts plaintext under ref's DEK, bound to aad, in SPEC §4's
	// payload format. A shredded ref is tally.ErrShredded.
	Seal(ctx context.Context, ref tally.SubjectRef, plaintext, aad []byte) ([]byte, error)
	// Open decrypts a payload Seal produced with the same ref and aad. A
	// shredded ref is tally.ErrShredded; any other mismatch is ErrOpen.
	Open(ctx context.Context, ref tally.SubjectRef, sealed, aad []byte) ([]byte, error)
}

var _ Vault = (*FileVault)(nil)

// ErrOpen means a sealed payload does not open: it was sealed under another
// DEK or AAD, or it was altered. It says no more than that, on purpose.
var ErrOpen = errors.New("seal: the payload does not open under this ref and AAD")

// SPEC §4's payload: a format byte, a 96-bit nonce, and the ciphertext with
// its 128-bit tag.
const (
	sealFormat   = 0x01
	nonceLen     = 12
	tagLen       = 16
	minSealedLen = 1 + nonceLen + tagLen
	aadTag       = "tally/v1/seal"
	maxEventID   = 128 // SPEC §6's event_id ceiling
)

// AAD is SPEC §4's additional data for a payload: the tag, log_id, event_id
// and subject_ref, each length-prefixed in SPEC §1's encoding, so that no
// boundary between event_id and subject_ref can shift (RS-19). seq is absent:
// sealing runs on the caller's goroutine, before seq exists.
func AAD(log tally.LogID, ev tally.EventID, ref tally.SubjectRef) ([]byte, error) {
	return aad(log[:], []byte(ev), ref[:])
}

func aad(log, ev, ref []byte) ([]byte, error) {
	var e wire.Encoder
	e.String(aadTag, 64)
	e.Fixed(log)
	e.Bytes(ev, maxEventID)
	e.Bytes(ref, 16)
	b, err := e.Result()
	if err != nil {
		return nil, fmt.Errorf("seal: the AAD: %w", err)
	}
	return b, nil
}

// Payload seals plaintext for the entry ev of log, under ref's DEK, and
// returns it as a tally.Payload to put in an Event (RS-12, RS-19). It runs on
// the caller's goroutine, before Append.
func Payload(ctx context.Context, v Vault, log tally.LogID, ev tally.EventID, ref tally.SubjectRef, plaintext []byte) (tally.Payload, error) {
	a, err := AAD(log, ev, ref)
	if err != nil {
		return tally.Payload{}, err
	}
	sealed, err := v.Seal(ctx, ref, plaintext, a)
	if err != nil {
		return tally.Payload{}, err
	}
	return tally.Sealed(ref, sealed), nil
}

// Seal encrypts plaintext under ref's DEK with AES-256-GCM and a random 96-bit
// nonce, bound to aad (RS-12). A ref whose DEK is gone is tally.ErrShredded.
func (v *FileVault) Seal(ctx context.Context, ref tally.SubjectRef, plaintext, aad []byte) ([]byte, error) {
	dek, err := v.lockedDEK(ctx, ref)
	if err != nil {
		return nil, err
	}
	defer clear(dek)
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(v.rand, nonce); err != nil {
		return nil, fmt.Errorf("seal: reading a nonce: %w", err)
	}
	return sealWith(dek, nonce, plaintext, aad)
}

// Open decrypts a payload Seal produced under ref with the same aad. A ref
// whose DEK is gone is tally.ErrShredded; a payload sealed under anything
// else, or altered, is ErrOpen.
func (v *FileVault) Open(ctx context.Context, ref tally.SubjectRef, sealed, aad []byte) ([]byte, error) {
	if len(sealed) < minSealedLen || sealed[0] != sealFormat {
		return nil, fmt.Errorf("%w: not SPEC §4's payload format", ErrOpen)
	}
	dek, err := v.lockedDEK(ctx, ref)
	if err != nil {
		return nil, err
	}
	defer clear(dek)
	gcm, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, sealed[1:1+nonceLen], sealed[1+nonceLen:], aad)
	if err != nil {
		return nil, ErrOpen
	}
	return plain, nil
}

// lockedDEK unwraps ref's DEK under the vault's lock, mapping a missing DEK
// to tally.ErrShredded.
func (v *FileVault) lockedDEK(ctx context.Context, ref tally.SubjectRef) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return nil, tally.ErrClosed
	}
	dek, err := v.dek(ctx, ref)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, tally.ErrShredded
	}
	return dek, err
}

// sealWith is SPEC §4 with the DEK and nonce given: what the published
// vectors check.
func sealWith(dek, nonce, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, minSealedLen+len(plaintext))
	out = append(out, sealFormat)
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, plaintext, aad), nil
}

func newGCM(dek []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	return gcm, nil
}
