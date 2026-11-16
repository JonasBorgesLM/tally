// Package seal is tally's crypto-shredding (RF-11, ADR-0011): a vault that
// maps a person's identifier to a random SubjectRef and a per-subject key
// (DEK), so that only the ref enters the log and destroying the DEK makes the
// payloads sealed under it unreadable, without touching the chain.
//
// It is a mechanism, not compliance: whether a deployment conforms to the LGPD
// depends on the operator's process and legal counsel. A shredded ref still
// links its entries to one another, deleting a file on an SSD or a journaling
// filesystem does not destroy it, an old backup of the vault undoes a shred,
// and copies of a plaintext in the application's memory are out of reach. The
// README's "Personal data and crypto-shredding" states each limit, with a
// classification of every stored field, and the RUNBOOK the procedure.
package seal

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// KEK wraps and unwraps the vault's keys (ADR-0020). It is an interface so
// that it can be a KMS or an HSM, which never hands its key to this process;
// NewLocalKEK is the in-process implementation.
//
// ID names the key, stably: it is stored beside every blob the KEK wraps, so
// that a vault knows which KEK can unwrap it, during a rotation above all.
// Unwrap must fail for a blob, or an aad, that Wrap did not produce together.
type KEK interface {
	ID() string
	Wrap(ctx context.Context, key, aad []byte) ([]byte, error)
	Unwrap(ctx context.Context, wrapped, aad []byte) ([]byte, error)
}

// maxKEKID bounds a KEK's id, which is stored in every vault file.
const maxKEKID = 64

// ErrUnknownKEK means a vault file is wrapped under a KEK the vault was not
// given. During a rotation, both the old and the new KEK are needed.
var ErrUnknownKEK = errors.New("seal: a vault file is wrapped under a KEK that was not given")

// localKEK is AES-256-GCM in this process. Its key lives only inside the
// closures, so no fmt verb, at any depth, prints it (RS-07).
type localKEK struct {
	id     string
	wrap   func(rand io.Reader, key, aad []byte) ([]byte, error)
	unwrap func(wrapped, aad []byte) ([]byte, error)
}

// NewLocalKEK returns a KEK held in this process: AES-256-GCM under key, which
// must be 32 bytes, with a random 96-bit nonce per wrap. id names it; it must
// be valid UTF-8, printable, and at most 64 bytes. The caller should clear
// key after the call: the KEK keeps its own copy, and Go cannot promise to
// erase either.
func NewLocalKEK(id string, key []byte) (KEK, error) {
	if err := checkKEKID(id); err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("seal: a local KEK is 32 bytes, not %d", len(key))
	}
	block, err := aes.NewCipher(append([]byte(nil), key...))
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	return &localKEK{
		id: id,
		wrap: func(r io.Reader, k, aad []byte) ([]byte, error) {
			nonce := make([]byte, gcm.NonceSize())
			if _, err := io.ReadFull(r, nonce); err != nil {
				return nil, fmt.Errorf("seal: reading a nonce: %w", err)
			}
			return gcm.Seal(nonce, nonce, k, aad), nil
		},
		unwrap: func(w, aad []byte) ([]byte, error) {
			if len(w) < gcm.NonceSize()+gcm.Overhead() {
				return nil, errors.New("seal: a wrapped key is too short")
			}
			k, err := gcm.Open(nil, w[:gcm.NonceSize()], w[gcm.NonceSize():], aad)
			if err != nil {
				return nil, errors.New("seal: a wrapped key does not unwrap under this KEK")
			}
			return k, nil
		},
	}, nil
}

// ID returns the id the KEK was created with.
func (k *localKEK) ID() string { return k.id }

// Wrap seals key under the KEK, with a random nonce, bound to aad.
func (k *localKEK) Wrap(ctx context.Context, key, aad []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return k.wrap(rand.Reader, key, aad)
}

// Unwrap opens a blob Wrap produced with the same aad.
func (k *localKEK) Unwrap(ctx context.Context, wrapped, aad []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return k.unwrap(wrapped, aad)
}

// String keeps the key out of %v and %s (RS-07).
func (k *localKEK) String() string { return fmt.Sprintf("seal.LocalKEK(%s)", k.id) }

// checkKEKID refuses an id that is empty, too long, or holds what a terminal
// or a file format would trip on.
func checkKEKID(id string) error {
	if id == "" || len(id) > maxKEKID || !utf8.ValidString(id) {
		return fmt.Errorf("seal: a KEK id is 1 to %d bytes of UTF-8", maxKEKID)
	}
	for _, r := range id {
		if r < 0x21 || r == 0x7f {
			return errors.New("seal: a KEK id holds no space or control character")
		}
	}
	return nil
}
