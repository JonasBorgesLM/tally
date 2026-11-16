package tally

import (
	"fmt"

	"github.com/JonasBorgesLM/tally/internal/note"
)

// NewSigner parses a signer key as tally keygen writes it,
// `PRIVATE+KEY+<name>+<key_id hex>+<base64(0x01 || 32-byte seed)>` (SPEC §5.3),
// and returns a Signer holding it in memory. Its Name, the key's name, is the
// log's origin for the log's whole life (ADR-0005).
//
// The key is held only inside a closure: it appears in no error, and no fmt
// verb prints it, on the Signer or on a struct holding one (RS-07). Keep the
// key a log signs with apart from every other system's keys (RS-06). A key
// held by a separate process or a KMS implements Signer itself instead.
func NewSigner(skey string) (Signer, error) {
	s, err := note.NewSigner(skey)
	if err != nil {
		return nil, fmt.Errorf("tally: signer key: %w", err)
	}
	return s, nil
}
