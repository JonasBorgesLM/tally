package tally_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/tallytest"
)

// A key from NewSigner signs checkpoints that verify under its verifier key,
// with its name as the log's origin.
func TestNewSignerSignsALog(t *testing.T) {
	ctx := context.Background()
	s, err := tally.NewSigner(tallytest.TestSignerKey)
	if err != nil {
		t.Fatal(err)
	}
	if s.Name() != "example.com/log" {
		t.Fatalf("Name = %q, want the key's name", s.Name())
	}
	mem := tallytest.NewMemStore()
	l, err := tally.Open(ctx, keepOpen{mem}, s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = l.Checkpoint(ctx); err != nil {
		t.Fatal(err)
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	keys, err := tally.NewVerifiers(tallytest.TestVerifierKey)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := tally.Verify(ctx, mem, keys, tally.WithRequireFullyAttested())
	if err != nil || !rep.OK() {
		t.Fatalf("Verify = %+v, %v", rep, err)
	}
}

// The private key is in no error and no formatted output (RS-07): not for a
// malformed key, and not for the Signer, alone or inside a struct.
//
// Seen failing with the error wrapping the key it was given.
func TestNewSignerNeverPrintsTheKey(t *testing.T) {
	secret := tallytest.TestSignerKey[strings.LastIndex(tallytest.TestSignerKey, "+")+1:]
	s, err := tally.NewSigner(tallytest.TestSignerKey)
	if err != nil {
		t.Fatal(err)
	}
	holder := struct {
		s     tally.Signer
		Field tally.Signer
	}{s, s}
	printed := 0
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d", "%x", "%q"} {
		for _, v := range []any{s, holder, &holder} {
			if out := fmt.Sprintf(verb, v); strings.Contains(out, secret) {
				t.Errorf("%s of %T prints the key: %s", verb, v, out)
			}
			printed++
		}
	}
	if printed != 21 {
		t.Fatalf("printed %d values, want 21", printed)
	}

	// The same key with its id altered: well-formed, and refused.
	bad := strings.Replace(tallytest.TestSignerKey, "+d455c521+", "+00000000+", 1)
	for _, k := range []string{bad, "PRIVATE+KEY+example.com/log+zz+" + secret, "not a key " + secret} {
		_, err := tally.NewSigner(k)
		if err == nil {
			t.Fatalf("NewSigner(%q) accepted a malformed key", k)
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("the error for a malformed key prints the key: %v", err)
		}
	}
}
