package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/internal/note"
	"github.com/JonasBorgesLM/tally/tallytest"
)

// keygen writes a working key pair, the private key at 0600, and the private
// key appears in no output: only in its file (RS-07).
//
// Seen failing with the private key added to keygen's output.
func TestKeygen(t *testing.T) {
	out := filepath.Join(t.TempDir(), "log")
	stdout, stderr, code := cli(t, "keygen", "--name", "example.com/log", "--out", out)
	if code != exitIntact {
		t.Fatalf("status %d\n%s", code, stderr)
	}
	skeyRaw, err := os.ReadFile(out + ".key") // #nosec G304 -- a test's own file
	if err != nil {
		t.Fatal(err)
	}
	vkeyRaw, err := os.ReadFile(out + ".pub") // #nosec G304 -- a test's own file
	if err != nil {
		t.Fatal(err)
	}
	skey, vkey := strings.TrimSpace(string(skeyRaw)), strings.TrimSpace(string(vkeyRaw))
	for path, want := range map[string]os.FileMode{out + ".key": 0o600, out + ".pub": 0o644} {
		if fi, serr := os.Stat(path); serr != nil || fi.Mode().Perm() != want {
			t.Errorf("%s mode %v, %v; want %v", path, fi.Mode().Perm(), serr, want)
		}
	}

	// The private key, and its seed alone, appear in no output.
	seed := skey[strings.LastIndexByte(skey, '+')+1:]
	for _, s := range []string{stdout, stderr} {
		if strings.Contains(s, skey) || strings.Contains(s, seed) {
			t.Fatalf("the private key reached the output:\n%s", s)
		}
	}
	if !strings.Contains(stdout, vkey) {
		t.Errorf("the verifier key is not printed:\n%s", stdout)
	}

	// The pair works: a log signed with the key verifies under the verifier
	// key.
	signer, err := note.NewSigner(skey)
	if err != nil {
		t.Fatal(err)
	}
	l, err := tally.Open(context.Background(), tallytest.NewMemStore(), signer, tally.WithCheckpointEvery(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	if _, err = l.Append(context.Background(), event("a")); err != nil {
		t.Fatal(err)
	}
	cp, err := l.Checkpoint(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	keys, err := tally.NewVerifiers(vkey)
	if err != nil {
		t.Fatal(err)
	}
	if err := tally.VerifyCheckpoint(cp, keys); err != nil {
		t.Fatalf("a checkpoint signed with the generated key does not verify: %v", err)
	}
}

// keygen refuses to overwrite an existing key, private or public, and then
// writes nothing.
//
// Seen failing with both the existence check and O_EXCL removed: the
// existing key is then replaced.
func TestKeygenNeverOverwrites(t *testing.T) {
	for _, existing := range []string{".key", ".pub"} {
		t.Run(existing, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "log")
			if err := os.WriteFile(out+existing, []byte("a key in use\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			_, stderr, code := cli(t, "keygen", "--name", "example.com/log", "--out", out)
			if code != exitError || !strings.Contains(stderr, "never overwrites") {
				t.Fatalf("status %d, stderr:\n%s", code, stderr)
			}
			if got, _ := os.ReadFile(out + existing); string(got) != "a key in use\n" { // #nosec G304 -- a test's own file
				t.Errorf("the existing %s was changed to %q", existing, got)
			}
			other := map[string]string{".key": ".pub", ".pub": ".key"}[existing]
			if _, err := os.Stat(out + other); !os.IsNotExist(err) {
				t.Errorf("keygen wrote %s beside an existing %s", other, existing)
			}
		})
	}
}

// An invalid name is refused before anything is written.
func TestKeygenRefusesAnInvalidName(t *testing.T) {
	out := filepath.Join(t.TempDir(), "log")
	if _, _, code := cli(t, "keygen", "--name", "has space", "--out", out); code != exitError {
		t.Fatalf("status %d, want 2", code)
	}
	if entries, _ := os.ReadDir(filepath.Dir(out)); len(entries) != 0 {
		t.Errorf("files written for an invalid name: %v", entries)
	}
}
