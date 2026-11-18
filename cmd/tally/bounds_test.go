package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/tallytest"
)

// The files the CLI reads from the operator are bounded (RS-05, audit A-08):
// a --key-file over maxKeyFile and a --from over the checkpoint ceiling are
// refused, exit 2, before being read into memory.
//
// Seen failing with --from read by os.ReadFile, and --key-file likewise.
func TestOperatorFilesAreBounded(t *testing.T) {
	dir, _ := logAndAnchor(t)
	big := func(n int) string {
		p := filepath.Join(t.TempDir(), "big")
		if err := os.WriteFile(p, []byte(strings.Repeat("x", n)), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cases := map[string][]string{
		"--key-file": {"verify", "--dir", dir, "--key-file", big(maxKeyFile + 1)},
		"--from": {"verify", "--dir", dir, "--key", tallytest.TestVerifierKey,
			"--from", big(tally.MaxCheckpointLen + 1)},
	}
	for name, args := range cases {
		_, stderr, code := cli(t, args...)
		if code != exitError || !strings.Contains(stderr, " is over ") {
			t.Errorf("%s over its bound: status %d, stderr %q; want %d naming the bound", name, code, stderr, exitError)
		}
	}
}
