package main

import (
	"strings"
	"testing"
)

// `tally version` prints the version the release workflow embedded, so an
// auditor knows which release vouches for the binary (ADR-0014); a binary
// built otherwise says what its build recorded instead.
func TestVersion(t *testing.T) {
	saved := version
	defer func() { version = saved }()

	version = "v9.8.7"
	var out, errOut strings.Builder
	if code := run(t.Context(), []string{"version"}, &out, &errOut); code != exitIntact || out.String() != "tally v9.8.7\n" {
		t.Fatalf("version = %d %q %q, want the embedded version", code, out.String(), errOut.String())
	}

	version = ""
	out.Reset()
	if code := run(t.Context(), []string{"version"}, &out, &errOut); code != exitIntact || !strings.HasPrefix(out.String(), "tally ") || len(out.String()) < len("tally x\n") {
		t.Fatalf("version without an embedded one = %d %q", code, out.String())
	}

	if code := run(t.Context(), []string{"version", "extra"}, &out, &errOut); code != exitError {
		t.Fatalf("version with an argument = %d, want %d", code, exitError)
	}
}
