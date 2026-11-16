package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/anchor"
	"github.com/JonasBorgesLM/tally/filestore"
	"github.com/JonasBorgesLM/tally/internal/note"
	"github.com/JonasBorgesLM/tally/tallytest"
)

// TestMain runs the real main when the test binary is started as the CLI, so
// exit statuses are tested through a process, as an auditor's script sees
// them.
func TestMain(m *testing.M) {
	if os.Getenv("TALLY_RUN_CLI") == "1" {
		main()
		return
	}
	os.Exit(m.Run())
}

// cli runs the CLI as a process and returns its output and exit status.
func cli(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), exe, args...) // #nosec G204 -- the test binary itself
	cmd.Env = append(os.Environ(), "TALLY_RUN_CLI=1")
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err = cmd.Run()
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		code = exit.ExitCode()
	case err != nil:
		t.Fatal(err)
	}
	return out.String(), errOut.String(), code
}

func signer(t *testing.T) tally.Signer {
	t.Helper()
	s, err := note.NewSigner(tallytest.TestSignerKey)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func event(id string) tally.Event {
	return tally.Event{ID: tally.EventID(id), OccurredAt: time.Unix(1_700_000_000, 0),
		Actor: tally.System(), Action: "user.login", Outcome: tally.OutcomeSuccess}
}

// dropCheckpoints stores no checkpoint, so every entry stays unattested.
type dropCheckpoints struct{ *filestore.Store }

func (dropCheckpoints) PutCheckpoint(context.Context, tally.SignedCheckpoint) error { return nil }

// writeLog appends n entries to the log in dir, publishing to the anchor in
// anchorDir if it is not empty, and closes it. With checkpoints false it
// stores none.
func writeLog(t *testing.T, dir, anchorDir, prefix string, n int, checkpoints bool) {
	t.Helper()
	ctx := context.Background()
	// Small segments, so that a log of a few entries has some to prune.
	s, err := filestore.Open(ctx, dir, filestore.WithSegmentSize(400))
	if err != nil {
		t.Fatal(err)
	}
	var store tally.Store = s
	if !checkpoints {
		store = dropCheckpoints{s}
	}
	opts := []tally.Option{tally.WithCheckpointEvery(3, 0)}
	if anchorDir != "" {
		a, aerr := anchor.NewDir(anchorDir)
		if aerr != nil {
			t.Fatal(aerr)
		}
		opts = append(opts, tally.WithAnchors(a))
	}
	l, err := tally.Open(ctx, store, signer(t), opts...)
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		if _, err := l.Append(ctx, event(fmt.Sprintf("%s-%d", prefix, i))); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}

func logAndAnchor(t *testing.T) (dir, anchorDir string) {
	t.Helper()
	root := t.TempDir()
	dir, anchorDir = filepath.Join(root, "log"), filepath.Join(root, "anchor")
	writeLog(t, dir, anchorDir, "a", 5, true)
	return dir, anchorDir
}

// otherVerifierKey is a valid key under the log's name that signed nothing.
func otherVerifierKey(t *testing.T) string {
	t.Helper()
	_, vkey, err := note.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{9}, 32)), "example.com/log")
	if err != nil {
		t.Fatal(err)
	}
	return vkey
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return lines[len(lines)-1]
}

// The exit status is a contract: 0 intact, 1 violation, 2 usage or IO error
// (RF-13). Tested through the built binary. A missing --anchor is an error,
// never created: a mistyped path must not read as an empty anchor.
//
// Seen failing with printReport always returning 0, and with the existence
// check on --anchor removed.
func TestVerifyExitStatus(t *testing.T) {
	dir, _ := logAndAnchor(t)
	key := tallytest.TestVerifierKey
	otherKey := otherVerifierKey(t)

	tampered := t.TempDir()
	if err := os.CopyFS(tampered, os.DirFS(dir)); err != nil {
		t.Fatal(err)
	}
	seg := filepath.Join(tampered, "0000000000000000.tlog")
	b, err := os.ReadFile(seg) // #nosec G304 -- a test's own file
	if err != nil {
		t.Fatal(err)
	}
	b[100] ^= 1
	if err := os.WriteFile(seg, b, 0o600); err != nil { // #nosec G703 -- a test's own file
		t.Fatal(err)
	}

	cases := []struct {
		name string
		args []string
		code int
		out  string // in stdout, or stderr for status 2
	}{
		{"intact", []string{"verify", "--dir", dir, "--key", key}, exitIntact, "result intact"},
		{"tampered", []string{"verify", "--dir", tampered, "--key", key}, exitViolation, "violation MalformedRecord"},
		{"an untrusted key", []string{"verify", "--dir", dir, "--key", otherKey}, exitViolation, "violation"},
		{"a missing directory", []string{"verify", "--dir", filepath.Join(dir, "nope"), "--key", key}, exitError, "no such file"},
		{"a missing anchor", []string{"verify", "--dir", dir, "--key", key, "--anchor", filepath.Join(dir, "no-anchor")}, exitError, "no such file"},
		{"no --dir", []string{"verify", "--key", key}, exitError, "--dir is required"},
		{"no key", []string{"verify", "--dir", dir}, exitError, "no verifier key"},
		{"an unknown flag", []string{"verify", "--dir", dir, "--key", key, "--nope"}, exitError, "flag provided but not defined"},
		{"an unknown command", []string{"frobnicate"}, exitError, "unknown command"},
		{"no command", nil, exitError, "usage:"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stdout, stderr, code := cli(t, c.args...)
			if code != c.code {
				t.Fatalf("status %d, want %d\nstdout:\n%s\nstderr:\n%s", code, c.code, stdout, stderr)
			}
			where := stdout
			if c.code == exitError {
				where = stderr
			}
			if !strings.Contains(where, c.out) {
				t.Errorf("output lacks %q:\nstdout:\n%s\nstderr:\n%s", c.out, stdout, stderr)
			}
			if _, err := os.Stat(filepath.Join(dir, "no-anchor")); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("the CLI created the missing anchor directory: %v", err)
			}
		})
	}
}

// verify prints the attested size and the unattested count (RF-18), and
// --require-fully-attested turns an unattested tail into a violation.
func TestVerifyPrintsAttestationAndRequiresIt(t *testing.T) {
	dir, _ := logAndAnchor(t)
	stdout, _, code := cli(t, "verify", "--dir", dir, "--key", tallytest.TestVerifierKey)
	if code != exitIntact || !strings.Contains(stdout, "size 6\n") || !strings.Contains(stdout, "attested 6\n") ||
		!strings.Contains(stdout, "unattested 0\n") {
		t.Fatalf("status %d, output:\n%s", code, stdout)
	}

	bare := filepath.Join(t.TempDir(), "log")
	writeLog(t, bare, "", "a", 4, false)
	stdout, _, code = cli(t, "verify", "--dir", bare, "--key", tallytest.TestVerifierKey)
	if code != exitIntact || !strings.Contains(stdout, "attested 0\n") || !strings.Contains(stdout, "unattested 5\n") {
		t.Fatalf("without the requirement: status %d, output:\n%s", code, stdout)
	}
	stdout, _, code = cli(t, "verify", "--dir", bare, "--key", tallytest.TestVerifierKey, "--require-fully-attested")
	if code != exitViolation || !strings.Contains(stdout, "violation UnattestedTail") {
		t.Fatalf("with --require-fully-attested: status %d, output:\n%s", code, stdout)
	}
}

// --anchor end to end: a host that rolls its log back to an older,
// self-consistent state passes verification on its own word, and fails
// against the anchor (T-08, RF-09).
func TestVerifyAgainstTheAnchorCatchesARollback(t *testing.T) {
	root := t.TempDir()
	dir, anchorDir, snapshot := filepath.Join(root, "log"), filepath.Join(root, "anchor"), filepath.Join(root, "old")
	writeLog(t, dir, anchorDir, "a", 3, true)
	if err := os.CopyFS(snapshot, os.DirFS(dir)); err != nil {
		t.Fatal(err)
	}
	writeLog(t, dir, anchorDir, "b", 3, true) // the anchor now holds a larger checkpoint

	// The rollback: the host puts the old directory back.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(snapshot, dir); err != nil {
		t.Fatal(err)
	}

	stdout, _, code := cli(t, "verify", "--dir", dir, "--key", tallytest.TestVerifierKey)
	if code != exitIntact {
		t.Fatalf("on the host's word alone: status %d, want 0 (the rollback is self-consistent)\n%s", code, stdout)
	}
	stdout, _, code = cli(t, "verify", "--dir", dir, "--key", tallytest.TestVerifierKey, "--anchor", anchorDir)
	if code != exitViolation || !strings.Contains(stdout, "violation TruncatedBelowCheckpoint") {
		t.Fatalf("against the anchor: status %d, output:\n%s", code, stdout)
	}
}

// head prints the size and the last leaf hash, unverified; a malformed log is
// status 1.
func TestHead(t *testing.T) {
	dir, _ := logAndAnchor(t)
	r, err := filestore.OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	var last tally.Record
	for rec, err := range r.Records(context.Background(), 0) {
		if err != nil {
			t.Fatal(err)
		}
		last = rec
	}
	leaf := tally.LeafHash(last.Body)
	stdout, _, code := cli(t, "head", "--dir", dir)
	want := fmt.Sprintf("size 6\nhead %s\n", base64.StdEncoding.EncodeToString(leaf[:]))
	if code != exitIntact || !strings.HasPrefix(stdout, want) || !strings.Contains(stdout, "unverified") {
		t.Fatalf("status %d, output:\n%s\nwant it to start with:\n%s", code, stdout, want)
	}

	seg := filepath.Join(dir, "0000000000000000.tlog")
	b, err := os.ReadFile(seg) // #nosec G304 -- a test's own file
	if err != nil {
		t.Fatal(err)
	}
	b[0] ^= 1
	if err := os.WriteFile(seg, b, 0o600); err != nil { // #nosec G703 -- a test's own file
		t.Fatal(err)
	}
	if _, stderr, code := cli(t, "head", "--dir", dir); code != exitViolation || !strings.Contains(stderr, "malformed") {
		t.Fatalf("a malformed log: status %d, stderr:\n%s", code, stderr)
	}
}

// checkpoint prints the newest stored checkpoint that verifies, byte for
// byte; none verifying is status 1, none stored is 2.
func TestCheckpoint(t *testing.T) {
	dir, _ := logAndAnchor(t)
	r, err := filestore.OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	var newest tally.SignedCheckpoint
	for cp, err := range r.Checkpoints(context.Background()) {
		if err != nil {
			t.Fatal(err)
		}
		newest = cp
	}
	stdout, _, code := cli(t, "checkpoint", "--dir", dir, "--key", tallytest.TestVerifierKey)
	if code != exitIntact || stdout != string(newest) {
		t.Fatalf("status %d, output:\n%q\nwant the newest checkpoint:\n%q", code, stdout, newest)
	}

	otherKey := otherVerifierKey(t)
	if _, _, code := cli(t, "checkpoint", "--dir", dir, "--key", otherKey); code != exitViolation {
		t.Errorf("no checkpoint verifying: status %d, want 1", code)
	}
	bare := filepath.Join(t.TempDir(), "log")
	writeLog(t, bare, "", "a", 2, false)
	if _, _, code := cli(t, "checkpoint", "--dir", bare, "--key", tallytest.TestVerifierKey); code != exitError {
		t.Errorf("no checkpoint stored: status %d, want 2", code)
	}
}

// Control bytes, ANSI sequences, bidi overrides, line breaks and invalid
// UTF-8 are escaped; printable text is unchanged (RS-13, T-17).
//
// Seen failing with the escape of non-graphic runes removed.
func TestSanitize(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain text, ação — ok", "plain text, ação — ok"},
		{"red \x1b[31mALERT\x1b[0m", `red \x1b[31mALERT\x1b[0m`},
		{"two\nlines\r", `two\x0alines\x0d`},
		{"nul\x00 del\x7f", `nul\x00 del\x7f`},
		{"c1 \u0085 bidi \u202egnp.exe", `c1 \u0085 bidi \u202egnp.exe`},
		{"bad \xff utf8", `bad \xff utf8`},
		{`a \x1b already`, `a \\x1b already`},
	}
	for _, c := range cases {
		if got := sanitize(c.in); got != c.want {
			t.Errorf("sanitize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// A newline in a log-derived field cannot forge a line of output: a note
// carrying "\nresult intact" stays on its violation's line, and the verdict
// is the report's own (RS-13, T-17).
//
// Seen failing with the sanitize calls removed from printReport: the forged
// "result intact" line then appears before the real verdict.
func TestAFieldCannotForgeALine(t *testing.T) {
	rep := &tally.Report{Size: 3, Failures: []tally.Failure{{
		Kind: tally.MalformedRecord, Seq: 2, Note: "bad frame\nresult intact\n\x1b[2Kok",
	}}}
	var out bytes.Buffer
	if code := printReport(&out, rep); code != exitViolation {
		t.Fatalf("status %d, want 1", code)
	}
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 5 {
		t.Fatalf("%d lines, want 5:\n%s", len(lines), out.String())
	}
	for _, l := range lines[:4] {
		if strings.HasPrefix(l, "result") {
			t.Errorf("a forged verdict line: %q", l)
		}
		if strings.ContainsRune(l, '\x1b') {
			t.Errorf("an escape sequence reached the output: %q", l)
		}
	}
	if lastLine(out.String()) != "result violated (1)" {
		t.Errorf("verdict %q", lastLine(out.String()))
	}
}
