package main

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/anchor"
	"github.com/JonasBorgesLM/tally/internal/note"
	"github.com/JonasBorgesLM/tally/tallytest"
	"github.com/JonasBorgesLM/tally/witness"
)

// witnessServer serves a real witness for the test log over HTTP, and returns
// its URL and verifier key.
func witnessServer(t *testing.T) (url, wvk string) {
	t.Helper()
	state := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	wsk, wvk, err := note.GenerateCosignerKey(strings.NewReader(strings.Repeat("w", 32)), "witness.example")
	if err != nil {
		t.Fatal(err)
	}
	w, err := witness.New(state, wsk, []string{tallytest.TestVerifierKey})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(w)
	t.Cleanup(srv.Close)
	return srv.URL, wvk
}

// copyLog copies a log directory, as a snapshot root on the host can restore.
func copyLog(t *testing.T, src string) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "log")
	copyDir(t, src, dst)
	return dst
}

// tally witness push, end to end: the first push, a second after more
// entries with a consistency proof, and the anchor holding cosigned
// checkpoints that make the log verify witnessed. A rollback below what the
// witness cosigned, and a prune that left it behind, are refused, status 1.
func TestWitnessPush(t *testing.T) {
	url, wvk := witnessServer(t)
	root := t.TempDir()
	dir, spool := filepath.Join(root, "log"), filepath.Join(root, "spool")
	if err := os.Mkdir(spool, 0o700); err != nil {
		t.Fatal(err)
	}
	key := tallytest.TestVerifierKey
	push := func(logDir string) (string, string, int) {
		return cli(t, "witness", "push", "--dir", logDir, "--key", key, "--witness", url, "--witness-key", wvk, "--anchor", spool)
	}

	writeLog(t, dir, spool, "a", 4, true)
	snapshot := copyLog(t, dir)
	if out, stderr, code := push(dir); code != exitIntact || !strings.HasPrefix(out, "witnessed ") {
		t.Fatalf("first push: %d\n%s%s", code, out, stderr)
	}
	writeLog(t, dir, spool, "b", 5, true)
	out, stderr, code := push(dir)
	if code != exitIntact {
		t.Fatalf("second push: %d\n%s%s", code, out, stderr)
	}
	verified, stderr, code := cli(t, "verify", "--dir", dir, "--key", key, "--anchor", spool,
		"--witness", wvk, "--require-witnessed")
	if code != exitIntact || line(t, verified, "witnessed") != line(t, verified, "size") {
		t.Fatalf("verify, requiring the witness: %d\n%s%s", code, verified, stderr)
	}

	// Root on the host restores the snapshot and pushes: the witness has
	// cosigned more than this log holds.
	if _, stderr, code := push(snapshot); code != exitViolation || !strings.Contains(stderr, "rolled back") {
		t.Fatalf("a rolled-back log: %d\n%s", code, stderr)
	}
}

// A prune past the size the witness holds leaves no proof that reaches it:
// the push refuses and says why, status 1, and the witness is not moved.
//
// Negative control: with consistencyProof ignoring the pruned start, the push
// failed with status 2 and an internal error instead of saying why. Verified
// by hand, restored before committing.
func TestWitnessPushAfterAPruneThatLeftItBehind(t *testing.T) {
	url, wvk := witnessServer(t)
	root := t.TempDir()
	dir, spool := filepath.Join(root, "log"), filepath.Join(root, "spool")
	if err := os.Mkdir(spool, 0o700); err != nil {
		t.Fatal(err)
	}
	key := tallytest.TestVerifierKey
	push := func() (string, string, int) {
		return cli(t, "witness", "push", "--dir", dir, "--key", key, "--witness", url, "--witness-key", wvk, "--anchor", spool)
	}

	writeLog(t, dir, spool, "a", 3, true)
	if out, stderr, code := push(); code != exitIntact || line(t, out, "witnessed") != "4" {
		t.Fatalf("the witness's first look: %d\n%s%s", code, out, stderr)
	}
	writeLog(t, dir, spool, "b", 20, true)

	// Prune at the newest heartbeat note the spool holds.
	a, err := anchor.NewDir(spool)
	if err != nil {
		t.Fatal(err)
	}
	var newest tally.SignedCheckpoint
	for cp, err := range a.Checkpoints(context.Background()) {
		if err != nil {
			t.Fatal(err)
		}
		if !isTlog(cp) && strings.Contains(string(cp), "\ntally-heartbeat/v1\n") {
			newest = cp
		}
	}
	if _, stderr, code := cli(t, "prune", "--dir", dir, "--key", key, "--anchor", spool,
		"--checkpoint", writeCheckpoint(t, newest)); code != exitIntact {
		t.Fatalf("prune: %d\n%s", code, stderr)
	}
	out, stderr, code := push()
	if code != exitViolation || !strings.Contains(stderr, "prune left it behind") {
		t.Fatalf("a push the prune left behind: %d\n%s%s", code, out, stderr)
	}
}

// tally prune --witness-key refuses a prune above what the witness cosigned
// in the anchor, which would leave it no proof to follow (ADR-0021, audit
// A2-05), and removes nothing; at a size the witness cosigned, it prunes.
//
// Negative control: with the size check removed, the prune above the witness
// ran, status 0. Verified by hand, restored before committing.
func TestPruneRefusesAboveTheWitness(t *testing.T) {
	url, wvk := witnessServer(t)
	root := t.TempDir()
	dir, spool := filepath.Join(root, "log"), filepath.Join(root, "spool")
	if err := os.Mkdir(spool, 0o700); err != nil {
		t.Fatal(err)
	}
	key := tallytest.TestVerifierKey
	writeLog(t, dir, spool, "a", 12, true)
	out, stderr, code := cli(t, "witness", "push", "--dir", dir, "--key", key, "--witness", url, "--witness-key", wvk, "--anchor", spool)
	if code != exitIntact {
		t.Fatalf("push: %d\n%s%s", code, out, stderr)
	}
	witnessedSize, err := strconv.ParseUint(line(t, out, "witnessed"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	writeLog(t, dir, spool, "b", 20, true)

	a, err := anchor.NewDir(spool)
	if err != nil {
		t.Fatal(err)
	}
	var newest, early tally.SignedCheckpoint
	for cp, err := range a.Checkpoints(context.Background()) {
		if err != nil {
			t.Fatal(err)
		}
		if isTlog(cp) || !strings.Contains(string(cp), "\ntally-heartbeat/v1\n") {
			continue
		}
		size, serr := tally.CheckpointSize(cp)
		if serr != nil {
			t.Fatal(serr)
		}
		if size <= witnessedSize {
			early = cp // the largest heartbeat note the witness's size covers
		}
		newest = cp
	}
	if early == nil || newest == nil {
		t.Fatal("the anchor holds no heartbeat notes to prune at")
	}
	before := segments(t, dir)
	_, stderr, code = cli(t, "prune", "--dir", dir, "--key", key, "--anchor", spool,
		"--checkpoint", writeCheckpoint(t, newest), "--witness-key", wvk)
	if code != exitViolation || !strings.Contains(stderr, "the witness has cosigned") {
		t.Fatalf("a prune above the witness: %d\n%s", code, stderr)
	}
	if after := segments(t, dir); len(after) != len(before) {
		t.Fatalf("a refused prune removed segments: %v -> %v", before, after)
	}
	if _, stderr, code = cli(t, "prune", "--dir", dir, "--key", key, "--anchor", spool,
		"--checkpoint", writeCheckpoint(t, early), "--witness-key", wvk); code != exitIntact {
		t.Fatalf("a prune at a size the witness cosigned: %d\n%s", code, stderr)
	}
}
