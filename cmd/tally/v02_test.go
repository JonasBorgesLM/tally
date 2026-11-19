package main

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/anchor"
	"github.com/JonasBorgesLM/tally/filestore"
	"github.com/JonasBorgesLM/tally/internal/merkle"
	"github.com/JonasBorgesLM/tally/internal/note"
	"github.com/JonasBorgesLM/tally/tallytest"
)

// line returns the value of the output line that starts with key and a space.
func line(t *testing.T, out, key string) string {
	t.Helper()
	for _, l := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(l, key+" "); ok {
			return v
		}
	}
	t.Fatalf("no %q line in:\n%s", key, out)
	return ""
}

// wholeRoot is the Merkle root of every record in dir, read from leaf 0.
func wholeRoot(t *testing.T, dir string) string {
	t.Helper()
	r, err := filestore.OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	var leaves [][32]byte
	for rec, err := range r.Records(context.Background(), 0) {
		if err != nil {
			t.Fatal(err)
		}
		leaves = append(leaves, tally.LeafHash(rec.Body))
	}
	root, err := merkle.Root(leaves)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(root[:])
}

// tally head prints the Merkle root (#60): from leaf 0, the same after a
// prune through the stored range, and "unknown" once the range is gone, as
// for a log v0.1 pruned.
//
// Negative control: with head never adopting the stored range, the root after
// the prune was "unknown". Verified by hand, restored before committing.
func TestHeadPrintsTheRoot(t *testing.T) {
	dir, anchorDir, _, anchored := prunableLog(t)
	want := wholeRoot(t, dir)
	out, _, code := cli(t, "head", "--dir", dir)
	if code != exitIntact || line(t, out, "root") != want {
		t.Fatalf("before the prune: status %d, root %q, want %q", code, line(t, out, "root"), want)
	}
	if _, stderr, code := cli(t, "prune", "--dir", dir, "--key", tallytest.TestVerifierKey, "--anchor", anchorDir,
		"--checkpoint", writeCheckpoint(t, anchored)); code != exitIntact {
		t.Fatalf("prune: status %d\n%s", code, stderr)
	}
	out, _, _ = cli(t, "head", "--dir", dir)
	if got := line(t, out, "root"); got != want {
		t.Fatalf("after the prune: root %q, want %q", got, want)
	}
	if err := os.Remove(filepath.Join(dir, "pruned.range")); err != nil {
		t.Fatal(err)
	}
	out, _, _ = cli(t, "head", "--dir", dir)
	if got := line(t, out, "root"); !strings.HasPrefix(got, "unknown") {
		t.Fatalf("without the range: root %q, want unknown", got)
	}
}

// tally checkpoint prints the newest heartbeat note by default, which prune
// and an incremental verify start from, and with --tlog the newest
// tlog-checkpoint, for a witness: its root is the log's.
func TestCheckpointPrintsEitherNote(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "log")
	writeLog(t, dir, "", "a", 6, true)
	key := tallytest.TestVerifierKey

	out, _, code := cli(t, "checkpoint", "--dir", dir, "--key", key)
	if code != exitIntact || !strings.Contains(out, "\ntally-heartbeat/v1\n") {
		t.Fatalf("default: status %d\n%s\nwant a tally-heartbeat/v1 note", code, out)
	}
	out, _, code = cli(t, "checkpoint", "--dir", dir, "--key", key, "--tlog")
	if code != exitIntact || !isTlog(tally.SignedCheckpoint(out)) {
		t.Fatalf("--tlog: status %d\n%s\nwant a tlog-checkpoint", code, out)
	}
	text, _, _ := strings.Cut(out, "\n\n")
	if got := strings.Split(text, "\n")[2]; got != wholeRoot(t, dir) {
		t.Fatalf("--tlog: root %q, want the log's %q", got, wholeRoot(t, dir))
	}
}

// tally verify --witness reports the witnessed size, and
// --require-witnessed makes an unwitnessed tail exit 1 (ADR-0021). A log key
// given as a witness is a usage error, status 2.
func TestVerifyWithAWitness(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "log")
	writeLog(t, dir, "", "a", 6, true)
	key := tallytest.TestVerifierKey
	wsk, wvk, err := note.GenerateCosignerKey(strings.NewReader(strings.Repeat("w", 32)), "witness.example")
	if err != nil {
		t.Fatal(err)
	}
	w, err := note.NewCosigner(wsk)
	if err != nil {
		t.Fatal(err)
	}

	out, _, code := cli(t, "verify", "--dir", dir, "--key", key, "--witness", wvk, "--require-witnessed")
	if code != exitViolation || line(t, out, "witnessed") != "0" || !strings.Contains(out, "UnwitnessedTail") {
		t.Fatalf("nothing cosigned: status %d\n%s", code, out)
	}

	// The witness cosigns the newest tlog-checkpoint, kept beside the log's.
	tl, _, _ := cli(t, "checkpoint", "--dir", dir, "--key", key, "--tlog")
	text, _, _ := strings.Cut(tl, "\n\n")
	cosig, err := note.Cosign([]byte(text+"\n"), w, time.Unix(1_790_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	anchorDir := filepath.Join(t.TempDir(), "anchor")
	a, err := anchor.NewDir(anchorDir)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Publish(context.Background(), tally.SignedCheckpoint(tl+cosig)); err != nil {
		t.Fatal(err)
	}
	out, stderr, code := cli(t, "verify", "--dir", dir, "--key", key, "--anchor", anchorDir, "--witness", wvk, "--require-witnessed")
	if code != exitIntact || line(t, out, "witnessed") != line(t, out, "size") {
		t.Fatalf("cosigned: status %d\n%s%s", code, out, stderr)
	}
	if _, _, code := cli(t, "verify", "--dir", dir, "--key", key, "--witness", key); code != exitError {
		t.Fatalf("a log key as a witness: status %d, want %d", code, exitError)
	}
}
