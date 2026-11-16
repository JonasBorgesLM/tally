package anchor_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/anchor"
	"github.com/JonasBorgesLM/tally/internal/note"
	"github.com/JonasBorgesLM/tally/tallytest"
)

func signer(t *testing.T) tally.Signer {
	t.Helper()
	s, err := note.NewSigner(tallytest.TestSignerKey)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// checkpoints signs n checkpoints of increasing size over a log in memory.
func checkpoints(t *testing.T, n int) []tally.SignedCheckpoint {
	t.Helper()
	ctx := context.Background()
	l, err := tally.Open(ctx, tallytest.NewMemStore(), signer(t), tally.WithCheckpointEvery(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	cps := make([]tally.SignedCheckpoint, 0, n)
	for i := range n {
		ev := tally.Event{ID: tally.EventID(fmt.Sprint(i)), OccurredAt: time.Unix(1_700_000_000, 0),
			Actor: tally.System(), Action: "user.login", Outcome: tally.OutcomeSuccess}
		if _, err := l.Append(ctx, ev); err != nil {
			t.Fatal(err)
		}
		cp, err := l.Checkpoint(ctx)
		if err != nil {
			t.Fatal(err)
		}
		cps = append(cps, cp)
	}
	return cps
}

func newDir(t *testing.T) (d *anchor.Dir, path string) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "spool")
	d, err := anchor.NewDir(path)
	if err != nil {
		t.Fatal(err)
	}
	return d, path
}

func notes(t *testing.T, path string) []string {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func read(t *testing.T, d *anchor.Dir) []tally.SignedCheckpoint {
	t.Helper()
	var got []tally.SignedCheckpoint
	for cp, err := range d.Checkpoints(context.Background()) {
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, cp)
	}
	return got
}

// Published checkpoints are read back in size order, one file each, at mode
// 0600 in a 0700 directory (RS-10).
func TestPublishAndReadBack(t *testing.T) {
	d, path := newDir(t)
	cps := checkpoints(t, 3)
	for _, i := range []int{2, 0, 1} { // published out of order
		if err := d.Publish(context.Background(), cps[i]); err != nil {
			t.Fatal(err)
		}
	}
	got := read(t, d)
	if len(got) != 3 {
		t.Fatalf("read %d checkpoints, want 3", len(got))
	}
	for i := range cps {
		if !bytes.Equal(got[i], cps[i]) {
			t.Errorf("checkpoint %d differs, or is out of size order", i)
		}
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("directory mode %v, %v; want 0700", fi.Mode().Perm(), err)
	}
	for _, name := range notes(t, path) {
		fi, err := os.Stat(filepath.Join(path, name))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v, %v; want 0600", name, fi.Mode().Perm(), err)
		}
	}
}

// A checkpoint already published is success, without a second file: the
// publish queue retries (tally.Anchor).
//
// Seen failing with every existing name treated as a conflict.
func TestRepublishingIsIdempotent(t *testing.T) {
	d, path := newDir(t)
	cp := checkpoints(t, 1)[0]
	for range 3 {
		if err := d.Publish(context.Background(), cp); err != nil {
			t.Fatal(err)
		}
	}
	if names := notes(t, path); len(names) != 1 {
		t.Fatalf("files %v, want one", names)
	}
}

// An existing file is never overwritten (RS-17): a different file under a
// checkpoint's name, written by someone else, makes Publish fail with
// ErrConflict and stays as it was.
//
// Seen failing with the link replaced by a rename, which overwrites.
func TestAnExistingFileIsNeverOverwritten(t *testing.T) {
	d, path := newDir(t)
	cp := checkpoints(t, 1)[0]
	if err := d.Publish(context.Background(), cp); err != nil {
		t.Fatal(err)
	}
	names := notes(t, path)
	if len(names) != 1 {
		t.Fatalf("files %v", names)
	}
	file := filepath.Join(path, names[0])
	planted := []byte("someone else's bytes")
	if err := os.WriteFile(file, planted, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := d.Publish(context.Background(), cp); !errors.Is(err, anchor.ErrConflict) {
		t.Fatalf("Publish over a planted file = %v, want ErrConflict", err)
	}
	if got, _ := os.ReadFile(file); !bytes.Equal(got, planted) { // #nosec G304 -- a test's own file
		t.Error("the existing file was overwritten")
	}
	for _, n := range notes(t, path) {
		if strings.HasSuffix(n, ".tmp") {
			t.Errorf("temporary file %s left behind", n)
		}
	}
}

// A temporary file left by a crash does not block publication.
func TestAStaleTemporaryFileIsReplaced(t *testing.T) {
	d, path := newDir(t)
	cp := checkpoints(t, 1)[0]
	if err := d.Publish(context.Background(), cp); err != nil {
		t.Fatal(err)
	}
	name := notes(t, path)[0]
	if err := os.Remove(filepath.Join(path, name)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "."+name+".tmp"), []byte("half"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := d.Publish(context.Background(), cp); err != nil {
		t.Fatalf("Publish over a stale temporary file: %v", err)
	}
	if got := read(t, d); len(got) != 1 || !bytes.Equal(got[0], cp) {
		t.Fatal("the checkpoint was not published")
	}
}

// Files that are not checkpoints are ignored, and one over the checkpoint
// ceiling is refused before it is read, as a violation (RS-05).
//
// Seen failing with the size check removed from readNote.
func TestReadingIgnoresOtherFilesAndBoundsSize(t *testing.T) {
	d, path := newDir(t)
	cp := checkpoints(t, 1)[0]
	if err := d.Publish(context.Background(), cp); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"README", ".x.note.tmp", "0000000000000001-zz.note"} {
		if err := os.WriteFile(filepath.Join(path, name), []byte("noise"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if got := read(t, d); len(got) != 1 {
		t.Fatalf("read %d checkpoints, want 1", len(got))
	}

	big := filepath.Join(path, "ffffffffffffffff-"+strings.Repeat("0", 64)+".note")
	if err := os.WriteFile(big, make([]byte, tally.MaxCheckpointLen+1), 0o600); err != nil {
		t.Fatal(err)
	}
	var last error
	for _, err := range d.Checkpoints(context.Background()) {
		last = err
	}
	var me *tally.MalformedError
	if !errors.As(last, &me) {
		t.Fatalf("an oversized file read as %v, want a MalformedError", last)
	}
}

// A Log publishing to a Dir, verified against what the Dir holds: the closing
// checkpoint is there and the log is fully attested by the anchor (RF-07,
// RF-09).
func TestALogPublishesToADir(t *testing.T) {
	d, _ := newDir(t)
	mem := tallytest.NewMemStore()
	ctx := context.Background()
	l, err := tally.Open(ctx, keepOpen{mem}, signer(t), tally.WithAnchors(d), tally.WithCheckpointEvery(2, 0))
	if err != nil {
		t.Fatal(err)
	}
	for i := range 5 {
		ev := tally.Event{ID: tally.EventID(fmt.Sprint(i)), OccurredAt: time.Unix(1_700_000_000, 0),
			Actor: tally.System(), Action: "user.login", Outcome: tally.OutcomeSuccess}
		if _, err = l.Append(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	keys, err := tally.NewVerifiers(tallytest.TestVerifierKey)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := tally.Verify(ctx, mem, keys, tally.WithAnchor(d), tally.WithRequireFullyAttested())
	if err != nil || !rep.OK() {
		t.Fatalf("Verify against the Dir = %v, %+v", err, rep)
	}
}

// keepOpen lets the test read the store after the Log closes it.
type keepOpen struct{ tally.Store }

func (keepOpen) Close() error { return nil }
