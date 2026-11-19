package main

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/anchor"
	"github.com/JonasBorgesLM/tally/filestore"
	"github.com/JonasBorgesLM/tally/tallytest"
)

// prunableLog writes a log in two phases: the first without an anchor, so its
// checkpoints are valid but never left the host, and the second publishing to
// an anchor. It returns the directories, the first phase's first checkpoint
// and the anchor's first checkpoint.
func prunableLog(t *testing.T) (dir, anchorDir string, unanchored, anchored tally.SignedCheckpoint) {
	t.Helper()
	root := t.TempDir()
	dir, anchorDir = filepath.Join(root, "log"), filepath.Join(root, "anchor")
	writeLog(t, dir, "", "a", 6, true)
	r, err := filestore.OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	for cp, err := range r.Checkpoints(context.Background()) {
		if err != nil {
			t.Fatal(err)
		}
		if !isTlog(cp) {
			unanchored = cp
			break
		}
	}
	writeLog(t, dir, anchorDir, "b", 6, true)
	a, err := anchor.NewDir(anchorDir)
	if err != nil {
		t.Fatal(err)
	}
	for cp, err := range a.Checkpoints(context.Background()) {
		if err != nil {
			t.Fatal(err)
		}
		if !isTlog(cp) {
			anchored = cp
			break
		}
	}
	if unanchored == nil || anchored == nil {
		t.Fatal("the fixture has no checkpoint")
	}
	return dir, anchorDir, unanchored, anchored
}

// A prune at an anchored tlog-checkpoint is refused, and says to use the
// heartbeat note of its size, which names the head a prune verifies from
// (#60). Nothing is removed.
func TestPruneAtATlogCheckpointIsRefused(t *testing.T) {
	dir, anchorDir, _, _ := prunableLog(t)
	a, err := anchor.NewDir(anchorDir)
	if err != nil {
		t.Fatal(err)
	}
	var tlog tally.SignedCheckpoint
	for cp, err := range a.Checkpoints(context.Background()) {
		if err != nil {
			t.Fatal(err)
		}
		if isTlog(cp) {
			tlog = cp
			break
		}
	}
	if tlog == nil {
		t.Fatal("the anchor holds no tlog-checkpoint")
	}
	before := segments(t, dir)
	_, stderr, code := cli(t, "prune", "--dir", dir, "--key", tallytest.TestVerifierKey, "--anchor", anchorDir,
		"--checkpoint", writeCheckpoint(t, tlog))
	if code != exitViolation || !strings.Contains(stderr, "heartbeat note") {
		t.Fatalf("status %d, stderr:\n%s\nwant status %d naming the heartbeat note", code, stderr, exitViolation)
	}
	if after := segments(t, dir); len(after) != len(before) {
		t.Fatalf("segments %v -> %v: a refused prune removed something", before, after)
	}
}

func writeCheckpoint(t *testing.T, cp tally.SignedCheckpoint) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cp.note")
	if err := os.WriteFile(path, cp, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func segments(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tlog") {
			names = append(names, e.Name())
		}
	}
	return names
}

// prune removes segments below a checkpoint the anchor holds, and the log
// still verifies against the anchor afterwards (RF-14, ADR-0012).
func TestPruneAtAnAnchoredCheckpoint(t *testing.T) {
	dir, anchorDir, _, anchored := prunableLog(t)
	before := segments(t, dir)
	key := tallytest.TestVerifierKey
	stdout, stderr, code := cli(t, "prune", "--dir", dir, "--key", key, "--anchor", anchorDir,
		"--checkpoint", writeCheckpoint(t, anchored))
	if code != exitIntact || !strings.HasPrefix(stdout, "pruned ") {
		t.Fatalf("status %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	after := segments(t, dir)
	if len(after) >= len(before) {
		t.Fatalf("segments %v -> %v: nothing was pruned", before, after)
	}
	stdout, _, code = cli(t, "verify", "--dir", dir, "--key", key, "--anchor", anchorDir)
	if code != exitIntact {
		t.Fatalf("verify after prune: status %d\n%s", code, stdout)
	}
}

// prune refuses, removing nothing, a checkpoint that verifies but is not in
// the anchor (RS-20), one whose signature does not verify, and an anchored
// checkpoint of another log; and it needs the log closed.
//
// Seen failing with the anchor check removed (the unanchored checkpoint is
// pruned at), and with ErrPruneRefused reported as an IO error (status 2).
func TestPruneRefuses(t *testing.T) {
	dir, anchorDir, unanchored, anchored := prunableLog(t)
	key := tallytest.TestVerifierKey

	tampered := slices.Clone(anchored)
	tampered[len(tampered)-3] ^= 1

	// Another log signed with the same key and published to the same anchor:
	// its checkpoint is anchored and valid, and is not this log's.
	other := filepath.Join(t.TempDir(), "other")
	writeLog(t, other, anchorDir, "c", 2, true)
	a, err := anchor.NewDir(anchorDir)
	if err != nil {
		t.Fatal(err)
	}
	var foreign tally.SignedCheckpoint
	ours := map[string]bool{}
	r, err := filestore.OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	for cp, err := range r.Checkpoints(context.Background()) {
		if err != nil {
			t.Fatal(err)
		}
		ours[string(cp)] = true
	}
	for cp, err := range a.Checkpoints(context.Background()) {
		if err != nil {
			t.Fatal(err)
		}
		if !ours[string(cp)] {
			foreign = cp
		}
	}
	if foreign == nil {
		t.Fatal("no checkpoint of the other log in the anchor")
	}

	cases := []struct {
		name string
		cp   tally.SignedCheckpoint
		code int
		want string
	}{
		{"not in the anchor", unanchored, exitViolation, "not in the anchor"},
		{"a bad signature", tampered, exitViolation, "refused"},
		{"another log's checkpoint", foreign, exitViolation, "refused"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := segments(t, dir)
			_, stderr, code := cli(t, "prune", "--dir", dir, "--key", key, "--anchor", anchorDir,
				"--checkpoint", writeCheckpoint(t, c.cp))
			if code != c.code || !strings.Contains(stderr, c.want) {
				t.Fatalf("status %d, stderr:\n%s", code, stderr)
			}
			if after := segments(t, dir); !slices.Equal(after, before) {
				t.Errorf("a refused prune changed the segments: %v -> %v", before, after)
			}
		})
	}

	t.Run("the log is open", func(t *testing.T) {
		s, err := filestore.Open(context.Background(), dir)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = s.Close() }()
		_, stderr, code := cli(t, "prune", "--dir", dir, "--key", key, "--anchor", anchorDir,
			"--checkpoint", writeCheckpoint(t, anchored))
		if code != exitError || !strings.Contains(stderr, "the log is open") {
			t.Fatalf("status %d, stderr:\n%s", code, stderr)
		}
	})
	t.Run("no anchor", func(t *testing.T) {
		if _, _, code := cli(t, "prune", "--dir", dir, "--key", key, "--checkpoint", writeCheckpoint(t, anchored)); code != exitError {
			t.Fatalf("status %d, want 2", code)
		}
	})
}
