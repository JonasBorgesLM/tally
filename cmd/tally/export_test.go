package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/filestore"
	"github.com/JonasBorgesLM/tally/tallytest"
)

// export writes one JSON line per stored record, decoded, genesis first, each
// with the leaf hash of its stored bytes (RF-15).
func TestExportJSONL(t *testing.T) {
	dir, _ := logAndAnchor(t)
	stdout, stderr, code := cli(t, "export", "--dir", dir)
	if code != exitIntact {
		t.Fatalf("status %d\n%s", code, stderr)
	}
	r, err := filestore.OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	var leaves []string
	for rec, err := range r.Records(context.Background(), 0) {
		if err != nil {
			t.Fatal(err)
		}
		leaf := tally.LeafHash(rec.Body)
		leaves = append(leaves, hex.EncodeToString(leaf[:]))
	}
	sc := bufio.NewScanner(strings.NewReader(stdout))
	n := 0
	for sc.Scan() {
		var j jsonRecord
		if err := json.Unmarshal(sc.Bytes(), &j); err != nil {
			t.Fatalf("line %d is not JSON: %v", n, err)
		}
		if j.Seq != uint64(n) || j.LeafHash != leaves[n] { // #nosec G115 -- a small counter
			t.Errorf("line %d: seq %d, leaf %s", n, j.Seq, j.LeafHash)
		}
		switch {
		case n == 0 && (j.Type != "genesis" || j.Origin != "example.com/log"):
			t.Errorf("line 0 is not the genesis: %+v", j)
		case n > 0:
			id, _ := base64.StdEncoding.DecodeString(j.EventID)
			if j.Type != "entry" || j.Action != "user.login" || j.Outcome != "success" ||
				j.ActorKind != "system" || !strings.HasPrefix(string(id), "a-") {
				t.Errorf("line %d: %+v", n, j)
			}
		}
		n++
	}
	if n != len(leaves) || n != 6 {
		t.Fatalf("%d lines for %d records, want 6", n, len(leaves))
	}
}

// Every text field of an exported line is escaped, so a stored value cannot
// carry an ANSI sequence, a bidi override, DEL or a line break to whoever
// reads the export; JSON alone escapes control bytes but not DEL, C1 or bidi
// characters (RS-13, T-17, #42). Opaque bytes are base64 or hex.
//
// Seen failing with the sanitize calls removed from toJSON: the bidi override
// and DEL then reach the output as they are.
func TestExportedFieldsAreSanitized(t *testing.T) {
	hostile := "x\x1b[31m\u202e\x7f\u0085\ny"
	views := []tally.RecordView{
		{Genesis: true, Origin: hostile},
		{Seq: 1, ActorKind: "service", ActorID: []byte(hostile), Action: hostile, Resource: hostile,
			PayloadKind: hostile, EventID: []byte(hostile), Payload: []byte(hostile)},
	}
	for _, v := range views {
		var out bytes.Buffer
		enc := json.NewEncoder(&out)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(toJSON(v, [32]byte{})); err != nil {
			t.Fatal(err)
		}
		line := out.String()
		if strings.Count(line, "\n") != 1 || !strings.HasSuffix(line, "\n") {
			t.Errorf("not one line: %q", line)
		}
		for _, bad := range []string{"\x1b", "\u202e", "\x7f", "\u0085"} {
			if strings.Contains(line, bad) {
				t.Errorf("%q reached the export: %q", bad, line)
			}
		}
	}
}

// export never overwrites a file, and a bundle needs a key.
func TestExportRefuses(t *testing.T) {
	dir, _ := logAndAnchor(t)
	existing := filepath.Join(t.TempDir(), "out")
	if err := os.WriteFile(existing, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, code := cli(t, "export", "--dir", dir, "--out", existing); code != exitError {
		t.Errorf("export over an existing file: status %d, want 2", code)
	}
	if got, _ := os.ReadFile(existing); string(got) != "keep" { // #nosec G304 -- a test's own file
		t.Errorf("the existing file was changed to %q", got)
	}
	if _, _, code := cli(t, "export", "--dir", dir, "--format", "bundle", "--out", existing+".tar"); code != exitError {
		t.Errorf("a bundle without a key: status %d, want 2", code)
	}
}

func exportBundle(t *testing.T, dir, anchorDir string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "bundle.tar")
	args := []string{"export", "--dir", dir, "--format", "bundle", "--out", out, "--key", tallytest.TestVerifierKey}
	if anchorDir != "" {
		args = append(args, "--anchor", anchorDir)
	}
	if _, stderr, code := cli(t, args...); code != exitIntact {
		t.Fatalf("export bundle: status %d\n%s", code, stderr)
	}
	return out
}

// bundleEntries reads a bundle's entries by name.
func bundleEntries(t *testing.T, path string) map[string][]byte {
	t.Helper()
	f, err := os.Open(path) // #nosec G304 -- a test's own file
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	got := map[string][]byte{}
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return got
		}
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		got[hdr.Name] = b
	}
}

// A bundle holds the log, the anchor, the verifier keys and a MANIFEST that
// says "quarantine none" when there is none; it matches its MANIFEST (RF-15).
func TestABundleMatchesItsManifest(t *testing.T) {
	dir, anchorDir := logAndAnchor(t)
	bundle := exportBundle(t, dir, anchorDir)
	stdout, _, code := cli(t, "bundle-check", bundle)
	if code != exitIntact || !strings.Contains(stdout, "result matches") {
		t.Fatalf("status %d\n%s", code, stdout)
	}
	entries := bundleEntries(t, bundle)
	manifest := string(entries[manifestName])
	if !strings.HasPrefix(manifest, manifestHeader+"\nquarantine none\n") {
		t.Errorf("MANIFEST does not say there is no quarantine:\n%s", manifest)
	}
	for _, want := range []string{"log/0000000000000000.tlog", "log/checkpoints.tlc", "keys/verifiers.txt"} {
		if _, ok := entries[want]; !ok {
			t.Errorf("the bundle lacks %s", want)
		}
	}
	anchored := 0
	for name := range entries {
		if strings.HasPrefix(name, "anchor/") {
			anchored++
		}
		if name == "log/LOCK" {
			t.Error("the bundle holds the lock file")
		}
	}
	if anchored == 0 {
		t.Error("the bundle holds no anchor checkpoint")
	}
}

// Every quarantine file is in the bundle, byte for byte, and counted in the
// MANIFEST (RF-20, T-22): they are the only evidence of what recovery removed.
func TestABundleCarriesTheQuarantine(t *testing.T) {
	dir, _ := logAndAnchor(t)
	// A torn tail, recovered by the next writer's Open.
	segs := segments(t, dir)
	last := filepath.Join(dir, segs[len(segs)-1])
	f, err := os.OpenFile(last, os.O_WRONLY|os.O_APPEND, 0) // #nosec G304 -- a test's own file
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write([]byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := filestore.Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.Recovered() != 3 {
		t.Fatalf("recovered %d bytes, want 3", s.Recovered())
	}
	_ = s.Close()

	bundle := exportBundle(t, dir, "")
	entries := bundleEntries(t, bundle)
	if !strings.Contains(string(entries[manifestName]), "\nquarantine 1\n") {
		t.Fatalf("MANIFEST does not count the quarantine:\n%s", entries[manifestName])
	}
	found := false
	for name, b := range entries {
		if strings.HasPrefix(name, "log/quarantine-") {
			found = bytes.Equal(b, []byte{1, 2, 3})
		}
	}
	if !found {
		t.Fatal("the quarantined bytes are not in the bundle as they were")
	}
	if _, _, code := cli(t, "bundle-check", bundle); code != exitIntact {
		t.Fatalf("bundle-check: status %d", code)
	}
}

// rewriteBundle copies a bundle through f, which may change an entry's bytes,
// drop it, or add one.
func rewriteBundle(t *testing.T, path string, f func(tw *tar.Writer, name string, b []byte) bool) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "tampered.tar")
	w, err := os.Create(out) // #nosec G304 -- a test's own file
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(w)
	entries := bundleEntries(t, path)
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	// MANIFEST last, as export writes it.
	slicesSortManifestLast(names)
	for _, name := range names {
		b := entries[name]
		if !f(tw, name, b) {
			continue
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(b)), ModTime: time.Unix(0, 0)}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out
}

func slicesSortManifestLast(names []string) {
	for i, n := range names {
		if n == manifestName {
			names[i], names[len(names)-1] = names[len(names)-1], names[i]
			return
		}
	}
}

// A tampered bundle fails its MANIFEST: a changed byte, a removed entry, an
// added one, a quarantine line that lies, no MANIFEST at all, or a bundle cut
// short, which is a finding (status 1), not an IO error.
//
// Seen failing with the hash comparison removed from checkBundle, and with
// the quarantine-line check removed.
func TestATamperedBundleFailsItsManifest(t *testing.T) {
	dir, anchorDir := logAndAnchor(t)
	bundle := exportBundle(t, dir, anchorDir)
	seg0 := "log/0000000000000000.tlog"
	cases := []struct {
		name string
		f    func(tw *tar.Writer, name string, b []byte) bool
		want string
	}{
		{"a changed byte", func(_ *tar.Writer, name string, b []byte) bool {
			if name == seg0 {
				b[70] ^= 1
			}
			return true
		}, "changed: " + seg0},
		{"a removed entry", func(_ *tar.Writer, name string, _ []byte) bool { return name != seg0 }, "listed but missing: " + seg0},
		{"an added entry", func(tw *tar.Writer, name string, _ []byte) bool {
			if name == manifestName {
				_ = tw.WriteHeader(&tar.Header{Name: "log/extra", Mode: 0o600, Size: 1, ModTime: time.Unix(0, 0)})
				_, _ = tw.Write([]byte{0})
			}
			return true
		}, "not listed: log/extra"},
		{"a lying quarantine line", func(_ *tar.Writer, name string, b []byte) bool {
			if name == manifestName {
				copy(b[len(manifestHeader)+1:], "quarantine 1   ") // overwrite "quarantine none"
			}
			return true
		}, "MANIFEST says"},
		{"no MANIFEST", func(_ *tar.Writer, name string, _ []byte) bool { return name != manifestName }, "no MANIFEST"},
	}
	t.Run("a truncated bundle", func(t *testing.T) {
		b, err := os.ReadFile(bundle) // #nosec G304 -- a test's own file
		if err != nil {
			t.Fatal(err)
		}
		cut := filepath.Join(t.TempDir(), "cut.tar")
		if err := os.WriteFile(cut, b[:len(b)/2], 0o600); err != nil { // #nosec G703 -- a test's own file
			t.Fatal(err)
		}
		if stdout, _, code := cli(t, "bundle-check", cut); code != exitViolation {
			t.Fatalf("status %d, want 1\n%s", code, stdout)
		}
	})
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tampered := rewriteBundle(t, bundle, c.f)
			stdout, _, code := cli(t, "bundle-check", tampered)
			if code != exitViolation || !strings.Contains(stdout, c.want) {
				t.Fatalf("status %d, output:\n%s\nwant %q", code, stdout, c.want)
			}
		})
	}
}
