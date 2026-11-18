package main

import (
	"archive/tar"
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/filestore"
)

// cmdExport writes the log as JSONL or as an audit bundle (RF-15). Both read
// the directory without the lock and change nothing. JSONL is what is
// stored, decoded: run verify for what is attested.
func cmdExport(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := newFlags("export", stderr)
	dir := flags.String("dir", "", "the log directory")
	format := flags.String("format", "jsonl", "jsonl, or bundle")
	out := flags.String("out", "", "the file to write; created, never overwritten. jsonl defaults to stdout")
	keys := keyList{}
	flags.Var(&keys, "key", "a verifier key to include in the bundle (repeatable)")
	anchorDir := flags.String("anchor", "", "a copy of the anchor to include in the bundle")
	if err := flags.Parse(args); err != nil {
		return exitError
	}
	if *dir == "" || flags.NArg() != 0 {
		(&output{w: stderr}).printf("tally export: --dir is required, and it takes no arguments\n")
		return exitError
	}
	if err := existingDir(*dir); err != nil {
		return fail(stderr, err)
	}
	switch *format {
	case "jsonl":
		w, done, err := openOut(*out, stdout)
		if err != nil {
			return fail(stderr, err)
		}
		code := exportJSONL(ctx, *dir, w, stderr)
		if err := done(); err != nil {
			return fail(stderr, err)
		}
		return code
	case "bundle":
		if *out == "" || len(keys) == 0 {
			(&output{w: stderr}).printf("tally export: a bundle needs --out and at least one --key\n")
			return exitError
		}
		if _, err := tally.NewVerifiers(keys...); err != nil {
			return fail(stderr, err)
		}
		if *anchorDir != "" {
			if err := existingDir(*anchorDir); err != nil {
				return fail(stderr, err)
			}
		}
		w, done, err := openOut(*out, stdout)
		if err != nil {
			return fail(stderr, err)
		}
		err = writeBundle(*dir, *anchorDir, keys, w)
		if derr := done(); err == nil {
			err = derr
		}
		if err != nil {
			return fail(stderr, errors.Join(err, os.Remove(*out)))
		}
		o := &output{w: stdout}
		o.printf("wrote %s\n", sanitize(*out))
		return o.status(exitIntact)
	default:
		(&output{w: stderr}).printf("tally export: --format is jsonl or bundle\n")
		return exitError
	}
}

// openOut opens path for writing, created with O_EXCL at 0600, or returns
// stdout for an empty path. done closes and syncs a file.
func openOut(path string, stdout io.Writer) (io.Writer, func() error, error) {
	if path == "" {
		return stdout, func() error { return nil }, nil
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- a path the operator chose
	if err != nil {
		return nil, nil, err
	}
	bw := bufio.NewWriter(f)
	return bw, func() error {
		err := bw.Flush()
		if err == nil {
			err = f.Sync()
		}
		return errors.Join(err, f.Close())
	}, nil
}

// jsonRecord is one JSONL line. Opaque bytes are base64 or hex, which carry no
// control character; text fields are sanitized before encoding, since JSON
// escapes control bytes but leaves DEL, C1 and bidi characters as they are
// (RS-13, T-17).
type jsonRecord struct {
	Seq      uint64 `json:"seq"`
	Type     string `json:"type"`
	LogID    string `json:"log_id_hex"`
	LeafHash string `json:"leaf_hash_hex"`

	Origin    string `json:"origin,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`

	RecordedAt  string `json:"recorded_at,omitempty"`
	OccurredAt  string `json:"occurred_at,omitempty"`
	EventID     string `json:"event_id_b64,omitempty"`
	ActorKind   string `json:"actor_kind,omitempty"`
	Actor       string `json:"actor,omitempty"`
	Action      string `json:"action,omitempty"`
	Resource    string `json:"resource,omitempty"`
	Outcome     string `json:"outcome,omitempty"`
	PayloadKind string `json:"payload_kind,omitempty"`
	SubjectRef  string `json:"subject_ref_hex,omitempty"`
	Payload     string `json:"payload_b64,omitempty"`
	PrevHash    string `json:"prev_hash_hex,omitempty"`
}

// toJSON maps a decoded record to its JSONL line, sanitizing every text field.
func toJSON(v tally.RecordView, leaf [32]byte) jsonRecord {
	j := jsonRecord{Seq: v.Seq, LogID: hex.EncodeToString(v.LogID[:]), LeafHash: hex.EncodeToString(leaf[:])}
	if v.Genesis {
		j.Type = "genesis"
		j.Origin = sanitize(v.Origin)
		j.CreatedAt = v.CreatedAt.Format(time.RFC3339Nano)
		return j
	}
	j.Type = "entry"
	j.RecordedAt = v.RecordedAt.Format(time.RFC3339Nano)
	j.OccurredAt = v.OccurredAt.Format(time.RFC3339Nano)
	j.EventID = base64.StdEncoding.EncodeToString(v.EventID)
	j.ActorKind = sanitize(v.ActorKind)
	switch v.ActorKind {
	case "service":
		j.Actor = sanitize(string(v.ActorID)) // a service name is text
	default:
		j.Actor = hex.EncodeToString(v.ActorID) // a SubjectRef, or empty for the system
	}
	j.Action = sanitize(v.Action)
	j.Resource = sanitize(v.Resource)
	j.Outcome = sanitize(v.Outcome.String())
	j.PayloadKind = sanitize(v.PayloadKind)
	j.SubjectRef = hex.EncodeToString(v.SubjectRef)
	j.Payload = base64.StdEncoding.EncodeToString(v.Payload)
	j.PrevHash = hex.EncodeToString(v.PrevHash[:])
	return j
}

// exportJSONL writes one line per stored record. A record that does not
// decode, or a malformed segment, ends the export with status 1.
func exportJSONL(ctx context.Context, dir string, w, stderr io.Writer) int {
	src, err := filestore.OpenReader(dir)
	if err != nil {
		return fail(stderr, err)
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for r, err := range src.Records(ctx, 0) {
		var me *tally.MalformedError
		if errors.As(err, &me) {
			(&output{w: stderr}).printf("tally export: malformed at leaf %d: %s\n", me.Seq, sanitize(me.Err.Error()))
			return exitViolation
		}
		if err != nil {
			return fail(stderr, err)
		}
		v, derr := tally.DecodeRecord(r.Body)
		if derr != nil {
			(&output{w: stderr}).printf("tally export: record %d does not decode: %s\n", r.Seq, sanitize(derr.Error()))
			return exitViolation
		}
		if err := enc.Encode(toJSON(v, tally.LeafHash(r.Body))); err != nil {
			return fail(stderr, err)
		}
	}
	return exitIntact
}

// The bundle (RF-15) is a tar archive: the log directory's files under log/,
// a copy of the anchor under anchor/ if given, the verifier keys in
// keys/verifiers.txt, and MANIFEST last, listing every other entry's SHA-256
// and size. MANIFEST also says how many quarantine files the log holds, and
// says "none" when there are none, so an absent section cannot be mistaken
// for an omitted one.
//
// MANIFEST is not signed. It shows that a bundle changed after it was made;
// it says nothing about the log, whose integrity comes from verify against
// the anchor, and an export made on a compromised host is the host's word.
const (
	manifestName    = "MANIFEST"
	manifestHeader  = "tally-bundle v1"
	maxManifestSize = 1 << 20 // the bundle-check reads MANIFEST with this limit (RS-05)
)

// writeBundle writes the bundle for dir to w.
func writeBundle(logDir, anchorDir string, keys []string, w io.Writer) error {
	tw := tar.NewWriter(w)
	var lines []string
	quarantined := 0
	add := func(name string, r io.Reader, size int64) error {
		hdr := &tar.Header{Name: name, Mode: 0o600, Size: size, ModTime: time.Unix(0, 0), Format: tar.FormatPAX}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		h := sha256.New()
		n, err := io.Copy(tw, io.TeeReader(io.LimitReader(r, size), h))
		if err != nil {
			return err
		}
		if n != size {
			return fmt.Errorf("%s shrank while it was exported", name)
		}
		// The name is quoted: a file in the log directory can be named
		// anything, a line break included, and must not break MANIFEST.
		lines = append(lines, fmt.Sprintf("%x %d %s", h.Sum(nil), size, strconv.Quote(name)))
		return nil
	}
	addDir := func(dir, prefix string) error {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, e := range entries {
			name := e.Name()
			if !e.Type().IsRegular() || name == "LOCK" || strings.HasSuffix(name, ".tmp") {
				continue
			}
			if prefix == "log/" && strings.HasPrefix(name, "quarantine-") {
				quarantined++
			}
			if err := addFile(add, filepath.Join(dir, name), prefix+name); err != nil {
				return err
			}
		}
		return nil
	}
	if err := addDir(logDir, "log/"); err != nil {
		return err
	}
	if anchorDir != "" {
		if err := addDir(anchorDir, "anchor/"); err != nil {
			return err
		}
	}
	k := []byte(strings.Join(keys, "\n") + "\n")
	if err := add("keys/verifiers.txt", strings.NewReader(string(k)), int64(len(k))); err != nil {
		return err
	}

	q := "quarantine none"
	if quarantined > 0 {
		q = "quarantine " + strconv.Itoa(quarantined)
	}
	manifest := manifestHeader + "\n" + q + "\n" + strings.Join(lines, "\n") + "\n"
	if err := add(manifestName, strings.NewReader(manifest), int64(len(manifest))); err != nil {
		return err
	}
	return tw.Close()
}

// addFile adds the file at path, copying as many bytes as it held when the
// export reached it: a log still being written grows, and the bundle holds a
// consistent prefix of each file.
func addFile(add func(string, io.Reader, int64) error, path, name string) error {
	f, err := os.Open(path) // #nosec G304 -- a file in the directory being exported
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck // read-only: a close error loses no data
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	return add(name, f, fi.Size())
}

// isMalformedTar reports whether err from a tar.Reader means the archive is
// cut off or malformed, which is a finding, rather than a failure to read.
func isMalformedTar(err error) bool {
	return errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, tar.ErrHeader) ||
		errors.Is(err, tar.ErrFieldTooLong) || errors.Is(err, tar.ErrInsecurePath)
}

// cmdBundleCheck checks an audit bundle against its MANIFEST: every entry is
// listed with its hash and size, and every listed entry is present. Status 0
// means it matches; 1, that something was changed, added or removed.
func cmdBundleCheck(args []string, stdout, stderr io.Writer) int {
	flags := newFlags("bundle-check", stderr)
	if err := flags.Parse(args); err != nil {
		return exitError
	}
	if flags.NArg() != 1 {
		(&output{w: stderr}).printf("tally bundle-check: give one bundle file\n")
		return exitError
	}
	f, err := os.Open(flags.Arg(0)) // #nosec G304 -- a path the operator chose
	if err != nil {
		return fail(stderr, err)
	}
	defer f.Close() //nolint:errcheck // read-only: a close error loses no data

	problems, err := checkBundle(f)
	if err != nil {
		return fail(stderr, err)
	}
	o := &output{w: stdout}
	for _, p := range problems {
		o.printf("mismatch %s\n", p)
	}
	if len(problems) > 0 {
		o.printf("result altered (%d)\n", len(problems))
		return o.status(exitViolation)
	}
	o.printf("result matches its manifest\n")
	return o.status(exitIntact)
}

// checkBundle reads a bundle and returns what does not match its MANIFEST,
// each problem sanitized: entry names are the bundle's, and hostile. Entries
// are hashed as they stream and never written anywhere.
func checkBundle(r io.Reader) ([]string, error) {
	tr := tar.NewReader(r)
	type seen struct {
		sum  string
		size int64
	}
	entries := map[string]seen{}
	var manifest []byte
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if isMalformedTar(err) {
			return []string{"the bundle is not a readable tar archive: " + sanitize(err.Error())}, nil
		}
		if err != nil {
			return nil, err
		}
		if hdr.Name == manifestName {
			manifest, err = io.ReadAll(io.LimitReader(tr, maxManifestSize+1))
			if err != nil {
				return nil, err
			}
			continue
		}
		h := sha256.New()
		// Hashed as it streams, in constant memory: an entry's size does not
		// matter, and a tar is not compressed.
		n, err := io.Copy(h, tr) // #nosec G110 -- streamed into a hash, never buffered or written out
		if isMalformedTar(err) {
			return []string{"entry " + sanitize(hdr.Name) + " is cut off"}, nil
		}
		if err != nil {
			return nil, err
		}
		if _, dup := entries[hdr.Name]; dup {
			return []string{"entry " + sanitize(hdr.Name) + " appears twice"}, nil
		}
		entries[hdr.Name] = seen{sum: hex.EncodeToString(h.Sum(nil)), size: n}
	}
	switch {
	case manifest == nil:
		return []string{"no MANIFEST"}, nil
	case len(manifest) > maxManifestSize:
		return []string{"MANIFEST is over its size limit"}, nil
	}
	lines := strings.Split(strings.TrimSuffix(string(manifest), "\n"), "\n")
	if len(lines) < 2 || lines[0] != manifestHeader || !strings.HasPrefix(lines[1], "quarantine ") {
		return []string{"MANIFEST has no tally-bundle v1 header"}, nil
	}
	var problems []string
	listed := map[string]bool{}
	for _, l := range lines[2:] {
		parts := strings.SplitN(l, " ", 3)
		if len(parts) != 3 {
			problems = append(problems, "a malformed MANIFEST line: "+sanitize(l))
			continue
		}
		sum, sizeText := parts[0], parts[1]
		name, qerr := strconv.Unquote(parts[2])
		if qerr != nil {
			problems = append(problems, "a malformed MANIFEST name: "+sanitize(parts[2]))
			continue
		}
		listed[name] = true
		got, ok := entries[name]
		size, perr := strconv.ParseInt(sizeText, 10, 64)
		switch {
		case !ok:
			problems = append(problems, "listed but missing: "+sanitize(name))
		case perr != nil || got.size != size || got.sum != sum:
			problems = append(problems, "changed: "+sanitize(name))
		}
	}
	// The quarantine line must match the quarantine files present: "none"
	// when there are none, so an absent section is never an omitted one.
	quarantined := 0
	for name := range entries {
		if strings.HasPrefix(name, "log/quarantine-") {
			quarantined++
		}
	}
	want := "quarantine none"
	if quarantined > 0 {
		want = "quarantine " + strconv.Itoa(quarantined)
	}
	if lines[1] != want {
		problems = append(problems, fmt.Sprintf("MANIFEST says %q, the bundle holds %d quarantine files", sanitize(lines[1]), quarantined))
	}
	extra := make([]string, 0, len(entries))
	for name := range entries {
		if !listed[name] {
			extra = append(extra, name)
		}
	}
	slices.Sort(extra)
	for _, name := range extra {
		problems = append(problems, "not listed: "+sanitize(name))
	}
	return problems, nil
}
