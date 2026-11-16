package filestore

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/internal/fsx"
	"github.com/JonasBorgesLM/tally/internal/note"
	"github.com/JonasBorgesLM/tally/tallytest"
)

// withFS injects the filesystem (RNF-11). Tests only: fsx is internal, so an
// exported option would name a type no caller can use.
func withFS(f fsx.FS) Option {
	return func(c *config) { c.fsys = f }
}

var errInjected = errors.New("injected fault")

// recFS records every operation as "<op> <base name>" and fails the one
// numbered failAt (0-based) with errInjected; failAt < 0 never fails.
type recFS struct {
	fsx.FS
	ops    []string
	failAt int
}

func newRecFS() *recFS { return &recFS{FS: fsx.OS{}, failAt: -1} }

func (r *recFS) op(s string) error {
	r.ops = append(r.ops, s)
	if len(r.ops)-1 == r.failAt {
		return errInjected
	}
	return nil
}

// reset forgets the operations so far, and fails the i-th from now on.
func (r *recFS) reset(failAt int) {
	r.ops, r.failAt = nil, failAt
}

func openMode(flag int) string {
	switch {
	case flag&os.O_EXCL != 0:
		return "create"
	case flag&(os.O_WRONLY|os.O_RDWR) != 0:
		return "append"
	default:
		return "read"
	}
}

func (r *recFS) OpenFile(name string, flag int, perm fs.FileMode) (fsx.File, error) {
	base := filepath.Base(name)
	if err := r.op(openMode(flag) + " " + base); err != nil {
		return nil, err
	}
	f, err := r.FS.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return &recFile{File: f, fs: r, base: base}, nil
}

func (r *recFS) Mkdir(name string, perm fs.FileMode) error {
	if err := r.op("mkdir " + filepath.Base(name)); err != nil {
		return err
	}
	return r.FS.Mkdir(name, perm)
}

func (r *recFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if err := r.op("readdir " + filepath.Base(name)); err != nil {
		return nil, err
	}
	return r.FS.ReadDir(name)
}

func (r *recFS) Stat(name string) (fs.FileInfo, error) {
	if err := r.op("stat " + filepath.Base(name)); err != nil {
		return nil, err
	}
	return r.FS.Stat(name)
}

func (r *recFS) Lock(name string) (io.Closer, error) {
	if err := r.op("lock " + filepath.Base(name)); err != nil {
		return nil, err
	}
	return r.FS.Lock(name)
}

type recFile struct {
	fsx.File
	fs   *recFS
	base string
}

func (f *recFile) Write(p []byte) (int, error) {
	if err := f.fs.op("write " + f.base); err != nil {
		return 0, err
	}
	return f.File.Write(p)
}

func (f *recFile) Sync() error {
	if err := f.fs.op("sync " + f.base); err != nil {
		return err
	}
	return f.File.Sync()
}

func (f *recFile) Truncate(size int64) error {
	if err := f.fs.op("truncate " + f.base); err != nil {
		return err
	}
	return f.File.Truncate(size)
}

func (r *recFS) Remove(name string) error {
	if err := r.op("remove " + filepath.Base(name)); err != nil {
		return err
	}
	return r.FS.Remove(name)
}

func (f *recFile) Close() error {
	// The descriptor is closed even under an injected fault, so that it does
	// not leak into the next case.
	err := f.fs.op("close " + f.base)
	if cerr := f.File.Close(); err == nil {
		err = cerr
	}
	return err
}

// vectorBodies returns the stored bytes of testdata/vectors/records.json: a
// genesis and four entries forming one chain.
func vectorBodies(t *testing.T) [][]byte {
	t.Helper()
	b, err := os.ReadFile("../testdata/vectors/records.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Records []struct {
			BodyHex string `json:"body_hex"`
		} `json:"records"`
	}
	if err := json.Unmarshal(b, &file); err != nil {
		t.Fatal(err)
	}
	bodies := make([][]byte, 0, len(file.Records))
	for _, r := range file.Records {
		body, err := hex.DecodeString(r.BodyHex)
		if err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, body)
	}
	if len(bodies) != 5 {
		t.Fatalf("records.json holds %d records, want 5", len(bodies))
	}
	return bodies
}

// vectorCheckpoint returns the signed note of testdata/vectors/checkpoints.json,
// over the head of records.json.
func vectorCheckpoint(t *testing.T) tally.SignedCheckpoint {
	t.Helper()
	b, err := os.ReadFile("../testdata/vectors/checkpoints.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Checkpoints []struct {
			Note string `json:"note"`
		} `json:"checkpoints"`
	}
	if err := json.Unmarshal(b, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Checkpoints) != 1 {
		t.Fatalf("checkpoints.json holds %d checkpoints, want 1", len(file.Checkpoints))
	}
	return tally.SignedCheckpoint(file.Checkpoints[0].Note)
}

func records(bodies [][]byte, from uint64) []tally.Record {
	recs := make([]tally.Record, len(bodies))
	for i, b := range bodies {
		recs[i] = tally.Record{Seq: from + uint64(i), Body: b} // #nosec G115 -- a slice index
	}
	return recs
}

func signer(t *testing.T) tally.Signer {
	t.Helper()
	s, err := note.NewSigner(tallytest.TestSignerKey)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func verifiers(t *testing.T) tally.Verifiers {
	t.Helper()
	v, err := tally.NewVerifiers(tallytest.TestVerifierKey)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// checkpointSize is line 3 of a checkpoint's text (SPEC §5.2).
func checkpointSize(t *testing.T, cp tally.SignedCheckpoint) uint64 {
	t.Helper()
	lines := strings.SplitN(string(cp), "\n", 4)
	if len(lines) < 4 {
		t.Fatalf("not a checkpoint: %q", cp)
	}
	n, err := strconv.ParseUint(lines[2], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// segmentFirsts lists the first_seq of every segment file in dir.
func segmentFirsts(t *testing.T, dir string) []uint64 {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var firsts []uint64
	for _, e := range entries {
		if first, ok, err := parseSegmentName(e.Name()); err == nil && ok {
			firsts = append(firsts, first)
		}
	}
	return firsts
}

func mustOpen(t *testing.T, dir string, opts ...Option) *Store {
	t.Helper()
	s, err := Open(t.Context(), dir, opts...)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

func logDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "log")
}
