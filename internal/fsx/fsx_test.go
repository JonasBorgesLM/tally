package fsx_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/tally/internal/fsx"
)

// recFS wraps an FS, records every operation as "<op> <base name>", and fails
// the operation numbered failAt (0-based) with errInjected. failAt < 0 never
// fails. shortWrite makes every Write report one byte fewer and no error.
type recFS struct {
	fsx.FS
	ops        []string
	failAt     int
	shortWrite bool
}

var errInjected = errors.New("injected fault")

func (r *recFS) op(name string) error {
	r.ops = append(r.ops, name)
	if len(r.ops)-1 == r.failAt {
		return errInjected
	}
	return nil
}

func (r *recFS) OpenFile(name string, flag int, perm fs.FileMode) (fsx.File, error) {
	if err := r.op("open " + filepath.Base(name)); err != nil {
		return nil, err
	}
	f, err := r.FS.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return &recFile{File: f, fs: r, base: filepath.Base(name)}, nil
}

func (r *recFS) Rename(oldpath, newpath string) error {
	if err := r.op("rename " + filepath.Base(oldpath) + " " + filepath.Base(newpath)); err != nil {
		return err
	}
	return r.FS.Rename(oldpath, newpath)
}

func (r *recFS) Remove(name string) error {
	if err := r.op("remove " + filepath.Base(name)); err != nil {
		return err
	}
	return r.FS.Remove(name)
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
	if f.fs.shortWrite && len(p) > 0 {
		return f.File.Write(p[:len(p)-1])
	}
	return f.File.Write(p)
}

func (f *recFile) Sync() error {
	if err := f.fs.op("sync " + f.base); err != nil {
		return err
	}
	return f.File.Sync()
}

func (f *recFile) Close() error {
	// The real descriptor is closed even when the fault is injected, so a
	// failed Close does not leak it into the next subtest.
	err := f.fs.op("close " + f.base)
	if cerr := f.File.Close(); err == nil {
		err = cerr
	}
	return err
}

// writeAtomicOps is the order WriteAtomic must follow for a file "cp" in a
// directory "dir". Durability rests on it: the data is synced before the
// rename makes it visible, and the directory is synced after, so the rename
// itself survives a crash (RS-10, ADR-0009).
var writeAtomicOps = []string{
	"remove cp.tmp",
	"open cp.tmp", "write cp.tmp", "sync cp.tmp", "close cp.tmp",
	"rename cp.tmp cp",
	"open dir", "sync dir", "close dir",
}

// renameAt is the index of the rename in writeAtomicOps: before it name is
// untouched, from it on name holds the new data.
var renameAt = slices.Index(writeAtomicOps, "rename cp.tmp cp")

func newDir(t *testing.T) (dir, name string) {
	t.Helper()
	dir = filepath.Join(t.TempDir(), "dir")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir, filepath.Join(dir, "cp")
}

func readFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(name) // #nosec G304 -- a test's own temporary path
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func assertNoTmp(t *testing.T, name string) {
	t.Helper()
	if _, err := os.Lstat(name + ".tmp"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("temporary file left behind: Lstat = %v", err)
	}
}

// Seen failing with the directory fsync removed from WriteAtomic, and with
// the file Sync moved after the Rename.
func TestWriteAtomicOrder(t *testing.T) {
	_, name := newDir(t)
	r := &recFS{FS: fsx.OS{}, failAt: -1}

	if err := fsx.WriteAtomic(r, name, []byte("new"), 0o600); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}
	if !slices.Equal(r.ops, writeAtomicOps) {
		t.Fatalf("operations:\n got  %q\n want %q", r.ops, writeAtomicOps)
	}
	if got := readFile(t, name); string(got) != "new" {
		t.Errorf("contents = %q, want %q", got, "new")
	}
	fi, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 600 (RS-10)", perm)
	}
	assertNoTmp(t, name)
}

// A fault at every operation of WriteAtomic is reported, and name holds
// either the old or the new contents, never anything else. The temporary
// file never survives a fault.
//
// Seen failing with the error of the directory fsync dropped, and with the
// Remove of the temporary file dropped after a failed Sync.
func TestWriteAtomicFaultAtEveryOperation(t *testing.T) {
	ran := 0
	for i, op := range writeAtomicOps {
		t.Run(fmt.Sprintf("%d %s", i, op), func(t *testing.T) {
			ran++
			_, name := newDir(t)
			if err := os.WriteFile(name, []byte("old"), 0o600); err != nil {
				t.Fatal(err)
			}
			r := &recFS{FS: fsx.OS{}, failAt: i}

			err := fsx.WriteAtomic(r, name, []byte("new"), 0o600)
			if !errors.Is(err, errInjected) {
				t.Fatalf("WriteAtomic = %v, want the injected fault", err)
			}
			want := "old"
			if i > renameAt {
				want = "new" // the rename happened; the directory fsync is what failed
			}
			if got := readFile(t, name); string(got) != want {
				t.Errorf("contents = %q, want %q", got, want)
			}
			assertNoTmp(t, name)
		})
	}
	if ran != len(writeAtomicOps) || ran == 0 {
		t.Fatalf("ran %d faults, want %d", ran, len(writeAtomicOps))
	}
}

// A Write that returns fewer bytes and no error is still an error: a file
// holding part of data must never be renamed over name.
//
// Seen failing with the n != len(data) check removed.
func TestWriteAtomicShortWrite(t *testing.T) {
	_, name := newDir(t)
	if err := os.WriteFile(name, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := &recFS{FS: fsx.OS{}, failAt: -1, shortWrite: true}

	if err := fsx.WriteAtomic(r, name, []byte("new"), 0o600); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("WriteAtomic = %v, want io.ErrShortWrite", err)
	}
	if got := readFile(t, name); string(got) != "old" {
		t.Errorf("contents = %q, want %q", got, "old")
	}
	assertNoTmp(t, name)
}

// A temporary file left by a crash is replaced, not appended to or refused.
func TestWriteAtomicStaleTmp(t *testing.T) {
	_, name := newDir(t)
	if err := os.WriteFile(name+".tmp", []byte("stale and longer"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := fsx.WriteAtomic(fsx.OS{}, name, []byte("new"), 0o600); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}
	if got := readFile(t, name); string(got) != "new" {
		t.Errorf("contents = %q, want %q", got, "new")
	}
	assertNoTmp(t, name)
}

// A symlink planted at the temporary name is removed, never written through.
//
// Seen failing with the leading Remove and O_EXCL both dropped: the write
// then lands in the symlink's target.
func TestWriteAtomicDoesNotFollowSymlink(t *testing.T) {
	dir, name := newDir(t)
	target := filepath.Join(filepath.Dir(dir), "target")
	if err := os.WriteFile(target, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, name+".tmp"); err != nil {
		t.Fatal(err)
	}
	if err := fsx.WriteAtomic(fsx.OS{}, name, []byte("new"), 0o600); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}
	if got := readFile(t, target); string(got) != "untouched" {
		t.Errorf("symlink target = %q, want it untouched", got)
	}
	if fi, err := os.Lstat(name); err != nil || fi.Mode()&fs.ModeSymlink != 0 {
		t.Errorf("name is not a regular file: %v, %v", fi, err)
	}
}

func TestSyncDir(t *testing.T) {
	dir, _ := newDir(t)
	r := &recFS{FS: fsx.OS{}, failAt: -1}
	if err := fsx.SyncDir(r, dir); err != nil {
		t.Fatalf("SyncDir: %v", err)
	}
	if want := []string{"open dir", "sync dir", "close dir"}; !slices.Equal(r.ops, want) {
		t.Errorf("operations = %q, want %q", r.ops, want)
	}
	if err := fsx.SyncDir(fsx.OS{}, filepath.Join(dir, "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("SyncDir(missing) = %v, want fs.ErrNotExist", err)
	}
}

// A second Lock fails with ErrLocked while the first is held, even from the
// same process, and succeeds once it is released (RS-09).
//
// Seen failing with LOCK_NB removed (the second Lock blocks; the test times
// out) and with the flock call removed (the second Lock succeeds).
func TestLockIsExclusive(t *testing.T) {
	name := filepath.Join(t.TempDir(), "LOCK")

	first, err := fsx.OS{}.Lock(name)
	if err != nil {
		t.Fatalf("first Lock: %v", err)
	}
	fi, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("lock file mode = %o, want 600 (RS-10)", perm)
	}

	second, err := fsx.OS{}.Lock(name)
	if !errors.Is(err, fsx.ErrLocked) {
		if second != nil {
			_ = second.Close()
		}
		t.Fatalf("second Lock = %v, want ErrLocked", err)
	}

	if err = first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	again, err := fsx.OS{}.Lock(name)
	if err != nil {
		t.Fatalf("Lock after release: %v", err)
	}
	if err := again.Close(); err != nil {
		t.Fatal(err)
	}
}

// The lock also excludes another process, which is the deployment it exists
// for: two services opening one log.
func TestLockExcludesAnotherProcess(t *testing.T) {
	if name := os.Getenv("FSX_LOCK_CHILD"); name != "" {
		_, err := fsx.OS{}.Lock(name)
		if errors.Is(err, fsx.ErrLocked) {
			fmt.Print("locked")
			return
		}
		fmt.Printf("unexpected: %v", err)
		return
	}

	name := filepath.Join(t.TempDir(), "LOCK")
	l, err := fsx.OS{}.Lock(name)
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}
	defer func() { _ = l.Close() }()

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), exe, "-test.run=^TestLockExcludesAnotherProcess$") // #nosec G204 -- the test binary itself
	cmd.Env = append(os.Environ(), "FSX_LOCK_CHILD="+name)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("child: %v\n%s", err, out.String())
	}
	if !strings.HasPrefix(out.String(), "locked") {
		t.Fatalf("child output = %q, want it to report ErrLocked", out.String())
	}
}
