// Package fsx is the filesystem underneath filestore: durable writes, the
// directory fsync a new file needs to survive a crash, the exclusive lock that
// makes a log single-writer, and an interface over all of it so tests can
// record or fail every operation (RNF-11).
//
// Every helper here takes an FS rather than calling os directly. That is the
// point of the package: a fault-injecting FS fails one operation at a time, and
// a recording FS asserts the order, which is the property durability rests on.
//
// Linux and macOS only (RNF-09). On macOS, os.File.Sync is F_FULLFSYNC, so a
// Sync here reaches the disk and not only its cache.
package fsx

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// ErrLocked means another open file description holds the lock, in this
// process or another (RS-09). filestore reports it as tally.ErrLocked.
var ErrLocked = errors.New("fsx: locked by another writer")

// File is the part of *os.File that filestore uses.
type File interface {
	io.Reader
	io.ReaderAt
	io.Writer
	io.Closer
	Name() string
	Stat() (fs.FileInfo, error)
	Sync() error
	Truncate(size int64) error
}

// FS is the filesystem surface filestore uses. OS is the real one; tests wrap
// it to record or inject faults.
type FS interface {
	OpenFile(name string, flag int, perm fs.FileMode) (File, error)
	Rename(oldpath, newpath string) error
	Remove(name string) error

	// Lock takes an exclusive, non-blocking lock on name, creating it with
	// mode 0600 if it does not exist. If the lock is held it returns an error
	// matching ErrLocked. Closing the returned Closer releases the lock.
	Lock(name string) (io.Closer, error)
}

// OS is the FS of the host's filesystem.
type OS struct{}

// OpenFile is os.OpenFile.
func (OS) OpenFile(name string, flag int, perm fs.FileMode) (File, error) {
	return os.OpenFile(name, flag, perm) // #nosec G304 -- path chosen by filestore, not by input
}

// Rename is os.Rename.
func (OS) Rename(oldpath, newpath string) error { return os.Rename(oldpath, newpath) }

// Remove is os.Remove.
func (OS) Remove(name string) error { return os.Remove(name) }

// SyncDir fsyncs the directory dir, so that entries created, renamed or
// removed in it survive a crash. Without it a new file can vanish after a
// crash even though its own contents were synced (ADR-0009).
func SyncDir(fsys FS, dir string) error {
	d, err := fsys.OpenFile(dir, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		return errors.Join(err, d.Close())
	}
	return d.Close()
}

// WriteAtomic replaces name with data so that, after a crash at any point,
// name holds either its previous contents or data, never a mix (RS-10).
//
// The order is: create name+".tmp" with O_EXCL and perm, write, fsync, close,
// rename over name, fsync the directory. A stale temporary file from an
// earlier crash is removed first; the caller holds the log's lock, so no one
// else is writing it.
//
// An error is final for the caller (ADR-0009): once the rename has happened, a
// failed directory fsync cannot be undone, and name may or may not survive a
// crash. Before the rename, name is untouched and the temporary file is
// removed; a failure to remove it is joined to the error.
func WriteAtomic(fsys FS, name string, data []byte, perm fs.FileMode) error {
	tmp := name + ".tmp"
	if err := fsys.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	// O_EXCL also refuses to follow a symlink planted at tmp.
	f, err := fsys.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if err := writeSyncClose(f, data); err != nil {
		return errors.Join(err, fsys.Remove(tmp))
	}
	if err := fsys.Rename(tmp, name); err != nil {
		return errors.Join(err, fsys.Remove(tmp))
	}
	return SyncDir(fsys, filepath.Dir(name))
}

// writeSyncClose writes data to f, syncs it and closes it, closing f on every
// path. A short write without an error is still an error.
func writeSyncClose(f File, data []byte) error {
	n, err := f.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
