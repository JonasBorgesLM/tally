//go:build linux

package fsx

import (
	"errors"
	"os"
	"syscall"
)

// PreallocationSupported reports whether Preallocate can work on this
// platform.
const PreallocationSupported = true

// fallocKeepSize is FALLOC_FL_KEEP_SIZE: allocate blocks without changing the
// file's length, so a reader still finds the file ending where its data
// ends.
const fallocKeepSize = 0x01

// FreeSpace returns the bytes available to an unprivileged writer on the
// filesystem holding dir (statfs f_bavail).
func (OS) FreeSpace(dir string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, &os.PathError{Op: "statfs", Path: dir, Err: err}
	}
	return st.Bavail * uint64(st.Bsize), nil // #nosec G115 -- a block size is positive
}

// Preallocate reserves size bytes of blocks for name without changing its
// length (fallocate with FALLOC_FL_KEEP_SIZE).
func (OS) Preallocate(name string, size int64) error {
	f, err := os.OpenFile(name, os.O_WRONLY, 0) // #nosec G304 -- path chosen by filestore, not by input
	if err != nil {
		return err
	}
	if err := syscall.Fallocate(int(f.Fd()), fallocKeepSize, 0, size); err != nil { // #nosec G115 -- a file descriptor fits in an int
		return errors.Join(&os.PathError{Op: "fallocate", Path: name, Err: err}, f.Close())
	}
	return f.Close()
}
