//go:build darwin

package fsx

import (
	"errors"
	"os"
	"syscall"
)

// PreallocationSupported reports whether Preallocate can work on this
// platform. macOS's F_PREALLOCATE takes a struct through fcntl, which Go's
// syscall package can pass only with unsafe, and the module uses none
// (RS-11).
const PreallocationSupported = false

// FreeSpace returns the bytes available to an unprivileged writer on the
// filesystem holding dir (statfs f_bavail).
func (OS) FreeSpace(dir string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, &os.PathError{Op: "statfs", Path: dir, Err: err}
	}
	return st.Bavail * uint64(st.Bsize), nil
}

// Preallocate is unsupported on macOS: see PreallocationSupported.
func (OS) Preallocate(string, int64) error {
	return errors.ErrUnsupported
}
