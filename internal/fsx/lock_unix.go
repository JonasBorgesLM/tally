//go:build linux || darwin

package fsx

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

// Lock takes flock(LOCK_EX|LOCK_NB) on name (RS-09).
//
// flock belongs to the open file description, not the process: a second Lock
// on the same file fails even from the same process, which is what makes a
// second Open of one log fail and what lets a test prove it. flock is
// unreliable on NFS and SMB, which are unsupported (ADR-0008).
func (OS) Lock(name string) (io.Closer, error) {
	f, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- path chosen by filestore, not by input
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil { // #nosec G115 -- a file descriptor fits in an int
		cerr := f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errors.Join(fmt.Errorf("%w: %s", ErrLocked, name), cerr)
		}
		return nil, errors.Join(&os.PathError{Op: "flock", Path: name, Err: err}, cerr)
	}
	// Closing the descriptor releases the lock.
	return f, nil
}
