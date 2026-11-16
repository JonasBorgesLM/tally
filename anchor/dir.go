// Package anchor holds Dir, a create-only spool of checkpoints for something
// off the host to pull from.
//
// **A directory the host can write to is not an anchor** (RS-17, T-21). Whoever
// has root on the host can rewrite or delete anything in it, and with that
// the protection against truncation, rollback, a rewrite with the key and a
// heartbeat gap (T-05, T-07, T-08, T-15) is gone. A Dir is only the host's
// half: it never overwrites or deletes a checkpoint, so that a puller off the
// host, holding a credential the host does not have, can copy each one once
// and keep it where the host cannot reach. Until it is pulled, a checkpoint
// in a Dir is exactly as safe as the host. The README gives recipes for the
// other half; the library cannot check that one exists.
package anchor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"iter"
	"os"
	"path/filepath"
	"slices"

	"github.com/JonasBorgesLM/tally"
)

// ErrConflict means a checkpoint file already exists under the name Publish
// would give, with other contents. Names come from the contents' hash, so an
// honest spool never produces it: someone wrote that file.
var ErrConflict = errors.New("anchor: a different file already holds this checkpoint's name")

// Dir is a create-only spool of checkpoints in one directory. It implements
// tally.Anchor for the host and tally.AnchorReader for whoever reads the
// pulled copy. Each checkpoint is a file named by its size and the SHA-256 of
// its bytes, written once with mode 0600 and never changed (RS-10).
type Dir struct {
	dir string
}

var (
	_ tally.Anchor       = (*Dir)(nil)
	_ tally.AnchorReader = (*Dir)(nil)
)

// isNoteName reports whether name is one Publish writes: 16 lowercase hex
// digits of size, a dash, 64 of SHA-256, and ".note".
func isNoteName(name string) bool {
	const ext = ".note"
	if len(name) != 16+1+64+len(ext) || name[16] != '-' || name[16+1+64:] != ext {
		return false
	}
	for i, c := range name[:16+1+64] {
		if i == 16 {
			continue
		}
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// NewDir returns a Dir over dir, creating it with mode 0700 if it does not
// exist.
func NewDir(dir string) (*Dir, error) {
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, fmt.Errorf("anchor: %w", err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("anchor: %w", err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("anchor: %s is not a directory", dir)
	}
	return &Dir{dir: dir}, nil
}

// Publish stores cp under a name of its own, durably, and never overwrites:
// it writes a temporary file, fsyncs it, links it to the final name, which
// fails if that name exists, and fsyncs the directory. A checkpoint already
// published with the same bytes is success, since the publish queue retries
// (tally.Anchor); a different file under that name is ErrConflict.
func (d *Dir) Publish(ctx context.Context, cp tally.SignedCheckpoint) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	size, err := tally.CheckpointSize(cp)
	if err != nil {
		return fmt.Errorf("anchor: %w", err)
	}
	sum := sha256.Sum256(cp)
	name := filepath.Join(d.dir, fmt.Sprintf("%016x-%s.note", size, hex.EncodeToString(sum[:])))
	tmp := filepath.Join(d.dir, "."+filepath.Base(name)+".tmp")

	// A temporary file left by a crash is ours to remove: the final name is
	// what is never overwritten.
	if rerr := os.Remove(tmp); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
		return fmt.Errorf("anchor: %w", rerr)
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- a name derived from a hash
	if err != nil {
		return fmt.Errorf("anchor: %w", err)
	}
	n, err := f.Write(cp)
	if err == nil && n != len(cp) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("anchor: %w", errors.Join(err, os.Remove(tmp)))
	}

	// link, unlike rename, refuses an existing name: create-only.
	linkErr := os.Link(tmp, name)
	if err := os.Remove(tmp); err != nil {
		return fmt.Errorf("anchor: %w", errors.Join(linkErr, err))
	}
	if errors.Is(linkErr, fs.ErrExist) {
		existing, err := os.ReadFile(name) // #nosec G304 -- a name derived from a hash
		if err != nil {
			return fmt.Errorf("anchor: %w", err)
		}
		if !bytes.Equal(existing, cp) {
			return fmt.Errorf("%w: %s", ErrConflict, filepath.Base(name))
		}
		return nil // already published, by an earlier attempt
	}
	if linkErr != nil {
		return fmt.Errorf("anchor: %w", linkErr)
	}
	return syncDir(d.dir)
}

// Checkpoints yields every checkpoint file in the directory, in name order,
// which is size order. Other files are ignored. A file over the checkpoint
// ceiling is not read (RS-05): it ends the sequence with a
// *tally.MalformedError, which Verify reports as a violation.
//
// Run it over the copy off the host. Read on the host, it says only what the
// host chose to leave there.
func (d *Dir) Checkpoints(ctx context.Context) iter.Seq2[tally.SignedCheckpoint, error] {
	return func(yield func(tally.SignedCheckpoint, error) bool) {
		entries, err := os.ReadDir(d.dir)
		if err != nil {
			yield(nil, fmt.Errorf("anchor: %w", err))
			return
		}
		var names []string
		for _, e := range entries {
			if isNoteName(e.Name()) {
				names = append(names, e.Name())
			}
		}
		slices.Sort(names)
		for _, name := range names {
			if err := ctx.Err(); err != nil {
				yield(nil, err)
				return
			}
			cp, err := readNote(filepath.Join(d.dir, name))
			if err != nil {
				yield(nil, err)
				return
			}
			if !yield(cp, nil) {
				return
			}
		}
	}
}

// readNote reads one checkpoint file, refusing one over the ceiling before
// reading it.
func readNote(path string) (tally.SignedCheckpoint, error) {
	f, err := os.Open(path) // #nosec G304 -- a name checked by isNoteName
	if err != nil {
		return nil, fmt.Errorf("anchor: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only: a close error loses no data
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("anchor: %w", err)
	}
	if fi.Size() > tally.MaxCheckpointLen {
		return nil, &tally.MalformedError{Err: fmt.Errorf("anchor: %s is %d bytes, over the checkpoint ceiling", filepath.Base(path), fi.Size())}
	}
	b := make([]byte, fi.Size())
	if _, err := io.ReadFull(f, b); err != nil {
		return nil, fmt.Errorf("anchor: %w", err)
	}
	return b, nil
}

// syncDir fsyncs dir, so that a new name in it survives a crash.
func syncDir(dir string) error {
	f, err := os.Open(dir) // #nosec G304 -- the Dir's own directory
	if err != nil {
		return fmt.Errorf("anchor: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("anchor: %w", errors.Join(err, f.Close()))
	}
	return f.Close()
}
