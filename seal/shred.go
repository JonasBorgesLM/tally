package seal

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/internal/fsx"
)

// Shred destroys ref's DEK (RF-11, RF-12): every payload sealed under it
// stops opening, with tally.ErrShredded, and the log still verifies, since a
// verifier hashes the ciphertext as stored and needs no DEK. A later Resolve
// of the same identifier makes a new incarnation, a new random ref that no
// vault file links to the old one (ADR-0011).
//
// It removes the ref's file first and fsyncs its directory, so the
// destruction is durable before anything else; then the identifier's index
// entry, if it still names this ref, and fsyncs that directory. A crash in
// between leaves an index entry whose ref has no DEK, which Resolve treats as
// shredded. Shred is idempotent: a ref with no DEK, shredded or never made, is
// nil.
//
// **Removing a file does not destroy its bytes** on an SSD or a journaling
// filesystem, and a backup of the vault from before the shred undoes it
// (ADR-0020, R-34; #46 documents every limit).
func (v *FileVault) Shred(ctx context.Context, ref tally.SubjectRef) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return tally.ErrClosed
	}
	b, err := v.read(refName(ref))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	idx, _, _, err := decodeRef(b)
	if err != nil {
		return err
	}
	if rerr := v.remove(refName(ref)); rerr != nil {
		return rerr
	}

	// The index entry goes too, unless a new incarnation already owns it.
	idxName := filepath.Join(idxDir, fmt.Sprintf("%x", idx))
	ib, err := v.read(idxName)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if named, derr := decodeIdx(ib); derr != nil || named != ref {
		return derr
	}
	return v.remove(idxName)
}

// remove deletes a vault file and fsyncs its directory, so the deletion
// survives a crash.
func (v *FileVault) remove(name string) error {
	path := filepath.Join(v.dir, name)
	if err := v.fsys.Remove(path); err != nil {
		return fmt.Errorf("seal: %w", err)
	}
	if err := fsx.SyncDir(v.fsys, filepath.Dir(path)); err != nil {
		return fmt.Errorf("seal: %w", err)
	}
	return nil
}
