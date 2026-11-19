package filestore

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/internal/fsx"
)

// pruneMarkerName holds the checkpoint the log was last pruned at (SPEC §3.5).
const pruneMarkerName = "pruned.tlc"

// ErrPruneRefused means Prune would not prune at cp: it does not verify under
// the keys, or the log does not verify from it. Nothing was removed. Any
// other error from Prune is an IO failure.
var ErrPruneRefused = errors.New("filestore: prune refused")

// Prune removes the leading segments whose every record is below cp's size,
// and returns how many it removed (RF-14, ADR-0012). The log still starts at
// or below the checkpoint's size: when that size is a segment boundary, the
// segment holding record size-1 goes too, and the next segment's header,
// whose prev_hash is the checkpoint's head, is what a verifier matches it
// against (SPEC §7 step 5). The last segment is never removed.
//
// cp must verify under keys and agree with the stored log: Prune runs Verify
// from cp (RF-08) and refuses unless the report is OK. A checkpoint whose
// signature does not verify is refused with tally.ErrUntrustedStart (RS-20).
// Every refusal also matches ErrPruneRefused.
// Any other violation the report holds, such as a stored checkpoint under a
// key missing from keys, refuses too: pruning destroys evidence, so it
// proceeds only on a log that verifies.
//
// **Prune cannot tell whether cp was anchored** (RS-20, T-05). A valid but
// never-published checkpoint passes here; the CLI's prune compares it with
// the anchor. After a prune, a verifier needs a trusted checkpoint at or
// above the new first segment, or reports PrunedWithoutTrustedCheckpoint
// (SPEC §7 step 7).
//
// Before removing anything, Prune writes the compact range of the leaves it
// removes (SPEC §3.6), then cp to the prune marker, each atomically; then it
// removes segments oldest first and fsyncs the directory. A crash in
// between leaves a contiguous log starting at a later segment, which still
// verifies from cp. The marker is for the operator: a verifier never reads it.
// Quarantine files and the checkpoints file are never removed.
//
// A Records iteration running concurrently may fail when a segment it
// reads is removed. An IO error is final for the Store, as a write's is.
func (s *Store) Prune(ctx context.Context, cp tally.SignedCheckpoint, keys tally.Verifiers) (removed int, err error) {
	rep, err := tally.Verify(ctx, s, keys, tally.FromCheckpoint(cp))
	if errors.Is(err, tally.ErrUntrustedStart) {
		return 0, fmt.Errorf("%w: %w", ErrPruneRefused, err)
	}
	if err != nil {
		return 0, fmt.Errorf("filestore: prune: %w", err)
	}
	if !rep.OK() {
		f := rep.Failures[0]
		return 0, fmt.Errorf("%w: the log does not verify from the checkpoint: %v at %d", ErrPruneRefused, f.Kind, f.Seq)
	}
	size, err := tally.CheckpointSize(cp)
	if err != nil {
		return 0, fmt.Errorf("filestore: prune: %w", err)
	}

	// Segment i is wholly below size when the next one starts at or below
	// it. The last segment is never removed.
	plan := func() (n int, first, keep uint64, err error) {
		if err := s.usable(); err != nil {
			return 0, 0, 0, err
		}
		for n+1 < len(s.segs) && s.segs[n+1] <= size {
			n++
		}
		return n, s.segs[0], s.segs[n], nil
	}
	s.mu.Lock()
	n, first, keep, err := plan()
	s.mu.Unlock()
	if err != nil || n == 0 {
		return 0, err
	}

	// The compact range below the first record kept stands for the leaves
	// removed, so proofs still reach across them (#59, SPEC §3.6). It is
	// read before the lock, as Records takes it. A log a v0.1 writer pruned
	// has lost the leaves a range needs, and is pruned further without one.
	var rangeFile []byte
	t, err := s.treeUpTo(ctx, first, keep)
	switch {
	case errors.Is(err, errNoTree):
	case err != nil:
		return 0, fmt.Errorf("filestore: prune: the pruned range: %w", err)
	default:
		prefix, err := t.CompactRange(keep)
		if err != nil {
			return 0, fmt.Errorf("filestore: prune: the pruned range: %w", err)
		}
		rangeFile = encodePruneRange(keep, prefix)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if n2, first2, keep2, err := plan(); err != nil || n2 != n || first2 != first || keep2 != keep {
		if err != nil {
			return 0, err
		}
		return 0, fmt.Errorf("%w: the log changed while the prune was planned", ErrPruneRefused)
	}

	// The range before the marker and before any removal: a crash leaves a
	// range that covers every leaf already gone.
	if rangeFile != nil {
		if err := fsx.WriteAtomic(s.fsys, filepath.Join(s.dir, pruneRangeName), rangeFile, filePerm); err != nil {
			return 0, s.fail(err)
		}
	}
	if err := fsx.WriteAtomic(s.fsys, filepath.Join(s.dir, pruneMarkerName), cp, filePerm); err != nil {
		return 0, s.fail(err)
	}
	for removed < n {
		if err := s.fsys.Remove(filepath.Join(s.dir, segmentName(s.segs[0]))); err != nil {
			return removed, s.fail(err)
		}
		s.segs = s.segs[1:]
		removed++
	}
	if err := fsx.SyncDir(s.fsys, s.dir); err != nil {
		return removed, s.fail(err)
	}
	return removed, nil
}
