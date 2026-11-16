package filestore

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/internal/fsx"
)

// pruneMarkerName holds the checkpoint the log was last pruned at (SPEC §3.5).
const pruneMarkerName = "pruned.tlc"

// Prune removes the leading segments whose every record is below cp's size,
// and returns how many it removed (RF-14, ADR-0012). The segment holding
// record size-1 is kept, so the log still starts at or below the checkpoint.
//
// cp must verify under keys and agree with the stored log: Prune runs Verify
// from cp (RF-08) and refuses unless the report is OK. A checkpoint whose
// signature does not verify is refused with tally.ErrUntrustedStart (RS-20).
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
// Before removing anything, Prune writes cp atomically to the prune marker;
// then it removes segments oldest first and fsyncs the directory. A crash in
// between leaves a contiguous log starting at a later segment, which still
// verifies from cp. The marker is for the operator: a verifier never reads it.
// Quarantine files and the checkpoints file are never removed.
//
// A Records iteration running concurrently may fail when a segment it
// reads is removed. An IO error is final for the Store, as a write's is.
func (s *Store) Prune(ctx context.Context, cp tally.SignedCheckpoint, keys tally.Verifiers) (removed int, err error) {
	rep, err := tally.Verify(ctx, s, keys, tally.FromCheckpoint(cp))
	if err != nil {
		return 0, fmt.Errorf("filestore: prune: %w", err)
	}
	if !rep.OK() {
		f := rep.Failures[0]
		return 0, fmt.Errorf("filestore: prune: the log does not verify from the checkpoint: %v at %d", f.Kind, f.Seq)
	}
	size, err := tally.CheckpointSize(cp)
	if err != nil {
		return 0, fmt.Errorf("filestore: prune: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return 0, err
	}
	// Segment i is wholly below size when the next one starts at or below
	// it. The last segment is never removed.
	n := 0
	for n+1 < len(s.segs) && s.segs[n+1] <= size {
		n++
	}
	if n == 0 {
		return 0, nil
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
