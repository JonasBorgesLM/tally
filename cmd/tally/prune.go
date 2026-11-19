package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/anchor"
	"github.com/JonasBorgesLM/tally/filestore"
)

// cmdPrune removes the log's segments wholly below a checkpoint (RF-14,
// ADR-0012), and only one the anchor holds (RS-20). The library can check a
// checkpoint's signature and that it agrees with the log; only the anchor says
// it left the host, which is what makes pruning below it safe. So the
// checkpoint must verify under the keys and be in the anchor byte for byte,
// or nothing is removed.
//
// It is the one command that writes: it takes the log's lock, so it fails
// with status 2 while the application has the log open. Status 1 means the
// prune was refused; nothing was removed.
func cmdPrune(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := newFlags("prune", stderr)
	dir := flags.String("dir", "", "the log directory")
	keys := keyFlags(flags)
	anchorDir := flags.String("anchor", "", "the anchor, which must hold the checkpoint")
	cpFile := flags.String("checkpoint", "", "the checkpoint to prune at, a signed note")
	witnessKey := flags.String("witness-key", "", "a witness's verifier key: refuse to prune above what it cosigned in the anchor (ADR-0021)")
	if err := flags.Parse(args); err != nil {
		return exitError
	}
	if *dir == "" || *anchorDir == "" || *cpFile == "" || flags.NArg() != 0 {
		(&output{w: stderr}).printf("tally prune: --dir, --anchor and --checkpoint are required, and it takes no arguments\n")
		return exitError
	}
	verifiers, err := keys()
	if err != nil {
		return fail(stderr, err)
	}
	cp, err := readCheckpointFile(*cpFile)
	if err != nil {
		return fail(stderr, err)
	}
	if err = tally.VerifyCheckpoint(cp, verifiers); err != nil {
		(&output{w: stderr}).printf("tally prune: refused: %s\n", sanitize(err.Error()))
		return exitViolation
	}
	for _, d := range []string{*dir, *anchorDir} {
		if err = existingDir(d); err != nil {
			return fail(stderr, err)
		}
	}
	anchored, err := inAnchor(ctx, *anchorDir, cp)
	if err != nil {
		return fail(stderr, err)
	}
	if !anchored {
		(&output{w: stderr}).printf("tally prune: refused: the checkpoint is not in the anchor; " +
			"pruning below a checkpoint that never left the host destroys the evidence it would protect (RS-20)\n")
		return exitViolation
	}
	if *witnessKey != "" {
		size, serr := tally.CheckpointSize(cp)
		if serr != nil {
			return fail(stderr, serr)
		}
		witnessed, werr := witnessedInAnchor(ctx, *anchorDir, verifiers, *witnessKey)
		if werr != nil {
			return fail(stderr, werr)
		}
		// A consistency proof from the witness's size needs that size at or
		// above the first record a prune keeps; pruning at a size the witness
		// has cosigned guarantees it (ADR-0021, audit A2-05).
		if size > witnessed {
			(&output{w: stderr}).printf("tally prune: refused: the checkpoint covers %d leaves and the witness has cosigned %d in the anchor; "+
				"pruning above it would leave the witness no proof to follow\n", size, witnessed)
			return exitViolation
		}
	}

	s, err := filestore.Open(ctx, *dir)
	if errors.Is(err, tally.ErrLocked) {
		(&output{w: stderr}).printf("tally prune: the log is open; stop the application that writes it first\n")
		return exitError
	}
	if err != nil {
		return fail(stderr, err)
	}
	removed, err := s.Prune(ctx, cp, verifiers)
	if cerr := s.Close(); err == nil {
		err = cerr
	}
	switch {
	case errors.Is(err, filestore.ErrPruneRefused):
		(&output{w: stderr}).printf("tally prune: refused: %s\n", sanitize(err.Error()))
		return exitViolation
	case err != nil:
		return fail(stderr, err)
	}
	size, err := tally.CheckpointSize(cp)
	if err != nil {
		return fail(stderr, err)
	}
	o := &output{w: stdout}
	o.printf("pruned %d segments below leaf %d\n", removed, size)
	return o.status(exitIntact)
}

// readCheckpointFile reads a checkpoint file, refusing one over the
// checkpoint ceiling before reading it (RS-05).
func readCheckpointFile(path string) (tally.SignedCheckpoint, error) {
	f, err := os.Open(path) // #nosec G304 -- a path the operator chose
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only: a close error loses no data
	b, err := io.ReadAll(io.LimitReader(f, tally.MaxCheckpointLen+1))
	if err != nil {
		return nil, err
	}
	if len(b) > tally.MaxCheckpointLen {
		return nil, fmt.Errorf("%s is over the checkpoint ceiling of %d bytes", path, tally.MaxCheckpointLen)
	}
	return b, nil
}

// inAnchor reports whether the anchor directory holds cp, byte for byte.
func inAnchor(ctx context.Context, dir string, cp tally.SignedCheckpoint) (bool, error) {
	a, err := anchor.NewDir(dir)
	if err != nil {
		return false, err
	}
	for held, err := range a.Checkpoints(ctx) {
		if err != nil {
			return false, err
		}
		if bytes.Equal(held, cp) {
			return true, nil
		}
	}
	return false, nil
}

// witnessedInAnchor is the largest size of a tlog-checkpoint in the anchor
// that the log's keys signed and the witness cosigned, or 0.
func witnessedInAnchor(ctx context.Context, dir string, keys tally.Verifiers, witnessKey string) (uint64, error) {
	wkeys, err := tally.NewVerifiers(witnessKey)
	if err != nil {
		return 0, fmt.Errorf("--witness-key: %w", err)
	}
	a, err := anchor.NewDir(dir)
	if err != nil {
		return 0, err
	}
	var witnessed uint64
	for held, err := range a.Checkpoints(ctx) {
		if err != nil {
			return 0, err
		}
		if !isTlog(held) {
			continue
		}
		if n, cerr := tally.CountCosignatures(held, keys, wkeys); cerr != nil || n < 1 {
			continue
		}
		if size, serr := tally.CheckpointSize(held); serr == nil && size > witnessed {
			witnessed = size
		}
	}
	return witnessed, nil
}
