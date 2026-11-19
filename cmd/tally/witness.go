package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/anchor"
	"github.com/JonasBorgesLM/tally/filestore"
	"github.com/JonasBorgesLM/tally/internal/merkle"
	"github.com/JonasBorgesLM/tally/witness"
)

// The witness, both sides (#61, ADR-0021): serve runs on the witness's own
// machine; push runs on the log's host and is the only thing that talks to it.

// cmdWitness dispatches tally witness serve | push.
func cmdWitness(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		(&output{w: stderr}).printf("tally witness: serve or push\n")
		return exitError
	}
	switch args[0] {
	case "serve":
		return cmdWitnessServe(ctx, args[1:], stdout, stderr)
	case "push":
		return cmdWitnessPush(ctx, args[1:], stdout, stderr)
	default:
		(&output{w: stderr}).printf("tally witness: unknown command %s: serve or push\n", sanitize(args[0]))
		return exitError
	}
}

// maxWitnessKeyFile bounds a key file before it is read (RS-05).
const maxWitnessKeyFile = 4 << 10

// cmdWitnessServe serves c2sp.org/tlog-witness's add-checkpoint for the logs
// given, until interrupted. Its state directory must be 0700, and its key
// file is the witness's private key, which never leaves this machine.
func cmdWitnessServe(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlags("witness serve", stderr)
	dir := fs.String("dir", "", "the witness's state directory, mode 0700")
	keyFile := fs.String("key-file", "", "the witness's private key, from tally keygen --witness")
	addr := fs.String("addr", ":7380", "the address to listen on")
	var logs keyList
	fs.Var(&logs, "log", "a log's verifier key, which names its origin (repeatable)")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	if *dir == "" || *keyFile == "" || len(logs) == 0 || fs.NArg() != 0 {
		(&output{w: stderr}).printf("tally witness serve: --dir, --key-file and --log are required, and it takes no arguments\n")
		return exitError
	}
	skey, err := readBounded(*keyFile, maxWitnessKeyFile)
	if err != nil {
		return fail(stderr, err)
	}
	w, err := witness.New(*dir, strings.TrimSpace(string(skey)), logs)
	if err != nil {
		return fail(stderr, err)
	}
	srv := &http.Server{
		Addr:              *addr,
		Handler:           w,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe() }()
	(&output{w: stdout}).printf("witness serving %d logs on %s\n", len(logs), sanitize(*addr))
	select {
	case err = <-done:
		return fail(stderr, err)
	case <-ctx.Done():
		// The serving context is already done; shutting down gets its own
		// bounded time, as a child of it that ignores its cancellation.
		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if err = srv.Shutdown(shutdown); err != nil {
			return fail(stderr, err)
		}
		return exitIntact
	}
}

// cmdWitnessPush sends the log's newest tlog-checkpoint to the witness, with
// the consistency proof from the size the witness holds, and publishes the
// cosigned note to the anchor spool, where the anchor pulls it. Status 1 means
// the witness refused the log's history (a fork, or a rollback below what it
// cosigned) or a prune left it behind; 2, usage, IO or a misconfiguration.
func cmdWitnessPush(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlags("witness push", stderr)
	dir := fs.String("dir", "", "the log directory, read only")
	keys := keyFlags(fs)
	url := fs.String("witness", "", "the witness's base URL; add-checkpoint is under it")
	witnessKey := fs.String("witness-key", "", "the witness's verifier key, to check its cosignature")
	anchorDir := fs.String("anchor", "", "the anchor spool the cosigned checkpoint is published to")
	timeout := fs.Duration("timeout", 30*time.Second, "how long one request to the witness may take")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	if *dir == "" || *url == "" || *witnessKey == "" || *anchorDir == "" || fs.NArg() != 0 {
		(&output{w: stderr}).printf("tally witness push: --dir, --witness, --witness-key and --anchor are required\n")
		return exitError
	}
	verifiers, err := keys()
	if err != nil {
		return fail(stderr, err)
	}
	wkeys, err := tally.NewVerifiers(*witnessKey)
	if err != nil {
		return fail(stderr, fmt.Errorf("--witness-key: %w", err))
	}
	for _, d := range []string{*dir, *anchorDir} {
		if err = existingDir(d); err != nil {
			return fail(stderr, err)
		}
	}
	src, err := filestore.OpenReader(*dir)
	if err != nil {
		return fail(stderr, err)
	}
	cp, err := newestTlog(ctx, src, verifiers)
	if err != nil {
		return fail(stderr, err)
	}
	size, err := tally.CheckpointSize(cp)
	if err != nil {
		return fail(stderr, err)
	}
	client := &http.Client{Timeout: *timeout}
	post := func(old uint64, proof [][32]byte) (int, []byte, error) {
		return addCheckpoint(ctx, client, *url, old, proof, cp)
	}

	// The witness's size, learned from a 409: a push never trusts a size it
	// remembers, since the witness is the one that must not roll back.
	status, body, err := post(0, nil)
	if err != nil {
		return fail(stderr, err)
	}
	if status == http.StatusConflict {
		old, perr := strconv.ParseUint(strings.TrimSuffix(string(body), "\n"), 10, 64)
		if perr != nil {
			return fail(stderr, fmt.Errorf("the witness's 409 does not name a size: %q", sanitize(string(body))))
		}
		if old > size {
			(&output{w: stderr}).printf("tally witness push: the witness has cosigned %d leaves, above this log's newest checkpoint at %d: "+
				"the log was rolled back, or this is not the history it witnessed (T-08, T-09)\n", old, size)
			return exitViolation
		}
		var proof [][32]byte
		if old < size {
			if proof, err = consistencyProof(ctx, src, old, size); errors.Is(err, merkle.ErrPruned) {
				(&output{w: stderr}).printf("tally witness push: the witness holds size %d, below the log's first record: "+
					"a prune left it behind, and no proof reaches it; prune only at a checkpoint the witness cosigned\n", old)
				return exitViolation
			} else if err != nil {
				return fail(stderr, err)
			}
		}
		if status, body, err = post(old, proof); err != nil {
			return fail(stderr, err)
		}
	}
	switch status {
	case http.StatusOK:
	case http.StatusUnprocessableEntity:
		(&output{w: stderr}).printf("tally witness push: the witness refused the log's history: %s", sanitize(string(body)))
		return exitViolation
	default:
		return fail(stderr, fmt.Errorf("the witness answered %d: %s", status, sanitize(strings.TrimSpace(string(body)))))
	}

	// Never publish a cosignature not checked: the anchor is evidence.
	cosigned := append(bytes.Clone(cp), body...)
	if n, cerr := tally.CountCosignatures(cosigned, verifiers, wkeys); cerr != nil || n != 1 {
		return fail(stderr, fmt.Errorf("the witness's answer is not its cosignature of this checkpoint (%d verified): %w", n, cerr))
	}
	a, err := anchor.NewDir(*anchorDir)
	if err != nil {
		return fail(stderr, err)
	}
	if err = a.Publish(ctx, cosigned); err != nil {
		return fail(stderr, err)
	}
	o := &output{w: stdout}
	o.printf("witnessed %d\n", size)
	return o.status(exitIntact)
}

// newestTlog is the newest stored tlog-checkpoint that verifies.
func newestTlog(ctx context.Context, src *filestore.Reader, keys tally.Verifiers) (tally.SignedCheckpoint, error) {
	var newest tally.SignedCheckpoint
	for cp, err := range src.Checkpoints(ctx) {
		if err != nil {
			return nil, err
		}
		if isTlog(cp) && tally.VerifyCheckpoint(cp, keys) == nil {
			newest = cp
		}
	}
	if newest == nil {
		return nil, errors.New("no tlog-checkpoint verifies under the given keys (a log written by v0.1, or pruned by it, has none)")
	}
	return newest, nil
}

// consistencyProof is the proof from size old to size n of the stored log,
// built from its leaves and its pruned range (SPEC §3.6). merkle.ErrPruned
// when old is below the first record kept.
func consistencyProof(ctx context.Context, src *filestore.Reader, old, n uint64) ([][32]byte, error) {
	start, prefix := uint64(0), [][32]byte(nil)
	first := true
	var leaves [][32]byte
	for r, err := range src.Records(ctx, 0) {
		if err != nil {
			return nil, err
		}
		if first {
			first = false
			if r.Seq > 0 {
				s, p, ok, rerr := src.CompactRange(ctx)
				if rerr != nil {
					return nil, rerr
				}
				if !ok || s < r.Seq {
					return nil, merkle.ErrPruned
				}
				start, prefix = s, p
			}
		}
		if r.Seq < start {
			continue
		}
		if r.Seq >= n {
			break
		}
		leaves = append(leaves, tally.LeafHash(r.Body))
	}
	tree, err := merkle.NewTree(start, prefix, leaves)
	if err != nil {
		return nil, err
	}
	return tree.ConsistencyProof(old, n)
}

// addCheckpoint posts one c2sp.org/tlog-witness add-checkpoint request.
func addCheckpoint(ctx context.Context, client *http.Client, base string, old uint64, proof [][32]byte, cp tally.SignedCheckpoint) (status int, body []byte, err error) {
	var b bytes.Buffer
	fmt.Fprintf(&b, "old %d\n", old)
	for _, h := range proof {
		b.WriteString(base64.StdEncoding.EncodeToString(h[:]) + "\n")
	}
	b.WriteString("\n")
	b.Write(cp)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(base, "/")+"/add-checkpoint", &b)
	if err != nil {
		return 0, nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close() //nolint:errcheck // read-only: a close error loses no data
	body, err = io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, body, nil
}
