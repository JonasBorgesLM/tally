package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/anchor"
	"github.com/JonasBorgesLM/tally/filestore"
)

// output writes to w and keeps the first error, so a command can tell whether
// what it printed arrived: a verdict that failed to print must not exit 0.
type output struct {
	w   io.Writer
	err error
}

func (o *output) printf(format string, a ...any) {
	if o.err == nil {
		_, o.err = fmt.Fprintf(o.w, format, a...)
	}
}

// status returns code, or exitError if the output failed.
func (o *output) status(code int) int {
	if o.err != nil {
		return exitError
	}
	return code
}

// maxKeyFile bounds --key-file (RS-05, audit A-08): a verifier key is under
// 200 bytes, so this is thousands of them, and a mistaken path to a large file
// fails rather than fills memory.
const maxKeyFile = 1 << 20

// readBounded reads path, refusing one over limit bytes before reading more.
func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- a path the operator chose
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only: a close error loses no data
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is over %d bytes", path, limit)
	}
	return b, nil
}

// keyList is a repeatable --key flag.
type keyList []string

func (k *keyList) String() string { return strings.Join(*k, ",") }

func (k *keyList) Set(v string) error {
	*k = append(*k, v)
	return nil
}

// keyFlags adds --key and --key-file to fs, and returns a function that
// collects the verifier keys from both.
func keyFlags(fs *flag.FlagSet) func() (tally.Verifiers, error) {
	var keys keyList
	fs.Var(&keys, "key", "a trusted verifier key (repeatable)")
	file := fs.String("key-file", "", "a file of trusted verifier keys, one per line")
	return func() (tally.Verifiers, error) {
		all := append([]string(nil), keys...)
		if *file != "" {
			b, err := readBounded(*file, maxKeyFile)
			if err != nil {
				return tally.Verifiers{}, err
			}
			for _, l := range strings.Split(string(b), "\n") {
				if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
					all = append(all, l)
				}
			}
		}
		if len(all) == 0 {
			return tally.Verifiers{}, errors.New("no verifier key: give --key or --key-file")
		}
		return tally.NewVerifiers(all...)
	}
}

// newFlags returns a FlagSet that reports errors to stderr and does not exit.
func newFlags(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

// fail prints err, sanitized, and returns the usage-or-IO status.
func fail(stderr io.Writer, err error) int {
	(&output{w: stderr}).printf("tally: %s\n", sanitize(err.Error()))
	return exitError
}

// existingDir refuses a path that is not an existing directory: a reader must
// never create what it was asked to read, and a mistyped path must not read
// as an empty log or an empty anchor.
func existingDir(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}
	return nil
}

// cmdVerify verifies a log directory (SPEC §7) and prints the report. Its
// status is 0 for an intact log, 1 for any violation, and 2 when it could not
// verify: an IO error is never a report (RS-04).
func cmdVerify(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlags("verify", stderr)
	dir := fs.String("dir", "", "the log directory")
	keys := keyFlags(fs)
	anchorDir := fs.String("anchor", "", "a copy of the anchor, read off the host")
	full := fs.Bool("require-fully-attested", false, "make an unattested tail a violation (RF-18)")
	from := fs.String("from", "", "a trusted checkpoint file to verify incrementally from (RF-08)")
	heartbeat := fs.Duration("heartbeat", 0, "the heartbeat interval to check the anchor's checkpoints against")
	tolerance := fs.Duration("tolerance", 0, "the slack allowed on --heartbeat")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	if *dir == "" || fs.NArg() != 0 {
		(&output{w: stderr}).printf("tally verify: --dir is required, and takes no arguments\n")
		return exitError
	}
	if *heartbeat > 0 && *anchorDir == "" {
		(&output{w: stderr}).printf("tally verify: --heartbeat needs --anchor: heartbeats are judged on anchored checkpoints\n")
		return exitError
	}
	verifiers, err := keys()
	if err != nil {
		return fail(stderr, err)
	}
	if err = existingDir(*dir); err != nil {
		return fail(stderr, err)
	}
	src, err := filestore.OpenReader(*dir)
	if err != nil {
		return fail(stderr, err)
	}

	var opts []tally.VerifyOption
	if *anchorDir != "" {
		if err = existingDir(*anchorDir); err != nil {
			return fail(stderr, err)
		}
		a, aerr := anchor.NewDir(*anchorDir)
		if aerr != nil {
			return fail(stderr, aerr)
		}
		opts = append(opts, tally.WithAnchor(a))
	}
	if *full {
		opts = append(opts, tally.WithRequireFullyAttested())
	}
	if *from != "" {
		cp, rerr := readCheckpointFile(*from)
		if rerr != nil {
			return fail(stderr, rerr)
		}
		opts = append(opts, tally.FromCheckpoint(cp))
	}
	if *heartbeat > 0 {
		opts = append(opts, tally.WithHeartbeat(*heartbeat, *tolerance, time.Now()))
	}

	rep, err := tally.Verify(ctx, src, verifiers, opts...)
	if err != nil {
		(&output{w: stderr}).printf("tally verify: could not verify: %s\n", sanitize(err.Error()))
		return exitError
	}
	return printReport(stdout, rep)
}

// printReport prints rep, one field per line, every log-derived value
// sanitized, and returns the exit status it means. The verdict is the last
// line, and no field can end a line early to forge one (RS-13).
func printReport(w io.Writer, rep *tally.Report) int {
	bw := bufio.NewWriter(w)
	o := &output{w: bw}
	o.printf("size %d\n", rep.Size)
	o.printf("attested %d\n", rep.AttestedSize)
	o.printf("unattested %d\n", rep.UnattestedEntries)
	for _, f := range rep.Failures {
		o.printf("violation %s at %d: %s\n", sanitize(f.Kind.String()), f.Seq, sanitize(f.Note))
	}
	code := exitIntact
	if rep.OK() {
		o.printf("result intact\n")
	} else {
		o.printf("result violated (%d)\n", len(rep.Failures))
		code = exitViolation
	}
	if err := bw.Flush(); err != nil {
		return exitError
	}
	return o.status(code)
}

// cmdHead prints the size and last leaf hash the log directory holds, read
// without verifying anything: it is what the host stored, not what is
// attested. A malformed segment is a violation, status 1.
func cmdHead(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlags("head", stderr)
	dir := fs.String("dir", "", "the log directory")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	if *dir == "" || fs.NArg() != 0 {
		(&output{w: stderr}).printf("tally head: --dir is required, and takes no arguments\n")
		return exitError
	}
	if err := existingDir(*dir); err != nil {
		return fail(stderr, err)
	}
	src, err := filestore.OpenReader(*dir)
	if err != nil {
		return fail(stderr, err)
	}
	var (
		last tally.Record
		read bool
	)
	for r, err := range src.Records(ctx, 0) {
		var me *tally.MalformedError
		if errors.As(err, &me) {
			(&output{w: stderr}).printf("tally head: malformed at leaf %d: %s\n", me.Seq, sanitize(me.Err.Error()))
			return exitViolation
		}
		if err != nil {
			return fail(stderr, err)
		}
		last, read = r, true
	}
	if !read {
		return fail(stderr, errors.New("the directory holds no record"))
	}
	leaf := tally.LeafHash(last.Body)
	o := &output{w: stdout}
	o.printf("size %d\nhead %s\nunverified: run tally verify for what is attested\n",
		last.Seq+1, base64.StdEncoding.EncodeToString(leaf[:]))
	return o.status(exitIntact)
}

// cmdCheckpoint prints the newest stored checkpoint whose signature verifies
// under the given keys, as a signed note, for an auditor or an anchor. Status
// 1 means checkpoints are stored and none verifies; 2, that none is stored.
func cmdCheckpoint(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlags("checkpoint", stderr)
	dir := fs.String("dir", "", "the log directory")
	keys := keyFlags(fs)
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	if *dir == "" || fs.NArg() != 0 {
		(&output{w: stderr}).printf("tally checkpoint: --dir is required, and takes no arguments\n")
		return exitError
	}
	verifiers, err := keys()
	if err != nil {
		return fail(stderr, err)
	}
	if err = existingDir(*dir); err != nil {
		return fail(stderr, err)
	}
	src, err := filestore.OpenReader(*dir)
	if err != nil {
		return fail(stderr, err)
	}
	var (
		newest tally.SignedCheckpoint
		stored int
	)
	for cp, err := range src.Checkpoints(ctx) {
		if err != nil {
			return fail(stderr, err)
		}
		stored++
		if tally.VerifyCheckpoint(cp, verifiers) == nil {
			newest = cp
		}
	}
	switch {
	case stored == 0:
		return fail(stderr, errors.New("no checkpoint is stored"))
	case newest == nil:
		(&output{w: stderr}).printf("tally checkpoint: %d checkpoints stored, none verifies under the given keys\n", stored)
		return exitViolation
	}
	// The note is printed as it is: sanitizing changes nothing in one that
	// follows SPEC §5, and defuses one that does not.
	o := &output{w: stdout}
	o.printf("%s", sanitizeLines(string(newest)))
	return o.status(exitIntact)
}
