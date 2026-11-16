package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/JonasBorgesLM/tally/internal/note"
)

// cmdKeygen generates a signing key named for the log's origin and writes it
// in SPEC §5.3's encodings: the private key to OUT.key at 0600 and the
// verifier key to OUT.pub (ADR-0005). It refuses to overwrite either file,
// since replacing a key loses the ability to sign as it, and an existing
// file may be a key in use. The private key is written to its file and
// nowhere else: not to stdout, stderr, or an error (RS-07).
//
// The name is the log's origin for its whole life (SPEC §5.3): a rotated key
// keeps it (RUNBOOK, "Key rotation").
func cmdKeygen(args []string, stdout, stderr io.Writer) int {
	flags := newFlags("keygen", stderr)
	name := flags.String("name", "", "the key's name, which is the log's origin")
	out := flags.String("out", "", "the path prefix: writes PREFIX.key and PREFIX.pub")
	if err := flags.Parse(args); err != nil {
		return exitError
	}
	if *name == "" || *out == "" || flags.NArg() != 0 {
		(&output{w: stderr}).printf("tally keygen: --name and --out are required, and it takes no arguments\n")
		return exitError
	}
	keyPath, pubPath := *out+".key", *out+".pub"
	for _, p := range []string{keyPath, pubPath} {
		if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
			if err == nil {
				err = fmt.Errorf("%s already exists; keygen never overwrites a key", p)
			}
			return fail(stderr, err)
		}
	}

	skey, vkey, err := note.GenerateKey(rand.Reader, *name)
	if err != nil {
		return fail(stderr, err)
	}
	if err := writeNew(keyPath, skey+"\n", 0o600); err != nil {
		return fail(stderr, err)
	}
	if err := writeNew(pubPath, vkey+"\n", 0o644); err != nil {
		// The private key alone is useless to whoever verifies; remove it
		// so a retry starts clean. It was created by this run.
		return fail(stderr, errors.Join(err, os.Remove(keyPath)))
	}

	o := &output{w: stdout}
	o.printf("private key  %s  (mode 0600; keep it on the signing host only)\n", sanitize(keyPath))
	o.printf("verifier key %s\n", sanitize(pubPath))
	o.printf("%s\n", sanitize(vkey))
	return o.status(exitIntact)
}

// writeNew creates path with O_EXCL and mode perm, writes data, and fsyncs
// the file and its directory: a key that vanishes in a crash after keygen
// reported success is a key the operator thinks they have.
func writeNew(path, data string, perm fs.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm) // #nosec G304 -- a path the operator chose
	if err != nil {
		return err
	}
	n, err := f.WriteString(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return errors.Join(err, os.Remove(path))
	}
	d, err := os.Open(filepath.Dir(path)) // #nosec G304 -- the directory of a path the operator chose
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		return errors.Join(err, d.Close())
	}
	return d.Close()
}
