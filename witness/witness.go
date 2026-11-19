// Package witness is a c2sp.org/tlog-witness witness for tally logs (#61,
// ADR-0021): it cosigns a log's tlog-checkpoint only when it is consistent
// with the last one it cosigned for that log, so a host cannot get two
// different histories witnessed.
//
// It runs on a machine other than the log's host, which pushes to it with
// add-checkpoint; the witness never connects to the host and holds no
// credential there. Its state is one file per log, the last checkpoint it
// cosigned, written durably before it answers, under one lock with the size
// check, so that two requests can never roll it back.
//
// The cosignature is cosignature/v1 over Ed25519 (c2sp.org/tlog-cosignature).
// One witness is one party to trust: it detects split view only for a
// verifier that requires its cosignature, and only while it is honest and
// apart from the host (T-09).
package witness

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/JonasBorgesLM/tally/internal/fsx"
	"github.com/JonasBorgesLM/tally/internal/merkle"
	"github.com/JonasBorgesLM/tally/internal/note"
)

const (
	// maxProofLines is c2sp.org/tlog-witness's bound on a request's proof.
	maxProofLines = 63
	// maxRequest bounds a request before it is read (RS-05): the old size
	// line, the proof, and a note at its ceiling.
	maxRequest = 32 + maxProofLines*45 + 1 + note.MaxSize

	stateExt = ".checkpoint"
	dirPerm  = 0o700
	filePerm = 0o600
)

// ErrLoosePermissions is returned by New for a state directory that group or
// other can reach: anyone who can write it can roll the witness back.
var ErrLoosePermissions = errors.New("witness: the state directory is looser than 0700")

// Witness cosigns consistent checkpoints for the logs it was given. It is an
// http.Handler serving POST /add-checkpoint; it is safe for concurrent use.
type Witness struct {
	cosigner *note.Cosigner
	logs     map[string]*note.Verifier // by origin
	dir      string
	fsys     fsx.FS
	now      func() time.Time

	mu sync.Mutex // the size check and the state write, together
}

// New returns a witness that cosigns with the witness key cosignerKey (type
// 0x04) for the logs whose verifier keys are logKeys, one per origin, and
// keeps its state in dir, which must exist with mode 0700.
func New(dir, cosignerKey string, logKeys []string) (*Witness, error) {
	return newWitness(fsx.OS{}, dir, cosignerKey, logKeys, time.Now)
}

func newWitness(fsys fsx.FS, dir, cosignerKey string, logKeys []string, now func() time.Time) (*Witness, error) {
	fi, err := fsys.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("witness: %w", err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("witness: %s is not a directory", dir)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: %s has mode %04o", ErrLoosePermissions, dir, fi.Mode().Perm())
	}
	c, err := note.NewCosigner(cosignerKey)
	if err != nil {
		return nil, fmt.Errorf("witness: the witness key: %w", err)
	}
	if len(logKeys) == 0 {
		return nil, errors.New("witness: no log to witness")
	}
	logs := make(map[string]*note.Verifier, len(logKeys))
	for i, k := range logKeys {
		v, err := note.NewVerifier(k)
		if err != nil {
			return nil, fmt.Errorf("witness: log key %d: %w", i, err)
		}
		if v.Witness() {
			return nil, fmt.Errorf("witness: log key %d is a witness's key, not a log's", i)
		}
		if _, dup := logs[v.Name()]; dup {
			return nil, fmt.Errorf("witness: two keys for the log %q", v.Name())
		}
		logs[v.Name()] = v
	}
	return &Witness{cosigner: c, logs: logs, dir: dir, fsys: fsys, now: now}, nil
}

// response is an add-checkpoint answer: a status, and a body with its type.
type response struct {
	status int
	ctype  string
	body   string
}

func refuse(status int, why string) response {
	return response{status: status, ctype: "text/plain; charset=utf-8", body: why + "\n"}
}

// ServeHTTP serves c2sp.org/tlog-witness's POST /add-checkpoint.
func (w *Witness) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/add-checkpoint" {
		http.NotFound(rw, r)
		return
	}
	if r.Method != http.MethodPost {
		rw.Header().Set("Allow", http.MethodPost)
		http.Error(rw, "add-checkpoint is a POST", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(rw, r.Body, maxRequest))
	if err != nil {
		http.Error(rw, "the request is too large or unreadable", http.StatusRequestEntityTooLarge)
		return
	}
	resp := w.addCheckpoint(body)
	rw.Header().Set("Content-Type", resp.ctype)
	rw.WriteHeader(resp.status)
	_, _ = io.WriteString(rw, resp.body) //nolint:errcheck // the client is gone; the state is already written
}

// addCheckpoint is add-checkpoint on a request body; ServeHTTP writes its
// result.
func (w *Witness) addCheckpoint(body []byte) response {
	old, proof, msg, err := parseRequest(body)
	if err != nil {
		return refuse(http.StatusBadRequest, err.Error())
	}
	text, _, ok := bytes.Cut(msg, []byte("\n\n"))
	if !ok {
		return refuse(http.StatusBadRequest, "the checkpoint is not a signed note")
	}
	origin, _, _ := strings.Cut(string(text), "\n")
	logKey, known := w.logs[origin]
	if !known {
		return refuse(http.StatusNotFound, "unknown log")
	}
	n, err := note.Open(msg, []*note.Verifier{logKey})
	switch {
	case errors.Is(err, note.ErrMalformed), errors.Is(err, note.ErrNonCanonical):
		return refuse(http.StatusBadRequest, "the checkpoint note is malformed")
	case err != nil:
		return refuse(http.StatusForbidden, "no valid signature from the log's key")
	}
	cp, err := parseTlog(n.Text)
	if err != nil {
		return refuse(http.StatusBadRequest, err.Error())
	}
	if old > cp.size {
		return refuse(http.StatusBadRequest, "the old size is larger than the checkpoint's")
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	stored, err := w.load(origin)
	if err != nil {
		return refuse(http.StatusInternalServerError, "the witness cannot read its state")
	}
	if old != stored.size {
		return response{status: http.StatusConflict, ctype: "text/x.tlog.size", body: strconv.FormatUint(stored.size, 10) + "\n"}
	}
	switch old {
	case 0:
		if len(proof) != 0 {
			return refuse(http.StatusUnprocessableEntity, "a proof from size 0")
		}
	case cp.size:
		if cp.root != stored.root {
			return refuse(http.StatusUnprocessableEntity, "a different root at the size already witnessed")
		}
	default:
		if merkle.VerifyConsistency(old, cp.size, proof, stored.root, cp.root) != nil {
			return refuse(http.StatusUnprocessableEntity, "the consistency proof does not verify")
		}
	}
	// Durable before the answer: a cosignature for a size the witness could
	// forget would let it cosign a fork of it after a restart.
	if err = fsx.WriteAtomic(w.fsys, w.statePath(origin), n.Text, filePerm); err != nil {
		return refuse(http.StatusInternalServerError, "the witness cannot write its state")
	}
	line, err := note.Cosign(n.Text, w.cosigner, w.now())
	if err != nil {
		return refuse(http.StatusInternalServerError, "the witness cannot cosign")
	}
	return response{status: http.StatusOK, ctype: "text/plain; charset=utf-8", body: line}
}

// state is what the witness keeps per log: the last size and root cosigned.
type state struct {
	size uint64
	root [32]byte
}

func (w *Witness) statePath(origin string) string {
	h := sha256.Sum256([]byte(origin))
	return filepath.Join(w.dir, hex.EncodeToString(h[:])+stateExt)
}

// load reads the last checkpoint cosigned for origin, or the zero state.
func (w *Witness) load(origin string) (state, error) {
	f, err := w.fsys.OpenFile(w.statePath(origin), os.O_RDONLY, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return state{}, nil
	}
	if err != nil {
		return state{}, err
	}
	defer f.Close() //nolint:errcheck // read-only: a close error loses no data
	b, err := io.ReadAll(io.LimitReader(f, note.MaxSize+1))
	if err != nil {
		return state{}, err
	}
	cp, err := parseTlog(b)
	if err != nil {
		return state{}, fmt.Errorf("witness: the stored checkpoint: %w", err)
	}
	return state(cp), nil
}

// parseRequest is c2sp.org/tlog-witness's add-checkpoint body: "old <size>",
// at most 63 base64 proof hashes, a blank line, the checkpoint note.
func parseRequest(body []byte) (old uint64, proof [][32]byte, msg []byte, err error) {
	line, rest, ok := bytes.Cut(body, []byte("\n"))
	if !ok {
		return 0, nil, nil, errors.New("no old size line")
	}
	sizeText, ok := strings.CutPrefix(string(line), "old ")
	if !ok {
		return 0, nil, nil, errors.New("the first line is not old <size>")
	}
	if old, err = parseDecimal(sizeText, true); err != nil {
		return 0, nil, nil, err
	}
	for {
		line, rest, ok = bytes.Cut(rest, []byte("\n"))
		if !ok {
			return 0, nil, nil, errors.New("no blank line before the checkpoint")
		}
		if len(line) == 0 {
			return old, proof, rest, nil
		}
		if len(proof) == maxProofLines {
			return 0, nil, nil, fmt.Errorf("more than %d proof lines", maxProofLines)
		}
		h, herr := parseHash(string(line))
		if herr != nil {
			return 0, nil, nil, herr
		}
		proof = append(proof, h)
	}
}

// tlogCheckpoint is a parsed tlog-checkpoint body.
type tlogCheckpoint struct {
	size uint64
	root [32]byte
}

// parseTlog is a tlog-checkpoint body as tally writes it (SPEC §5.2): origin,
// size, root, and no extension line.
func parseTlog(text []byte) (tlogCheckpoint, error) {
	if !bytes.HasSuffix(text, []byte("\n")) {
		return tlogCheckpoint{}, errors.New("the checkpoint does not end in a newline")
	}
	lines := strings.Split(string(text[:len(text)-1]), "\n")
	if len(lines) != 3 {
		return tlogCheckpoint{}, errors.New("not a three-line tlog-checkpoint: extension lines are not accepted")
	}
	size, err := parseDecimal(lines[1], false)
	if err != nil {
		return tlogCheckpoint{}, err
	}
	root, err := parseHash(lines[2])
	if err != nil {
		return tlogCheckpoint{}, err
	}
	return tlogCheckpoint{size: size, root: root}, nil
}

// parseDecimal is a size: ASCII decimal, no leading zero, at least 1 unless
// zero is allowed.
func parseDecimal(s string, zero bool) (uint64, error) {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != s || (n == 0 && !zero) {
		return 0, fmt.Errorf("%q is not a size", s)
	}
	return n, nil
}

// parseHash is canonical, padded, standard base64 of 32 bytes.
func parseHash(s string) ([32]byte, error) {
	var h [32]byte
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) != 32 || base64.StdEncoding.EncodeToString(raw) != s {
		return h, errors.New("a hash is not canonical base64 of 32 bytes")
	}
	copy(h[:], raw)
	return h, nil
}
