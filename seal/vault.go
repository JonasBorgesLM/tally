package seal

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/internal/fsx"
	"github.com/JonasBorgesLM/tally/internal/wire"
)

// The vault's files (SPEC §4.1, ADR-0020).
const (
	vaultName = "VAULT"
	idxDir    = "idx"
	refsDir   = "refs"
	lockName  = "LOCK"

	vaultMagic    = "TALLYVLT"
	idxMagic      = "TALLYIDX"
	refMagic      = "TALLYREF"
	formatVersion = 1

	aadVaultKey = "tally/v1/vault-key"
	aadDEK      = "tally/v1/dek"

	keyLen      = 32
	maxWrapped  = 1024 // a wrapped 32-byte key, with room for a KMS's envelope
	maxFileSize = 4096 // every vault file is far smaller; checked before reading (RS-05)

	dirPerm  fs.FileMode = 0o700
	filePerm fs.FileMode = 0o600
)

// ErrLoosePermissions is returned by OpenFileVault for a directory that group
// or other users can access. A vault holds keys; there is no option to relax
// this.
var ErrLoosePermissions = errors.New("seal: vault directory permissions are looser than 0700")

type config struct {
	more []KEK
	rand io.Reader
	fsys fsx.FS
}

// Option configures OpenFileVault.
type Option func(*config)

// WithKEKs makes more KEKs available to unwrap vault files, beside the one
// given to OpenFileVault, which wraps everything new. A rotation interrupted
// part way is resumed with both the old and the new KEK (RotateKEK).
func WithKEKs(more ...KEK) Option {
	return func(c *config) { c.more = append(c.more, more...) }
}

// WithRand sets the source of refs, DEKs and the vault key (RNF-11). The
// default is crypto/rand. Only a test should change it.
func WithRand(r io.Reader) Option {
	return func(c *config) { c.rand = r }
}

// FileVault is a vault in one directory (ADR-0020): VAULT holds the vault key,
// wrapped; idx/ maps an HMAC of each identifier to its ref; refs/ holds each
// ref's DEK, wrapped. One process holds it at a time, through a lock, and it
// is safe for concurrent use within that process.
//
// It holds no key where fmt can print it: the vault key lives inside the
// index function's closure, and a DEK is unwrapped when it is used and not
// kept (RS-07).
type FileVault struct {
	dir  string
	fsys fsx.FS
	rand io.Reader

	mu      sync.Mutex
	lock    io.Closer
	closed  bool
	current KEK
	keks    map[string]KEK
	index   func(identifier []byte) [32]byte
}

// OpenFileVault opens the vault in dir, creating it, with mode 0700, on first
// use. kek wraps every key written from now on; a vault created now has its
// vault key wrapped under it. It fails with tally.ErrLocked if another
// process holds the vault, with ErrLoosePermissions if dir is accessible to
// group or others, and with ErrUnknownKEK if VAULT is wrapped under a KEK not
// given.
func OpenFileVault(ctx context.Context, dir string, kek KEK, opts ...Option) (*FileVault, error) {
	cfg := config{rand: rand.Reader, fsys: fsx.OS{}}
	for _, o := range opts {
		o(&cfg)
	}
	if kek == nil {
		return nil, errors.New("seal: OpenFileVault needs a KEK")
	}
	v := &FileVault{dir: dir, fsys: cfg.fsys, rand: cfg.rand, current: kek, keks: map[string]KEK{}}
	for _, k := range append([]KEK{kek}, cfg.more...) {
		if err := checkKEKID(k.ID()); err != nil {
			return nil, err
		}
		v.keks[k.ID()] = k
	}
	if err := v.prepare(); err != nil {
		return nil, err
	}
	lock, err := v.fsys.Lock(filepath.Join(dir, lockName))
	if err != nil {
		if errors.Is(err, fsx.ErrLocked) {
			return nil, fmt.Errorf("%w: %s", tally.ErrLocked, dir)
		}
		return nil, fmt.Errorf("seal: %w", err)
	}
	v.lock = lock
	if err := v.loadVaultKey(ctx); err != nil {
		return nil, errors.Join(err, lock.Close())
	}
	return v, nil
}

// prepare creates the vault's directories, or checks that dir is one no one
// else can access.
func (v *FileVault) prepare() error {
	fi, err := v.fsys.Stat(v.dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err = v.fsys.Mkdir(v.dir, dirPerm); err != nil {
			return fmt.Errorf("seal: %w", err)
		}
		if err = fsx.SyncDir(v.fsys, filepath.Dir(v.dir)); err != nil {
			return fmt.Errorf("seal: %w", err)
		}
	case err != nil:
		return fmt.Errorf("seal: %w", err)
	case !fi.IsDir():
		return fmt.Errorf("seal: %s is not a directory", v.dir)
	case fi.Mode().Perm()&0o077 != 0:
		return fmt.Errorf("%w: %s has mode %04o", ErrLoosePermissions, v.dir, fi.Mode().Perm())
	}
	for _, sub := range []string{idxDir, refsDir} {
		err := v.fsys.Mkdir(filepath.Join(v.dir, sub), dirPerm)
		if err != nil && !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("seal: %w", err)
		}
	}
	return fsx.SyncDir(v.fsys, v.dir)
}

// loadVaultKey reads VAULT, or creates it with a new vault key, and builds the
// index function around the key.
func (v *FileVault) loadVaultKey(ctx context.Context) error {
	b, err := v.read(vaultName)
	var key []byte
	switch {
	case errors.Is(err, fs.ErrNotExist):
		key = make([]byte, keyLen)
		if _, err = io.ReadFull(v.rand, key); err != nil {
			return fmt.Errorf("seal: reading a vault key: %w", err)
		}
		if werr := v.writeVaultKey(ctx, key, v.current); werr != nil {
			return werr
		}
	case err != nil:
		return err
	default:
		kekID, wrapped, derr := decodeVault(b)
		if derr != nil {
			return derr
		}
		if key, err = v.unwrap(ctx, kekID, wrapped, vaultKeyAAD()); err != nil {
			return err
		}
		if len(key) != keyLen {
			return errors.New("seal: VAULT holds a key of the wrong length")
		}
	}
	v.index = func(identifier []byte) [32]byte {
		mac := hmac.New(sha256.New, key)
		mac.Write(identifier)
		var out [32]byte
		mac.Sum(out[:0])
		return out
	}
	return nil
}

// writeVaultKey wraps key under kek and writes VAULT atomically.
func (v *FileVault) writeVaultKey(ctx context.Context, key []byte, kek KEK) error {
	wrapped, err := kek.Wrap(ctx, key, vaultKeyAAD())
	if err != nil {
		return fmt.Errorf("seal: wrapping the vault key: %w", err)
	}
	b, err := encodeVault(kek.ID(), wrapped)
	if err != nil {
		return err
	}
	return v.write(vaultName, b)
}

// Resolve returns the ref for identifier, creating one, with a new DEK, on
// first use (RF-11). A ref is 128 random bits: nothing about it can be
// recomputed from the identifier, which is stored nowhere. The index is
// HMAC-SHA256 under the vault key. Identifiers are compared as bytes; a
// caller normalizes them first.
func (v *FileVault) Resolve(ctx context.Context, identifier []byte) (tally.SubjectRef, error) {
	if len(identifier) == 0 {
		return tally.SubjectRef{}, errors.New("seal: an empty identifier")
	}
	if err := ctx.Err(); err != nil {
		return tally.SubjectRef{}, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return tally.SubjectRef{}, tally.ErrClosed
	}
	idx := v.index(identifier)
	idxName := filepath.Join(idxDir, hex.EncodeToString(idx[:]))

	b, err := v.read(idxName)
	switch {
	case err == nil:
		ref, derr := decodeIdx(b)
		if derr != nil {
			return tally.SubjectRef{}, derr
		}
		if _, rerr := v.read(refName(ref)); rerr == nil {
			return ref, nil
		} else if !errors.Is(rerr, fs.ErrNotExist) {
			return tally.SubjectRef{}, rerr
		}
		// The ref's DEK is gone: shredded, with the index left behind by a
		// crash. A new incarnation follows (#45).
	case !errors.Is(err, fs.ErrNotExist):
		return tally.SubjectRef{}, err
	}
	return v.create(ctx, idx, idxName)
}

// create makes a new ref and DEK for the index entry idxName: the ref's file
// first, then the index, so that a crash leaves at worst a DEK no ref was
// returned for, which nothing was sealed with (ADR-0020).
func (v *FileVault) create(ctx context.Context, idx [32]byte, idxName string) (tally.SubjectRef, error) {
	var ref tally.SubjectRef
	for {
		if _, err := io.ReadFull(v.rand, ref[:]); err != nil {
			return tally.SubjectRef{}, fmt.Errorf("seal: reading a ref: %w", err)
		}
		// 128 random bits do not collide; a ref's file is never replaced
		// all the same, since that would destroy another subject's DEK.
		if _, err := v.read(refName(ref)); errors.Is(err, fs.ErrNotExist) {
			break
		} else if err != nil {
			return tally.SubjectRef{}, err
		}
	}
	dek := make([]byte, keyLen)
	if _, err := io.ReadFull(v.rand, dek); err != nil {
		return tally.SubjectRef{}, fmt.Errorf("seal: reading a DEK: %w", err)
	}
	wrapped, err := v.current.Wrap(ctx, dek, dekAAD(ref))
	clear(dek)
	if err != nil {
		return tally.SubjectRef{}, fmt.Errorf("seal: wrapping a DEK: %w", err)
	}
	rb, err := encodeRef(idx, v.current.ID(), wrapped)
	if err != nil {
		return tally.SubjectRef{}, err
	}
	if err := v.write(refName(ref), rb); err != nil {
		return tally.SubjectRef{}, err
	}
	if err := v.write(idxName, encodeIdx(ref)); err != nil {
		return tally.SubjectRef{}, err
	}
	return ref, nil
}

// dek unwraps ref's DEK. The caller uses it and clears it. A ref with no file
// returns an error matching fs.ErrNotExist.
func (v *FileVault) dek(ctx context.Context, ref tally.SubjectRef) ([]byte, error) {
	b, err := v.read(refName(ref))
	if err != nil {
		return nil, err
	}
	_, kekID, wrapped, err := decodeRef(b)
	if err != nil {
		return nil, err
	}
	key, err := v.unwrap(ctx, kekID, wrapped, dekAAD(ref))
	if err != nil {
		return nil, err
	}
	if len(key) != keyLen {
		clear(key)
		return nil, errors.New("seal: a DEK of the wrong length")
	}
	return key, nil
}

// RotateKEK rewraps every key in the vault under next, which then wraps
// everything new (ADR-0020). Each ref's file and VAULT are unwrapped with the
// KEK that wrapped them and rewritten atomically under next; VAULT last. The
// DEKs do not change, so nothing sealed needs re-encrypting.
//
// An interrupted rotation leaves some files under the old KEK and some under
// next. Each file names its KEK, so calling RotateKEK(next) again, on a vault
// opened with both KEKs, finishes it.
//
// Rotation narrows what a stolen KEK exposes; it does not undo a copy of a
// wrapped DEK taken earlier from the disk (R-34).
func (v *FileVault) RotateKEK(ctx context.Context, next KEK) error {
	if err := checkKEKID(next.ID()); err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return tally.ErrClosed
	}
	v.keks[next.ID()] = next

	entries, err := v.fsys.ReadDir(filepath.Join(v.dir, refsDir))
	if err != nil {
		return fmt.Errorf("seal: %w", err)
	}
	for _, e := range entries {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		ref, ok := parseRefName(e.Name())
		if !ok {
			continue
		}
		if rerr := v.rewrapRef(ctx, ref, next); rerr != nil {
			return rerr
		}
	}

	b, err := v.read(vaultName)
	if err != nil {
		return err
	}
	kekID, wrapped, err := decodeVault(b)
	if err != nil {
		return err
	}
	if kekID != next.ID() {
		key, err := v.unwrap(ctx, kekID, wrapped, vaultKeyAAD())
		if err != nil {
			return err
		}
		err = v.writeVaultKey(ctx, key, next)
		clear(key)
		if err != nil {
			return err
		}
	}
	v.current = next
	return nil
}

// rewrapRef rewrites ref's file under next, unless it already is.
func (v *FileVault) rewrapRef(ctx context.Context, ref tally.SubjectRef, next KEK) error {
	b, err := v.read(refName(ref))
	if err != nil {
		return err
	}
	idx, kekID, wrapped, err := decodeRef(b)
	if err != nil || kekID == next.ID() {
		return err
	}
	dek, err := v.unwrap(ctx, kekID, wrapped, dekAAD(ref))
	if err != nil {
		return err
	}
	rewrapped, err := next.Wrap(ctx, dek, dekAAD(ref))
	clear(dek)
	if err != nil {
		return fmt.Errorf("seal: rewrapping a DEK: %w", err)
	}
	rb, err := encodeRef(idx, next.ID(), rewrapped)
	if err != nil {
		return err
	}
	return v.write(refName(ref), rb)
}

// unwrap unwraps a blob with the KEK named kekID.
func (v *FileVault) unwrap(ctx context.Context, kekID string, wrapped, aad []byte) ([]byte, error) {
	k, ok := v.keks[kekID]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownKEK, kekID)
	}
	key, err := k.Unwrap(ctx, wrapped, aad)
	if err != nil {
		return nil, fmt.Errorf("seal: unwrapping under %q: %w", kekID, err)
	}
	return key, nil
}

// Close releases the vault's lock. Every later call returns tally.ErrClosed;
// Close itself is idempotent.
func (v *FileVault) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return nil
	}
	v.closed = true
	return v.lock.Close()
}

// read reads a vault file, refusing one over maxFileSize before reading it
// (RS-05). A missing file is an error matching fs.ErrNotExist.
func (v *FileVault) read(name string) ([]byte, error) {
	f, err := v.fsys.OpenFile(filepath.Join(v.dir, name), os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only: a close error loses no data
	b, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	if len(b) > maxFileSize {
		return nil, fmt.Errorf("seal: %s is over %d bytes", name, maxFileSize)
	}
	return b, nil
}

// write writes a vault file atomically, at mode 0600 (RS-10).
func (v *FileVault) write(name string, b []byte) error {
	if err := fsx.WriteAtomic(v.fsys, filepath.Join(v.dir, name), b, filePerm); err != nil {
		return fmt.Errorf("seal: %w", err)
	}
	return nil
}

func refName(ref tally.SubjectRef) string {
	return filepath.Join(refsDir, hex.EncodeToString(ref[:]))
}

// parseRefName reads a refs/ file name back into its ref.
func parseRefName(name string) (tally.SubjectRef, bool) {
	var ref tally.SubjectRef
	b, err := hex.DecodeString(name)
	if err != nil || len(b) != len(ref) || hex.EncodeToString(b) != name {
		return ref, false
	}
	copy(ref[:], b)
	return ref, true
}

// AADs (SPEC §4.1): each wrapped key is bound to what it protects.

func vaultKeyAAD() []byte {
	var e wire.Encoder
	e.String(aadVaultKey, 64)
	b, _ := e.Result() //nolint:errcheck // a constant tag under its limit always encodes
	return b
}

func dekAAD(ref tally.SubjectRef) []byte {
	var e wire.Encoder
	e.String(aadDEK, 64)
	e.Fixed(ref[:])
	b, _ := e.Result() //nolint:errcheck // a constant tag under its limit and a fixed field always encode
	return b
}

// File encodings (SPEC §4.1), in SPEC §1's encoding.

func encodeVault(kekID string, wrapped []byte) ([]byte, error) {
	var e wire.Encoder
	e.Fixed([]byte(vaultMagic))
	e.Uint8(formatVersion)
	e.String(kekID, maxKEKID)
	e.Bytes(wrapped, maxWrapped)
	b, err := e.Result()
	if err != nil {
		return nil, fmt.Errorf("seal: encoding VAULT: %w", err)
	}
	return b, nil
}

func decodeVault(b []byte) (kekID string, wrapped []byte, err error) {
	d := wire.NewDecoder(b)
	if err := checkMagic(&d, vaultMagic); err != nil {
		return "", nil, err
	}
	kekID = d.String(maxKEKID)
	wrapped = bytes.Clone(d.Bytes(maxWrapped))
	if err := d.Finish(); err != nil {
		return "", nil, fmt.Errorf("seal: VAULT: %w", err)
	}
	return kekID, wrapped, nil
}

func encodeIdx(ref tally.SubjectRef) []byte {
	var e wire.Encoder
	e.Fixed([]byte(idxMagic))
	e.Uint8(formatVersion)
	e.Fixed(ref[:])
	b, _ := e.Result() //nolint:errcheck // fixed fields always encode
	return b
}

func decodeIdx(b []byte) (tally.SubjectRef, error) {
	var ref tally.SubjectRef
	d := wire.NewDecoder(b)
	if err := checkMagic(&d, idxMagic); err != nil {
		return ref, err
	}
	d.Fixed(ref[:])
	if err := d.Finish(); err != nil {
		return ref, fmt.Errorf("seal: an index file: %w", err)
	}
	return ref, nil
}

func encodeRef(idx [32]byte, kekID string, wrapped []byte) ([]byte, error) {
	var e wire.Encoder
	e.Fixed([]byte(refMagic))
	e.Uint8(formatVersion)
	e.Fixed(idx[:])
	e.String(kekID, maxKEKID)
	e.Bytes(wrapped, maxWrapped)
	b, err := e.Result()
	if err != nil {
		return nil, fmt.Errorf("seal: encoding a ref file: %w", err)
	}
	return b, nil
}

func decodeRef(b []byte) (idx [32]byte, kekID string, wrapped []byte, err error) {
	d := wire.NewDecoder(b)
	if err := checkMagic(&d, refMagic); err != nil {
		return idx, "", nil, err
	}
	d.Fixed(idx[:])
	kekID = d.String(maxKEKID)
	wrapped = bytes.Clone(d.Bytes(maxWrapped))
	if err := d.Finish(); err != nil {
		return idx, "", nil, fmt.Errorf("seal: a ref file: %w", err)
	}
	return idx, kekID, wrapped, nil
}

func checkMagic(d *wire.Decoder, magic string) error {
	var m [8]byte
	d.Fixed(m[:])
	if string(m[:]) != magic || d.Uint8() != formatVersion {
		return fmt.Errorf("seal: not a %s file of version %d", magic, formatVersion)
	}
	return nil
}
