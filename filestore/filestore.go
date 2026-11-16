// Package filestore is a tally.Store on the local filesystem: a directory of
// segment files and a checkpoints file, in the format of SPEC §3.
//
// One writer per directory, enforced by an exclusive flock: a second Open
// fails with tally.ErrLocked (RS-09). AppendBatch returns only once its
// records are fsynced, and a new file's directory is fsynced before the file
// is relied on (RF-01, ADR-0009). Any write or fsync error is final for the
// Store, which refuses every later write.
//
// Opening recovers a torn tail by quarantining it, never by deleting it, and
// never below the last stored checkpoint (RF-20). A torn write and a flipped
// bit in the last acknowledged record can look the same (T-22): quarantine
// keeps the evidence, and cannot tell which it was.
//
// A segment is rotated only inside PutCheckpoint, after the checkpoint is
// durable, so every segment boundary carries a checkpoint of that size
// (ADR-0019). The segment size is therefore a target, not a bound.
//
// Linux and macOS only (RNF-09). NFS and SMB are unsupported: flock and fsync
// are unreliable there.
package filestore

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/internal/fsx"
)

const (
	// DefaultSegmentSize is the size at which a segment is rotated, at the
	// next checkpoint (ADR-0019).
	DefaultSegmentSize = 64 << 20

	segmentExt       = ".tlog"
	segmentMagic     = "TALLYLOG"
	segmentHeaderLen = 8 + 1 + 16 + 8 + 32 // SPEC §3.1

	checkpointsName      = "checkpoints.tlc"
	checkpointsMagic     = "TALLYCPT"
	checkpointsHeaderLen = 8 + 1 // SPEC §3.4

	lockName      = "LOCK"
	formatVersion = 1
	frameOverhead = 4 + 4 // SPEC §3.2

	dirPerm  fs.FileMode = 0o700
	filePerm fs.FileMode = 0o600
)

// ErrLoosePermissions is returned by Open for a directory that group or other
// users can access (RS-15). WithLoosePermissions accepts it.
var ErrLoosePermissions = errors.New("filestore: directory permissions are looser than 0700")

type config struct {
	segmentSize int64
	loose       bool
	fsys        fsx.FS
}

// Option configures Open.
type Option func(*config)

// WithSegmentSize sets the size in bytes at which a segment is rotated, at the
// next checkpoint after it is reached (ADR-0019). It must be positive. The
// default is DefaultSegmentSize.
func WithSegmentSize(n int64) Option {
	return func(c *config) { c.segmentSize = n }
}

// WithLoosePermissions lets Open accept a directory that group or other users
// can access. Anyone who can write to the directory can rewrite the log; the
// hash chain detects that only up to the last checkpoint anchored off the
// host (RS-15, RS-17).
func WithLoosePermissions() Option {
	return func(c *config) { c.loose = true }
}

// Store is a tally.Store over one directory. tally.Log calls its write
// methods from one goroutine; Records and Checkpoints are safe to call
// concurrently with them, and read a snapshot of what was durable when the
// iteration started.
type Store struct {
	fsys        fsx.FS
	dir         string
	segmentSize int64

	mu     sync.Mutex
	lock   io.Closer
	closed bool
	err    error // the first write or fsync error; final (ADR-0009)

	recovered int64 // bytes quarantined by Open (RF-20)

	logID   tally.LogID
	segs    []uint64 // first_seq of each segment, ascending
	seg     fsx.File // the last segment, open for appending; nil before genesis
	segSize int64    // durable length of the last segment
	next    uint64   // seq of the next record
	last    [32]byte // leaf hash of record next-1
	cps     fsx.File // the checkpoints file, open for appending; nil before the first
	cpsSize int64    // durable length of the checkpoints file
}

var (
	_ tally.Store            = (*Store)(nil)
	_ tally.RecoveryReporter = (*Store)(nil)
)

// Open opens the log in dir, creating dir with mode 0700 if it does not exist.
// It takes the directory's lock, fails with ErrLoosePermissions if dir is
// accessible to group or others, and with tally.ErrLocked if another Store
// holds it, in this process or another.
//
// Open reads every segment header and every frame of the last segment and of
// the checkpoints file, and recovers their tails (SPEC §3.3, RF-20): bytes
// after the last complete, valid frame, or a last file shorter than its
// header, are written durably to a quarantine file and only then removed.
// Recovered reports how many. Open refuses, changing nothing, a bad frame
// with bytes after it, and any recovery that would leave fewer records than
// the last stored checkpoint covers. tally.Open then reads the whole log
// through Records.
func Open(ctx context.Context, dir string, opts ...Option) (*Store, error) {
	cfg := config{segmentSize: DefaultSegmentSize, fsys: fsx.OS{}}
	for _, o := range opts {
		o(&cfg)
	}
	if cfg.segmentSize < 1 {
		return nil, fmt.Errorf("filestore: segment size %d is not positive", cfg.segmentSize)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := prepareDir(cfg, dir); err != nil {
		return nil, err
	}
	lock, err := cfg.fsys.Lock(filepath.Join(dir, lockName))
	if err != nil {
		if errors.Is(err, fsx.ErrLocked) {
			return nil, fmt.Errorf("%w: %s", tally.ErrLocked, dir)
		}
		return nil, fmt.Errorf("filestore: locking %s: %w", dir, err)
	}
	s := &Store{fsys: cfg.fsys, dir: dir, segmentSize: cfg.segmentSize, lock: lock}
	if err := s.load(); err != nil {
		return nil, errors.Join(err, s.closeFiles())
	}
	return s, nil
}

// prepareDir creates dir, or checks that it is a directory no one else can
// access (RS-15).
func prepareDir(cfg config, dir string) error {
	fi, err := cfg.fsys.Stat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err = cfg.fsys.Mkdir(dir, dirPerm); err != nil {
			return fmt.Errorf("filestore: %w", err)
		}
		// The new directory's own entry must survive a crash too.
		if err = fsx.SyncDir(cfg.fsys, filepath.Dir(dir)); err != nil {
			return fmt.Errorf("filestore: %w", err)
		}
		return nil
	case err != nil:
		return fmt.Errorf("filestore: %w", err)
	case !fi.IsDir():
		return fmt.Errorf("filestore: %s is not a directory", dir)
	case fi.Mode().Perm()&0o077 != 0 && !cfg.loose:
		return fmt.Errorf("%w: %s has mode %04o", ErrLoosePermissions, dir, fi.Mode().Perm())
	}
	return nil
}

// AppendBatch appends recs to the last segment and fsyncs it, creating the
// first segment, with O_EXCL, for the genesis. It returns only once every
// record is durable (RF-01). recs must continue the stored log.
//
// A write or fsync error is final: this and every later write returns it,
// and part of the batch may be stored (ADR-0009).
func (s *Store) AppendBatch(ctx context.Context, recs []tally.Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return err
	}
	if len(recs) == 0 {
		return nil
	}
	size := 0
	for i, r := range recs {
		if want := s.next + uint64(i); r.Seq != want { // #nosec G115 -- i is a slice index
			return fmt.Errorf("filestore: record %d of the batch has seq %d, want %d", i, r.Seq, want)
		}
		if len(r.Body) > tally.MaxRecordLen {
			return fmt.Errorf("filestore: record %d is %d bytes, over the %d-byte ceiling", r.Seq, len(r.Body), tally.MaxRecordLen)
		}
		size += frameOverhead + len(r.Body)
	}
	if s.seg == nil {
		id, err := tally.RecordLogID(recs[0].Body)
		if err != nil {
			return fmt.Errorf("filestore: the first record: %w", err)
		}
		s.logID = id
		if err := s.startSegment(0, [32]byte{}); err != nil {
			return s.fail(err)
		}
	}

	buf := make([]byte, 0, size)
	for _, r := range recs {
		buf = appendFrame(buf, r.Body)
	}
	if err := writeAll(s.seg, buf); err != nil {
		return s.fail(err)
	}
	if err := s.seg.Sync(); err != nil {
		return s.fail(err)
	}
	s.segSize += int64(len(buf))
	s.next += uint64(len(recs))
	s.last = tally.LeafHash(recs[len(recs)-1].Body)
	return nil
}

// PutCheckpoint appends cp to the checkpoints file and fsyncs it, creating
// the file, with O_EXCL, for the first one. Once cp is durable, and if the
// last segment has reached the segment size, it starts a new segment at the
// next seq: cp covers every stored record, so the new segment's first_seq is
// cp's size and its prev_hash is cp's head (ADR-0019).
//
// Errors are final, as AppendBatch's are.
func (s *Store) PutCheckpoint(ctx context.Context, cp tally.SignedCheckpoint) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return err
	}
	if len(cp) == 0 || len(cp) > tally.MaxCheckpointLen {
		return fmt.Errorf("filestore: a checkpoint of %d bytes, outside 1 to %d", len(cp), tally.MaxCheckpointLen)
	}
	if s.seg == nil {
		return errors.New("filestore: a checkpoint before the genesis covers nothing")
	}

	if s.cps == nil {
		buf := append([]byte(checkpointsMagic), formatVersion)
		buf = appendFrame(buf, cp)
		f, err := s.createFile(checkpointsName, buf)
		if err != nil {
			return s.fail(err)
		}
		s.cps, s.cpsSize = f, int64(len(buf))
	} else {
		buf := appendFrame(nil, cp)
		if err := writeAll(s.cps, buf); err != nil {
			return s.fail(err)
		}
		if err := s.cps.Sync(); err != nil {
			return s.fail(err)
		}
		s.cpsSize += int64(len(buf))
	}

	// A segment holding no frame is never rotated: the next one would have
	// the same first_seq, and so the same name.
	if s.segSize >= s.segmentSize && s.segSize > segmentHeaderLen {
		if err := s.startSegment(s.next, s.last); err != nil {
			return s.fail(err)
		}
	}
	return nil
}

// Close releases the lock and closes the files. Every later call returns
// tally.ErrClosed; Close itself is idempotent.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.closeFiles()
}

func (s *Store) closeFiles() error {
	var errs []error
	if s.seg != nil {
		errs = append(errs, s.seg.Close())
	}
	if s.cps != nil {
		errs = append(errs, s.cps.Close())
	}
	errs = append(errs, s.lock.Close())
	return errors.Join(errs...)
}

// usable reports why the Store cannot write, if it cannot.
func (s *Store) usable() error {
	if s.closed {
		return tally.ErrClosed
	}
	return s.err
}

// fail records err as final (ADR-0009) and returns it.
func (s *Store) fail(err error) error {
	s.err = fmt.Errorf("filestore: %w", err)
	return s.err
}

// startSegment creates the segment starting at first, writes and fsyncs its
// header, fsyncs the directory, and makes it the segment appended to.
func (s *Store) startSegment(first uint64, prev [32]byte) error {
	hdr := make([]byte, 0, segmentHeaderLen)
	hdr = append(hdr, segmentMagic...)
	hdr = append(hdr, formatVersion)
	hdr = append(hdr, s.logID[:]...)
	hdr = binary.BigEndian.AppendUint64(hdr, first)
	hdr = append(hdr, prev[:]...)

	f, err := s.createFile(segmentName(first), hdr)
	if err != nil {
		return err
	}
	if s.seg != nil {
		if err := s.seg.Close(); err != nil {
			return errors.Join(err, f.Close())
		}
	}
	s.seg, s.segSize = f, int64(len(hdr))
	s.segs = append(s.segs, first)
	return nil
}

// createFile creates name in the directory with O_EXCL and mode 0600, writes
// data, fsyncs the file and then the directory, and returns the file open for
// appending. O_EXCL makes an existing file an error rather than something
// appended to or truncated (RS-10).
func (s *Store) createFile(name string, data []byte) (fsx.File, error) {
	f, err := s.fsys.OpenFile(filepath.Join(s.dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_APPEND, filePerm)
	if err != nil {
		return nil, err
	}
	if err := writeAll(f, data); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	if err := f.Sync(); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	if err := fsx.SyncDir(s.fsys, s.dir); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return f, nil
}

func segmentName(first uint64) string {
	return fmt.Sprintf("%016x%s", first, segmentExt)
}

// writeAll writes b to f. A short write without an error is still an error.
func writeAll(f fsx.File, b []byte) error {
	n, err := f.Write(b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	return err
}

// appendFrame appends body to dst as one SPEC §3.2 frame. The caller has
// checked len(body) against its ceiling, far below 2^32.
func appendFrame(dst, body []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(body))) // #nosec G115 -- checked against a ceiling under 2^32
	dst = append(dst, body...)
	return binary.BigEndian.AppendUint32(dst, crc32.Checksum(body, castagnoli()))
}

func castagnoli() *crc32.Table {
	// MakeTable caches the Castagnoli table itself, so this holds no state here.
	return crc32.MakeTable(crc32.Castagnoli)
}
