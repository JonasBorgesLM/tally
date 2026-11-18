package filestore

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"iter"
	"os"
	"path/filepath"
	"slices"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/internal/fsx"
)

// Format errors: stored bytes that break SPEC §3. A reader reports them as a
// *tally.MalformedError, a violation, and every other error as an IO failure.
var (
	errShortFrame    = errors.New("a frame is cut off")
	errEmptyFrame    = errors.New("a frame of length 0, which no record is")
	errFrameTooLong  = errors.New("a frame's length is over its ceiling")
	errFrameCRC      = errors.New("a frame fails its CRC")
	errBadHeader     = errors.New("a malformed header")
	errDiscontinuous = errors.New("a segment does not continue the previous one")
	errUpperName     = errors.New("a segment name with uppercase hex digits")
)

// isFormat reports whether err is one of the format errors above.
func isFormat(err error) bool {
	for _, f := range []error{errShortFrame, errEmptyFrame, errFrameTooLong, errFrameCRC, errBadHeader, errDiscontinuous, errUpperName} {
		if errors.Is(err, f) {
			return true
		}
	}
	return false
}

// header is a segment header (SPEC §3.1).
type header struct {
	logID tally.LogID
	first uint64
	prev  [32]byte
}

// readHeader reads and checks the header of the segment starting at first:
// its length, magic and version, and that it names the same first_seq as the
// file (SPEC §3, §3.1).
func (s *Store) readHeader(first uint64) (header, error) {
	name := segmentName(first)
	f, err := s.fsys.OpenFile(filepath.Join(s.dir, name), os.O_RDONLY, 0)
	if err != nil {
		return header{}, fmt.Errorf("filestore: %w", err)
	}
	h, err := parseHeader(name, f, first)
	return h, errors.Join(err, f.Close())
}

func parseHeader(name string, r io.Reader, first uint64) (header, error) {
	b := make([]byte, segmentHeaderLen)
	if _, err := io.ReadFull(r, b); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return header{}, fmt.Errorf("filestore: %s: %w: cut off", name, errBadHeader)
		}
		return header{}, fmt.Errorf("filestore: %s: %w", name, err)
	}
	if err := checkMagic(name, b); err != nil {
		return header{}, err
	}
	var h header
	copy(h.logID[:], b[9:25])
	h.first = binary.BigEndian.Uint64(b[25:33])
	copy(h.prev[:], b[33:65])
	if h.first != first {
		return header{}, fmt.Errorf("filestore: %s: %w: its first_seq is %d", name, errBadHeader, h.first)
	}
	return h, nil
}

func checkMagic(name string, hdr []byte) error {
	magic := segmentMagic
	if name == checkpointsName {
		magic = checkpointsMagic
	}
	if !bytes.Equal(hdr[:8], []byte(magic)) || hdr[8] != formatVersion {
		return fmt.Errorf("filestore: %s: %w: wrong magic or version", name, errBadHeader)
	}
	return nil
}

// parseSegmentName reports whether name is a segment file name (SPEC §3) and,
// if so, its first_seq. A name that would be one but for uppercase hex digits
// is an error, so that renaming cannot hide a segment.
func parseSegmentName(name string) (first uint64, ok bool, err error) {
	first, ok, upper := segmentNameValue(name)
	if upper {
		return 0, false, fmt.Errorf("filestore: %s: %w", name, errUpperName)
	}
	return first, ok, nil
}

// segmentNameValue reads name as a segment name in either case, and reports
// whether it used an uppercase digit.
func segmentNameValue(name string) (first uint64, ok, upper bool) {
	if len(name) != 16+len(segmentExt) || name[16:] != segmentExt {
		return 0, false, false
	}
	for _, c := range name[:16] {
		switch {
		case c >= '0' && c <= '9':
			first = first<<4 | uint64(c-'0')
		case c >= 'a' && c <= 'f':
			first = first<<4 | uint64(c-'a'+10)
		case c >= 'A' && c <= 'F':
			first = first<<4 | uint64(c-'A'+10)
			upper = true
		default:
			return 0, false, false
		}
	}
	return first, true, upper
}

// readFrame reads one SPEC §3.2 frame and returns its body. It checks the
// length against limit before allocating (RS-05). io.EOF means the input
// ended exactly between frames.
func readFrame(r io.Reader, limit uint32) ([]byte, error) {
	var lenBuf [4]byte
	switch n, err := io.ReadFull(r, lenBuf[:]); {
	case n == 0 && errors.Is(err, io.EOF):
		return nil, io.EOF
	case errors.Is(err, io.ErrUnexpectedEOF):
		return nil, errShortFrame
	case err != nil:
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n == 0 {
		// No record or checkpoint is empty, and a run of zeros, which a crash
		// can leave past the last write, would otherwise read as frames: a
		// zero length with the CRC of nothing, which is also zero (#127).
		return nil, errEmptyFrame
	}
	if n > limit {
		return nil, fmt.Errorf("%w: %d bytes", errFrameTooLong, n)
	}
	buf := make([]byte, int(n)+4)
	if _, err := io.ReadFull(r, buf); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, errShortFrame
		}
		return nil, err
	}
	body := buf[:n:n]
	if binary.BigEndian.Uint32(buf[n:]) != crc32.Checksum(body, castagnoli()) {
		return nil, errFrameCRC
	}
	return body, nil
}

// segmentRef is one segment to read: its first_seq, as its name gives it,
// and whether that name used uppercase digits.
type segmentRef struct {
	first uint64
	upper bool
}

// readSegments yields the records of segs from fromSeq on, reading from the
// last segment starting at or before fromSeq. lastLimit bounds how much of the
// last segment is read, or -1 for all of it. logID, if known, is what every
// header must name; otherwise the first header read sets it.
//
// It checks each header and name, and from the second segment read on that
// each continues the previous one. A format error ends the sequence with a
// *tally.MalformedError at the first leaf not yielded (#93); an IO error ends
// it with that error.
func readSegments(ctx context.Context, fsys fsx.FS, dir string, segs []segmentRef, fromSeq uint64,
	lastLimit int64, logID *tally.LogID, yield func(tally.Record, error) bool,
) {
	start := 0
	for i, sg := range segs {
		if sg.first <= fromSeq {
			start = i
		}
	}
	var (
		seq  uint64
		prev [32]byte
	)
	for i := start; i < len(segs); i++ {
		limit := int64(-1)
		if i == len(segs)-1 {
			limit = lastLimit
		}
		r := segmentRead{fsys: fsys, dir: dir, ref: segs[i], limit: limit, logID: logID, from: fromSeq}
		if i > start {
			r.check, r.seq, r.prev = true, seq, prev
		}
		var ok bool
		seq, prev, ok = r.run(ctx, yield)
		if !ok {
			return
		}
	}
}

// Records yields the stored records from fromSeq on (see readSegments).
func (s *Store) Records(ctx context.Context, fromSeq uint64) iter.Seq2[tally.Record, error] {
	return func(yield func(tally.Record, error) bool) {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			yield(tally.Record{}, tally.ErrClosed)
			return
		}
		segs := make([]segmentRef, len(s.segs))
		for i, first := range s.segs {
			segs[i] = segmentRef{first: first}
		}
		lastSize, logID := s.segSize, s.logID
		s.mu.Unlock()
		readSegments(ctx, s.fsys, s.dir, segs, fromSeq, lastSize, &logID, yield)
	}
}

// segmentRead is one segment read by readSegments.
type segmentRead struct {
	fsys  fsx.FS
	dir   string
	ref   segmentRef
	limit int64 // bytes to read, or -1 for the whole file
	logID *tally.LogID
	from  uint64

	check bool     // whether the header must continue seq and prev
	seq   uint64   // the previous segment's next seq
	prev  [32]byte // the previous segment's last leaf hash
}

// run yields the segment's records from r.from on, and returns the next seq
// and the last leaf hash. ok is false when the sequence ended, by an error or
// because the consumer stopped.
func (r segmentRead) run(ctx context.Context, yield func(tally.Record, error) bool) (next uint64, last [32]byte, ok bool) {
	// Before its header is read, a segment stands at the leaf its
	// predecessor ended on, or at the first leaf its name gives.
	at := r.ref.first
	if r.check {
		at = r.seq
	}
	fail := func(err error) (uint64, [32]byte, bool) {
		if isFormat(err) {
			err = &tally.MalformedError{Seq: at, Err: err}
		}
		yield(tally.Record{}, err)
		return 0, last, false
	}
	if r.ref.upper {
		return fail(fmt.Errorf("filestore: %016X%s: %w", r.ref.first, segmentExt, errUpperName))
	}
	name := segmentName(r.ref.first)
	f, err := r.fsys.OpenFile(filepath.Join(r.dir, name), os.O_RDONLY, 0)
	if err != nil {
		return fail(fmt.Errorf("filestore: %w", err))
	}
	defer f.Close() //nolint:errcheck // read-only: a close error loses no data

	var src io.Reader = f
	if r.limit >= 0 {
		src = io.LimitReader(f, r.limit)
	}
	br := bufio.NewReader(src)
	h, err := parseHeader(name, br, r.ref.first)
	if err != nil {
		return fail(err)
	}
	if *r.logID == (tally.LogID{}) {
		*r.logID = h.logID
	} else if h.logID != *r.logID {
		return fail(fmt.Errorf("filestore: %s: %w: another log_id", name, errBadHeader))
	}
	if r.check && (h.first != r.seq || h.prev != r.prev) {
		return fail(fmt.Errorf("filestore: %s: %w", name, errDiscontinuous))
	}

	seq, last := h.first, h.prev
	off := int64(segmentHeaderLen)
	for {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		at = seq
		body, err := readFrame(br, tally.MaxRecordLen)
		if errors.Is(err, io.EOF) {
			return seq, last, true
		}
		if err != nil {
			return fail(fmt.Errorf("filestore: %s at offset %d: %w", name, off, err))
		}
		last = tally.LeafHash(body)
		off += int64(frameOverhead + len(body))
		if seq >= r.from && !yield(tally.Record{Seq: seq, Body: body}, nil) {
			return 0, last, false
		}
		seq++
	}
}

// readCheckpoints yields the checkpoints in dir's checkpoints file, reading
// limit bytes of it, or all of it for -1. A format error ends the sequence
// with a *tally.MalformedError; an IO error, with that error.
func readCheckpoints(ctx context.Context, fsys fsx.FS, dir string, limit int64, yield func(tally.SignedCheckpoint, error) bool) {
	fail := func(err error) {
		if isFormat(err) {
			err = &tally.MalformedError{Err: err}
		}
		yield(nil, err)
	}
	f, err := fsys.OpenFile(filepath.Join(dir, checkpointsName), os.O_RDONLY, 0)
	if err != nil {
		fail(fmt.Errorf("filestore: %w", err))
		return
	}
	defer f.Close() //nolint:errcheck // read-only: a close error loses no data

	var src io.Reader = f
	if limit >= 0 {
		src = io.LimitReader(f, limit)
	}
	br := bufio.NewReader(src)
	hdr := make([]byte, checkpointsHeaderLen)
	if _, err := io.ReadFull(br, hdr); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			err = errBadHeader
		}
		fail(fmt.Errorf("filestore: %s: %w", checkpointsName, err))
		return
	}
	if err := checkMagic(checkpointsName, hdr); err != nil {
		fail(err)
		return
	}
	for {
		if err := ctx.Err(); err != nil {
			yield(nil, err)
			return
		}
		body, err := readFrame(br, tally.MaxCheckpointLen)
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			fail(fmt.Errorf("filestore: %s: %w", checkpointsName, err))
			return
		}
		if !yield(tally.SignedCheckpoint(body), nil) {
			return
		}
	}
}

// Checkpoints yields the stored checkpoints, oldest first, as a snapshot of
// the checkpoints file (see readCheckpoints).
func (s *Store) Checkpoints(ctx context.Context) iter.Seq2[tally.SignedCheckpoint, error] {
	return func(yield func(tally.SignedCheckpoint, error) bool) {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			yield(nil, tally.ErrClosed)
			return
		}
		size, exists := s.cpsSize, s.cps != nil
		s.mu.Unlock()
		if exists {
			readCheckpoints(ctx, s.fsys, s.dir, size, yield)
		}
	}
}

// Reader is a read-only tally.Source over a log directory, for an auditor or
// a verifier: it never takes the lock, never recovers, never creates or
// writes anything, so verifying evidence does not alter it (#93). Each read
// lists the directory afresh and reads every file to its end, so a bad tail
// that a writer's Open would quarantine is reported here as a violation
// (SPEC §3.3, "Verifier").
//
// It does not coordinate with a writer. Reading a log a Store is appending to
// may see a frame in the middle of being written, which reads as a short
// tail; verify a copy, or a closed log.
type Reader struct {
	fsys fsx.FS
	dir  string
}

var _ tally.Source = (*Reader)(nil)

// OpenReader returns a Reader over dir, which must exist and be a directory.
func OpenReader(dir string) (*Reader, error) {
	return openReader(fsx.OS{}, dir)
}

func openReader(fsys fsx.FS, dir string) (*Reader, error) {
	fi, err := fsys.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("filestore: %w", err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("filestore: %s is not a directory", dir)
	}
	return &Reader{fsys: fsys, dir: dir}, nil
}

// segments lists dir's segments, ordered by first_seq, uppercase names
// included so that reading reports them in place.
func (r *Reader) segments() ([]segmentRef, bool, error) {
	entries, err := r.fsys.ReadDir(r.dir)
	if err != nil {
		return nil, false, fmt.Errorf("filestore: %w", err)
	}
	var segs []segmentRef
	hasCps := false
	for _, e := range entries {
		if first, ok, upper := segmentNameValue(e.Name()); ok {
			segs = append(segs, segmentRef{first: first, upper: upper})
		}
		hasCps = hasCps || e.Name() == checkpointsName
	}
	slices.SortFunc(segs, func(a, b segmentRef) int {
		switch {
		case a.first < b.first:
			return -1
		case a.first > b.first:
			return 1
		}
		return 0
	})
	return segs, hasCps, nil
}

// Records yields the records from fromSeq on, reading every segment to its
// end. With no segment it yields nothing, which Verify reports as an error.
func (r *Reader) Records(ctx context.Context, fromSeq uint64) iter.Seq2[tally.Record, error] {
	return func(yield func(tally.Record, error) bool) {
		segs, _, err := r.segments()
		if err != nil {
			yield(tally.Record{}, err)
			return
		}
		var logID tally.LogID
		readSegments(ctx, r.fsys, r.dir, segs, fromSeq, -1, &logID, yield)
	}
}

// Checkpoints yields the checkpoints file's checkpoints, reading it to its
// end. With no checkpoints file it yields nothing.
func (r *Reader) Checkpoints(ctx context.Context) iter.Seq2[tally.SignedCheckpoint, error] {
	return func(yield func(tally.SignedCheckpoint, error) bool) {
		_, hasCps, err := r.segments()
		if err != nil {
			yield(nil, err)
			return
		}
		if hasCps {
			readCheckpoints(ctx, r.fsys, r.dir, -1, yield)
		}
	}
}
