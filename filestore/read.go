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

var (
	errShortFrame   = errors.New("a frame is cut off")
	errFrameTooLong = errors.New("a frame's length is over its ceiling")
	errFrameCRC     = errors.New("a frame fails its CRC")
)

// header is a segment header (SPEC §3.1).
type header struct {
	logID tally.LogID
	first uint64
	prev  [32]byte
}

// load reads the directory into s: every segment header, every frame of the
// last segment and of the checkpoints file, and opens both for appending.
// Bytes after the last complete, valid frame are refused here; quarantining
// them is recovery's job (SPEC §3.3).
func (s *Store) load() error {
	entries, err := s.fsys.ReadDir(s.dir)
	if err != nil {
		return fmt.Errorf("filestore: %w", err)
	}
	hasCps := false
	for _, e := range entries {
		first, ok, perr := parseSegmentName(e.Name())
		if perr != nil {
			return perr
		}
		if ok {
			// ReadDir sorts by name, and 16 lowercase hex digits sort as
			// numbers do.
			s.segs = append(s.segs, first)
		}
		hasCps = hasCps || e.Name() == checkpointsName
	}
	if len(s.segs) == 0 {
		if hasCps {
			return errors.New("filestore: a checkpoints file with no segment")
		}
		return nil
	}

	for i, first := range s.segs {
		h, herr := s.readHeader(first)
		if herr != nil {
			return herr
		}
		if i == 0 {
			s.logID = h.logID
		} else if h.logID != s.logID {
			return fmt.Errorf("filestore: segment %s has another log_id", segmentName(first))
		}
	}

	last := s.segs[len(s.segs)-1]
	n, prev, size, err := s.scan(segmentName(last), segmentHeaderLen, tally.MaxRecordLen)
	if err != nil {
		return err
	}
	s.next = last + n
	s.last = prev
	if n == 0 {
		h, herr := s.readHeader(last)
		if herr != nil {
			return herr
		}
		s.last = h.prev
	}
	if s.seg, err = s.fsys.OpenFile(filepath.Join(s.dir, segmentName(last)), os.O_WRONLY|os.O_APPEND, 0); err != nil {
		return fmt.Errorf("filestore: %w", err)
	}
	s.segSize = size

	if hasCps {
		if _, _, size, err = s.scan(checkpointsName, checkpointsHeaderLen, tally.MaxCheckpointLen); err != nil {
			return err
		}
		if s.cps, err = s.fsys.OpenFile(filepath.Join(s.dir, checkpointsName), os.O_WRONLY|os.O_APPEND, 0); err != nil {
			return fmt.Errorf("filestore: %w", err)
		}
		s.cpsSize = size
	}
	return nil
}

// scan reads every frame of the file name after its header of hdrLen bytes,
// checking the header's magic and version, and returns the number of frames,
// the leaf hash of the last one, and the file's length. A file that does not
// end on a complete, valid frame is an error.
func (s *Store) scan(name string, hdrLen int, limit uint32) (n uint64, last [32]byte, size int64, err error) {
	f, err := s.fsys.OpenFile(filepath.Join(s.dir, name), os.O_RDONLY, 0)
	if err != nil {
		return 0, last, 0, fmt.Errorf("filestore: %w", err)
	}
	defer func() { err = errors.Join(err, f.Close()) }()

	r := bufio.NewReader(f)
	hdr := make([]byte, hdrLen)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return 0, last, 0, fmt.Errorf("filestore: %s: the header is cut off: %w", name, err)
	}
	if err := checkMagic(name, hdr); err != nil {
		return 0, last, 0, err
	}
	size = int64(hdrLen)
	for {
		body, err := readFrame(r, limit)
		if errors.Is(err, io.EOF) {
			return n, last, size, nil
		}
		if err != nil {
			return 0, last, 0, fmt.Errorf("filestore: %s at offset %d: %w", name, size, err)
		}
		n++
		last = tally.LeafHash(body)
		size += int64(frameOverhead + len(body))
	}
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
		return header{}, fmt.Errorf("filestore: %s: the header is cut off: %w", name, err)
	}
	if err := checkMagic(name, b); err != nil {
		return header{}, err
	}
	var h header
	copy(h.logID[:], b[9:25])
	h.first = binary.BigEndian.Uint64(b[25:33])
	copy(h.prev[:], b[33:65])
	if h.first != first {
		return header{}, fmt.Errorf("filestore: %s: the header's first_seq is %d", name, h.first)
	}
	return h, nil
}

func checkMagic(name string, hdr []byte) error {
	magic := segmentMagic
	if name == checkpointsName {
		magic = checkpointsMagic
	}
	if !bytes.Equal(hdr[:8], []byte(magic)) || hdr[8] != formatVersion {
		return fmt.Errorf("filestore: %s: wrong magic or version", name)
	}
	return nil
}

// parseSegmentName reports whether name is a segment file name (SPEC §3) and,
// if so, its first_seq. A name that would be one but for uppercase hex digits
// is an error, so that renaming cannot hide a segment.
func parseSegmentName(name string) (first uint64, ok bool, err error) {
	if len(name) != 16+len(segmentExt) || name[16:] != segmentExt {
		return 0, false, nil
	}
	upper := false
	for _, c := range name[:16] {
		switch {
		case c >= '0' && c <= '9':
			first = first<<4 | uint64(c-'0')
		case c >= 'a' && c <= 'f':
			first = first<<4 | uint64(c-'a'+10)
		case c >= 'A' && c <= 'F':
			upper = true
		default:
			return 0, false, nil
		}
	}
	if upper {
		return 0, false, fmt.Errorf("filestore: %s is a segment name with uppercase hex digits", name)
	}
	return first, true, nil
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

// Records yields the stored records from fromSeq on, reading the segments
// from the last one starting at or before fromSeq. It checks each segment's
// header and name, and from the second segment read on that each header
// continues the previous segment: the same log_id, first_seq one past its
// last record, and prev_hash that record's leaf hash. Any failure, of IO or
// of the format, ends the sequence with an error (#93 is to report the
// latter as a violation).
func (s *Store) Records(ctx context.Context, fromSeq uint64) iter.Seq2[tally.Record, error] {
	return func(yield func(tally.Record, error) bool) {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			yield(tally.Record{}, tally.ErrClosed)
			return
		}
		segs, lastSize, logID := slices.Clone(s.segs), s.segSize, s.logID
		s.mu.Unlock()

		start := 0
		for i, first := range segs {
			if first <= fromSeq {
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
				limit = lastSize
			}
			r := segmentRead{fsys: s.fsys, dir: s.dir, first: segs[i], limit: limit, logID: logID, from: fromSeq}
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
}

// segmentRead is one segment read by Records.
type segmentRead struct {
	fsys  fsx.FS
	dir   string
	first uint64
	limit int64 // bytes to read, or -1 for the whole file
	logID tally.LogID
	from  uint64

	check bool     // whether the header must continue seq and prev
	seq   uint64   // the previous segment's next seq
	prev  [32]byte // the previous segment's last leaf hash
}

// run yields the segment's records from r.from on, and returns the next seq
// and the last leaf hash. ok is false when the sequence ended, by an error or
// because the consumer stopped.
func (r segmentRead) run(ctx context.Context, yield func(tally.Record, error) bool) (next uint64, last [32]byte, ok bool) {
	name := segmentName(r.first)
	fail := func(err error) (uint64, [32]byte, bool) {
		yield(tally.Record{}, err)
		return 0, last, false
	}
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
	h, err := parseHeader(name, br, r.first)
	if err != nil {
		return fail(err)
	}
	if h.logID != r.logID {
		return fail(fmt.Errorf("filestore: %s has another log_id", name))
	}
	if r.check && (h.first != r.seq || h.prev != r.prev) {
		return fail(fmt.Errorf("filestore: %s does not continue the previous segment", name))
	}

	seq, last := h.first, h.prev
	off := int64(segmentHeaderLen)
	for {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
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

// Checkpoints yields the stored checkpoints, oldest first, as a snapshot of
// the checkpoints file. Any failure ends the sequence with an error.
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
		if !exists {
			return
		}

		f, err := s.fsys.OpenFile(filepath.Join(s.dir, checkpointsName), os.O_RDONLY, 0)
		if err != nil {
			yield(nil, fmt.Errorf("filestore: %w", err))
			return
		}
		defer f.Close() //nolint:errcheck // read-only: a close error loses no data

		br := bufio.NewReader(io.LimitReader(f, size))
		hdr := make([]byte, checkpointsHeaderLen)
		if _, err := io.ReadFull(br, hdr); err != nil {
			yield(nil, fmt.Errorf("filestore: %s: the header is cut off: %w", checkpointsName, err))
			return
		}
		if err := checkMagic(checkpointsName, hdr); err != nil {
			yield(nil, err)
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
				yield(nil, fmt.Errorf("filestore: %s: %w", checkpointsName, err))
				return
			}
			if !yield(tally.SignedCheckpoint(body), nil) {
				return
			}
		}
	}
}
