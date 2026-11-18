package filestore

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/internal/fsx"
)

// errBelowCheckpoint means opening would leave fewer records than the last
// stored checkpoint covers: recovery would remove a record it covers, or the
// log already lacks one (RF-20, SPEC §3.3). Either is evidence, so Open
// refuses rather than append after it and fork the log's own history.
var errBelowCheckpoint = errors.New("filestore: the log holds fewer records than its last checkpoint covers")

// tailState is how a file ends, on opening (SPEC §3.3). A bad middle is not a
// state: classify returns it as an error, since a crash does not produce it.
type tailState uint8

const (
	tailClean    tailState = iota // ends on a complete, valid frame
	tailShort                     // a frame cut off: quarantine and truncate
	tailBad                       // a complete last frame failing its CRC: quarantine and truncate
	tailNoHeader                  // shorter than its header: quarantine and remove
)

// tail is a file read up to its last complete, valid frame.
type tail struct {
	name   string
	state  tailState
	frames uint64
	last   []byte // the body of the last good frame; nil if none
	end    int64  // the offset just past the last good frame
	size   int64  // the file's length
}

// classify reads the file name, whose header is hdrLen bytes, and reports how
// it ends, changing nothing. A header of full length with the wrong magic or
// version, a frame over its ceiling, or a bad frame with bytes after it is
// an error: none of them is what a crash leaves (SPEC §3.3, "bad middle").
func (s *Store) classify(name string, hdrLen int, limit uint32) (t tail, err error) {
	t.name = name
	f, err := s.fsys.OpenFile(filepath.Join(s.dir, name), os.O_RDONLY, 0)
	if err != nil {
		return t, fmt.Errorf("filestore: %w", err)
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	fi, err := f.Stat()
	if err != nil {
		return t, fmt.Errorf("filestore: %w", err)
	}
	t.size = fi.Size()
	if t.size < int64(hdrLen) {
		t.state = tailNoHeader
		return t, nil
	}

	r := bufio.NewReader(f)
	hdr := make([]byte, hdrLen)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return t, fmt.Errorf("filestore: %s: %w", name, err)
	}
	if err := checkMagic(name, hdr); err != nil {
		return t, err
	}
	t.end = int64(hdrLen)
	for {
		body, err := readFrame(r, limit)
		switch {
		case err == nil:
			t.frames++
			t.last = body
			t.end += int64(frameOverhead + len(body))
			continue
		case errors.Is(err, io.EOF):
			t.state = tailClean
			return t, nil
		case errors.Is(err, errShortFrame), errors.Is(err, errEmptyFrame):
			// A crash leaves debris after the last frame it completed: a frame
			// cut off, or zeros. It never leaves a complete frame after that
			// debris, since every acknowledged frame was made durable before
			// the next batch was written. One there means the cut-off frame
			// is not a torn write but a changed length, and truncating would
			// drop every acknowledged frame after it (audit A-02, #127).
			at, ferr := frameAfter(f, t.end, t.size, limit)
			if ferr != nil {
				return t, fmt.Errorf("filestore: %s: %w", name, ferr)
			}
			if at >= 0 {
				return t, fmt.Errorf("filestore: %s at offset %d: %w, with a complete frame after it at offset %d", name, t.end, err, at)
			}
			t.state = tailShort
			return t, nil
		case errors.Is(err, errFrameCRC):
			// readFrame consumed the whole frame: it is the tail only if
			// nothing follows it.
			var lenBuf [4]byte
			if _, rerr := f.ReadAt(lenBuf[:], t.end); rerr != nil {
				return t, fmt.Errorf("filestore: %s: %w", name, rerr)
			}
			if t.end+frameOverhead+int64(binary.BigEndian.Uint32(lenBuf[:])) != t.size {
				return t, fmt.Errorf("filestore: %s at offset %d: %w, with bytes after it", name, t.end, errFrameCRC)
			}
			t.state = tailBad
			return t, nil
		default:
			return t, fmt.Errorf("filestore: %s at offset %d: %w", name, t.end, err)
		}
	}
}

// frameAfter returns the offset of the first complete, non-empty frame whose
// CRC matches that starts after offset from in f, a file of size bytes, or -1
// if there is none. It reads f once, in order, and reads a candidate's body
// only when its length is possible: over 0, at most limit (checked before
// allocating, RS-05), and within the file.
func frameAfter(f fsx.File, from, size int64, limit uint32) (int64, error) {
	if size-from < 2*frameOverhead+1 {
		return -1, nil // no room for the cut-off frame's length and a frame after it
	}
	r := bufio.NewReaderSize(io.NewSectionReader(f, from+1, size-from-1), 64<<10)
	var win [4]byte
	off := from + 1 // where win starts, once full
	for i := 0; ; i++ {
		b, err := r.ReadByte()
		if errors.Is(err, io.EOF) {
			return -1, nil
		}
		if err != nil {
			return -1, err
		}
		if i < 4 {
			win[i] = b
			if i < 3 {
				continue
			}
		} else {
			copy(win[:], win[1:])
			win[3] = b
			off++
		}
		n := binary.BigEndian.Uint32(win[:])
		if n == 0 || n > limit || off+frameOverhead+int64(n) > size {
			continue
		}
		buf := make([]byte, int(n)+4)
		if _, err := f.ReadAt(buf, off+4); err != nil {
			return -1, err
		}
		if binary.BigEndian.Uint32(buf[n:]) == crc32.Checksum(buf[:n], castagnoli()) {
			return off, nil
		}
	}
}

// quarantineName is SPEC §3.3's name for the bytes of file removed from
// offset on; k > 0 distinguishes a later recovery at the same offset.
func quarantineName(file string, offset int64, k int) string {
	what := "checkpoints"
	if file != checkpointsName {
		what = file[:16]
	}
	if k == 0 {
		return fmt.Sprintf("quarantine-%s-%016x.bin", what, offset)
	}
	return fmt.Sprintf("quarantine-%s-%016x-%d.bin", what, offset, k)
}

// maxQuarantineTries bounds the search for a free quarantine name. Each try
// is a recovery that already happened at this offset, so a thousand means
// something other than crashes is going on.
const maxQuarantineTries = 1000

// recoverTail quarantines the bytes of t after its last good frame and then
// removes them: by truncating, or, for a file shorter than its header, by
// removing the file. The quarantine file is durable, file and directory,
// before anything is removed (RF-20); nothing is ever deleted unquarantined.
func (s *Store) recoverTail(t tail) error {
	if t.state == tailClean {
		return nil
	}
	path := filepath.Join(s.dir, t.name)
	f, err := s.fsys.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("filestore: %w", err)
	}
	// Bounded: under one frame plus its overhead, or under a header.
	removed := make([]byte, t.size-t.end)
	_, err = f.ReadAt(removed, t.end)
	if err = errors.Join(err, f.Close()); err != nil {
		return fmt.Errorf("filestore: reading the tail of %s: %w", t.name, err)
	}

	if err := s.writeQuarantine(t, removed); err != nil {
		return err
	}

	if t.state == tailNoHeader {
		if err := s.fsys.Remove(path); err != nil {
			return fmt.Errorf("filestore: %w", err)
		}
		if err := fsx.SyncDir(s.fsys, s.dir); err != nil {
			return fmt.Errorf("filestore: %w", err)
		}
	} else {
		w, err := s.fsys.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			return fmt.Errorf("filestore: %w", err)
		}
		if err := w.Truncate(t.end); err != nil {
			return fmt.Errorf("filestore: %w", errors.Join(err, w.Close()))
		}
		if err := w.Sync(); err != nil {
			return fmt.Errorf("filestore: %w", errors.Join(err, w.Close()))
		}
		if err := w.Close(); err != nil {
			return fmt.Errorf("filestore: %w", err)
		}
	}
	s.recovered += int64(len(removed))
	return nil
}

// writeQuarantine stores removed durably under the first free quarantine
// name for t.
func (s *Store) writeQuarantine(t tail, removed []byte) error {
	for k := range maxQuarantineTries {
		f, err := s.createFile(quarantineName(t.name, t.end, k), removed)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("filestore: quarantining the tail of %s: %w", t.name, err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("filestore: %w", err)
		}
		return nil
	}
	return fmt.Errorf("filestore: %d quarantine files already exist for %s at offset %d", maxQuarantineTries, t.name, t.end)
}

// load opens the log in the directory, recovering its tail (SPEC §3.3, §3.4,
// RF-20). It classifies first and changes nothing until it has decided to
// open: a refusal leaves every byte where it was.
//
// Only the tails of the last segment and of the checkpoints file are
// recovered. Every other segment is complete by construction, since a segment
// is rotated only after its records are durable; a fault in one ends Records
// with an error, so tally.Open refuses the log.
func (s *Store) load() error {
	entries, err := s.fsys.ReadDir(s.dir)
	if err != nil {
		return fmt.Errorf("filestore: %w", err)
	}
	var segs []uint64
	hasCps := false
	for _, e := range entries {
		first, ok, perr := parseSegmentName(e.Name())
		if perr != nil {
			return perr
		}
		if ok {
			// ReadDir sorts by name, and 16 lowercase hex digits sort as
			// numbers do.
			segs = append(segs, first)
		}
		hasCps = hasCps || e.Name() == checkpointsName
	}

	// Classify, changing nothing.
	var (
		cps   tail
		floor uint64 // the size of the last good stored checkpoint
		fix   []tail // tails to recover, in this order
	)
	if hasCps {
		if cps, err = s.classify(checkpointsName, checkpointsHeaderLen, tally.MaxCheckpointLen); err != nil {
			return err
		}
		if cps.last != nil {
			if floor, err = tally.CheckpointSize(cps.last); err != nil {
				return fmt.Errorf("filestore: the last stored checkpoint: %w", err)
			}
		}
		fix = append(fix, cps)
	}
	var seg tail
	if len(segs) > 0 {
		if seg, err = s.classify(segmentName(segs[len(segs)-1]), segmentHeaderLen, tally.MaxRecordLen); err != nil {
			return err
		}
		if seg.state == tailNoHeader {
			// A crash while creating the segment: it holds no record. The
			// one before it was complete when this one was started.
			fix = append(fix, seg)
			segs = segs[:len(segs)-1]
			if len(segs) > 0 {
				if seg, err = s.classify(segmentName(segs[len(segs)-1]), segmentHeaderLen, tally.MaxRecordLen); err != nil {
					return err
				}
				if seg.state != tailClean {
					return fmt.Errorf("filestore: %s, before a partial segment, does not end on a complete frame", seg.name)
				}
			}
		} else {
			fix = append(fix, seg)
		}
	}

	// Decide.
	hasCps = hasCps && cps.state != tailNoHeader
	if len(segs) == 0 {
		if hasCps {
			return errors.New("filestore: a checkpoints file with no segment")
		}
		return s.recoverAll(fix)
	}
	for i, first := range segs {
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
	last := segs[len(segs)-1]
	if leaves := last + seg.frames; floor > leaves {
		return fmt.Errorf("%w: %d covered, %d would remain", errBelowCheckpoint, floor, leaves)
	}

	// Recover, then open.
	if rerr := s.recoverAll(fix); rerr != nil {
		return rerr
	}
	s.segs = segs
	s.next = last + seg.frames
	if seg.last != nil {
		s.last = tally.LeafHash(seg.last)
	} else {
		h, herr := s.readHeader(last)
		if herr != nil {
			return herr
		}
		s.last = h.prev
	}
	if s.seg, err = s.fsys.OpenFile(filepath.Join(s.dir, segmentName(last)), os.O_WRONLY|os.O_APPEND, 0); err != nil {
		return fmt.Errorf("filestore: %w", err)
	}
	s.segSize = seg.end
	if hasCps {
		if s.cps, err = s.fsys.OpenFile(filepath.Join(s.dir, checkpointsName), os.O_WRONLY|os.O_APPEND, 0); err != nil {
			return fmt.Errorf("filestore: %w", err)
		}
		s.cpsSize = cps.end
	}
	return nil
}

func (s *Store) recoverAll(tails []tail) error {
	for _, t := range tails {
		if err := s.recoverTail(t); err != nil {
			return err
		}
	}
	return nil
}

// Recovered returns how many bytes Open moved to quarantine (RF-20). tally.Open
// reports a non-zero count through Observer.Recovered.
func (s *Store) Recovered() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recovered
}
