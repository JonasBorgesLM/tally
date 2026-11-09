package tally

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
)

// Frames are SPEC §3.2: len uint32, body, CRC-32C of body. The CRC detects
// partial writes and accidental corruption; anyone rewriting a file recomputes
// it, so it is never evidence of anything. Classifying a bad tail on opening
// (§3.3) is the store's job; here every bad frame is a violation.

const (
	frameOverhead = 4 + 4
	// maxFrameLen is SPEC §6's frame ceiling. The largest valid ENTRY body is
	// under it.
	maxFrameLen = 16<<20 + 2<<10
)

var (
	errFrameTruncated = errors.New("tally: frame runs past the end of the input")
	errFrameTooLong   = errors.New("tally: frame length over the ceiling")
	errFrameCRC       = errors.New("tally: frame CRC mismatch")
)

func castagnoli() *crc32.Table {
	// MakeTable caches the Castagnoli table itself, so this holds no state here.
	return crc32.MakeTable(crc32.Castagnoli)
}

// appendFrame appends body to dst as one frame. body must be within the frame
// ceiling, which every encodable record is.
func appendFrame(dst, body []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(body))) // #nosec G115 -- records are under maxFrameLen, far below 2^32.
	dst = append(dst, body...)
	return binary.BigEndian.AppendUint32(dst, crc32.Checksum(body, castagnoli()))
}

// readFrame reads the frame at the start of b and returns its body, a slice of
// b, and the bytes after it. The length is checked against the ceiling before
// anything else is read (RS-05).
func readFrame(b []byte) (body, rest []byte, err error) {
	if len(b) < 4 {
		return nil, nil, fmt.Errorf("%w: %w", errMalformed, errFrameTruncated)
	}
	n := binary.BigEndian.Uint32(b)
	if n > maxFrameLen {
		return nil, nil, fmt.Errorf("%w: %w", errMalformed, errFrameTooLong)
	}
	if uint64(len(b)) < uint64(n)+frameOverhead {
		return nil, nil, fmt.Errorf("%w: %w", errMalformed, errFrameTruncated)
	}
	end := 4 + int(n)
	body = b[4:end]
	if binary.BigEndian.Uint32(b[end:]) != crc32.Checksum(body, castagnoli()) {
		return nil, nil, fmt.Errorf("%w: %w", errMalformed, errFrameCRC)
	}
	return body, b[end+4:], nil
}
