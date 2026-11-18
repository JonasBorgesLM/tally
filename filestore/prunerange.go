package filestore

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"math/bits"
	"os"
	"path/filepath"
	"strconv"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/internal/fsx"
	"github.com/JonasBorgesLM/tally/internal/merkle"
)

// A Log reopening a pruned Store keeps the Merkle root from its range (#60).
var _ tally.CompactRanger = (*Store)(nil)

// pruneRangeName holds the compact range of the pruned leaves (SPEC §3.6).
const pruneRangeName = "pruned.range"

const pruneRangeHeader = "tally pruned range\n"

// maxPruneRange bounds the file before it is read (RS-05): the header, a
// 20-digit start, and 64 base64 hashes of 44 characters, each on a line.
const maxPruneRange = len(pruneRangeHeader) + 21 + 64*45

// encodePruneRange is SPEC §3.6: the header, the first retained seq in
// decimal, then each hash of the compact range below it, largest subtree
// first, in standard base64, one per line.
func encodePruneRange(start uint64, prefix [][32]byte) []byte {
	var b bytes.Buffer
	b.WriteString(pruneRangeHeader)
	b.WriteString(strconv.FormatUint(start, 10))
	b.WriteByte('\n')
	for _, h := range prefix {
		b.WriteString(base64.StdEncoding.EncodeToString(h[:]))
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// decodePruneRange is encodePruneRange's inverse, and accepts nothing else:
// the file re-encodes to its own bytes.
func decodePruneRange(data []byte) (start uint64, prefix [][32]byte, err error) {
	bad := errors.New("filestore: malformed pruned range")
	rest, ok := bytes.CutPrefix(data, []byte(pruneRangeHeader))
	if !ok {
		return 0, nil, bad
	}
	line, rest, ok := bytes.Cut(rest, []byte{'\n'})
	if !ok {
		return 0, nil, bad
	}
	start, err = strconv.ParseUint(string(line), 10, 64)
	if err != nil || start == 0 {
		return 0, nil, bad
	}
	prefix = make([][32]byte, 0, bits.OnesCount64(start))
	for len(rest) > 0 {
		line, rest, ok = bytes.Cut(rest, []byte{'\n'})
		if !ok || len(line) != 44 || len(prefix) == cap(prefix) {
			return 0, nil, bad
		}
		// Decoded into room for what 44 characters can hold, 33 bytes: a
		// buffer of 32 panics on a line that decodes longer (RS-05).
		var buf [33]byte
		if n, err := base64.StdEncoding.Decode(buf[:], line); err != nil || n != 32 {
			return 0, nil, bad
		}
		prefix = append(prefix, [32]byte(buf[:32]))
	}
	if len(prefix) != cap(prefix) || !bytes.Equal(encodePruneRange(start, prefix), data) {
		return 0, nil, bad
	}
	return start, prefix, nil
}

// CompactRange is tally.CompactRanger: the compact range the last prune
// stored (SPEC §3.6), ok false when there is none.
func (s *Store) CompactRange(_ context.Context) (start uint64, prefix [][32]byte, ok bool, err error) {
	return readPruneRange(s.fsys, s.dir)
}

// CompactRange is tally.CompactRanger for a verifier: the range the last
// prune stored, which Verify uses only to compare roots that a trusted
// checkpoint signs (SPEC §3.6).
func (r *Reader) CompactRange(_ context.Context) (start uint64, prefix [][32]byte, ok bool, err error) {
	return readPruneRange(r.fsys, r.dir)
}

var _ tally.CompactRanger = (*Reader)(nil)

// readPruneRange reads dir's pruned range, bounded before reading (RS-05).
func readPruneRange(fsys fsx.FS, dir string) (start uint64, prefix [][32]byte, ok bool, err error) {
	f, err := fsys.OpenFile(filepath.Join(dir, pruneRangeName), os.O_RDONLY, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil, false, nil
	}
	if err != nil {
		return 0, nil, false, err
	}
	defer f.Close() //nolint:errcheck // read-only: a close error loses no data
	data, err := io.ReadAll(io.LimitReader(f, int64(maxPruneRange)+1))
	if err != nil {
		return 0, nil, false, err
	}
	if len(data) > maxPruneRange {
		return 0, nil, false, errors.New("filestore: pruned range too large")
	}
	start, prefix, err = decodePruneRange(data)
	if err != nil {
		return 0, nil, false, err
	}
	return start, prefix, true, nil
}

// tree is the Merkle tree of the stored log from first on: the compact range
// below the first retained leaf, if the log was pruned, and every stored leaf
// from there (#59). first is the first seq the store holds. A log pruned
// without a range, by v0.1, has no tree: ErrNoTree.
func (s *Store) tree(ctx context.Context, first uint64) (*merkle.Tree, error) {
	return s.treeUpTo(ctx, first, math.MaxUint64)
}

// treeUpTo is tree over the leaves below upTo only.
func (s *Store) treeUpTo(ctx context.Context, first, upTo uint64) (*merkle.Tree, error) {
	start, prefix := uint64(0), [][32]byte(nil)
	if first > 0 {
		var ok bool
		var err error
		start, prefix, ok, err = s.CompactRange(ctx)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errNoTree
		}
		// A crash during a prune can leave segments below the range's start,
		// whose leaves the range already covers. A range starting below the
		// first segment stands for leaves that are gone and not in it.
		if start < first {
			return nil, fmt.Errorf("filestore: the pruned range starts at %d, below the log's first record %d", start, first)
		}
	}
	var leaves [][32]byte
	for rec, err := range s.Records(ctx, start) {
		if err != nil {
			return nil, err
		}
		if rec.Seq >= upTo {
			break
		}
		leaves = append(leaves, tally.LeafHash(rec.Body))
	}
	return merkle.NewTree(start, prefix, leaves)
}

// errNoTree means the leaves below the log's first record are gone and no
// range stands for them: the log was pruned by v0.1, before ranges existed.
var errNoTree = errors.New("filestore: the log was pruned without a range; no tree reaches below it")
