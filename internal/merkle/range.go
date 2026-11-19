package merkle

import (
	"fmt"
	"math/bits"
)

// Range is a compact range grown one leaf at a time: the roots of the maximal
// aligned subtrees of [0, size), largest first, one per bit set in size. A
// writer keeps one to sign the root of every checkpoint without rereading the
// log (#60): Append costs O(log n) hashes, and Root folds at most 64. The zero
// Range is empty, the range below leaf 0.
type Range struct {
	size   uint64
	hashes [][32]byte
}

// NewRange returns the range below size, from its hashes (Tree.CompactRange,
// or a pruned log's stored range). With size 0, hashes is empty.
func NewRange(size uint64, hashes [][32]byte) (*Range, error) {
	if len(hashes) != bits.OnesCount64(size) {
		return nil, fmt.Errorf("merkle: a compact range below %d has %d hashes, not %d", size, bits.OnesCount64(size), len(hashes))
	}
	return &Range{size: size, hashes: append([][32]byte(nil), hashes...)}, nil
}

// Size is the number of leaves the range covers.
func (r *Range) Size() uint64 { return r.size }

// Hashes returns a copy of the range's hashes, largest subtree first.
func (r *Range) Hashes() [][32]byte { return append([][32]byte(nil), r.hashes...) }

// Append adds the next leaf. Every trailing subtree it completes merges into
// its left neighbour, as a binary counter carries.
func (r *Range) Append(leaf [32]byte) {
	r.hashes = append(r.hashes, leaf)
	for n := r.size; n&1 == 1; n >>= 1 {
		last := len(r.hashes) - 1
		r.hashes[last-1] = NodeHash(r.hashes[last-1], r.hashes[last])
		r.hashes = r.hashes[:last]
	}
	r.size++
}

// Root is the RFC 6962 root of the leaves the range covers: the subtrees
// folded from the right, which is how MTH splits a size that is not a power
// of two. A range of no leaves has no root.
func (r *Range) Root() ([32]byte, error) {
	if r.size == 0 {
		return [32]byte{}, fmt.Errorf("merkle: a tree has at least one leaf")
	}
	root := r.hashes[len(r.hashes)-1]
	for i := len(r.hashes) - 2; i >= 0; i-- {
		root = NodeHash(r.hashes[i], root)
	}
	return root, nil
}

// Clone returns an independent copy, so a writer can grow a candidate batch
// and keep the old range if the batch is not stored.
func (r *Range) Clone() *Range {
	return &Range{size: r.size, hashes: append([][32]byte(nil), r.hashes...)}
}
