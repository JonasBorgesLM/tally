// Package merkle is the RFC 6962 Merkle tree over tally's leaves (ADR-0002,
// ADR-0004): the tree hash, inclusion proofs and consistency proofs, and
// their verification.
//
// The leaves are the leaf hashes tally already stores and chains, SHA-256(0x00
// || record bytes), with genesis as leaf 0; the tree adds only interior nodes,
// SHA-256(0x01 || left || right). So a tree over a log written by v0.1 needs
// nothing rewritten: it is computed from the hashes the log already has.
//
// Building a proof follows RFC 6962 §2.1's recursive definitions; checking one
// follows RFC 9162 §2.1.3.2 and §2.1.4.2, which take only the proof and the two
// sizes. The two halves are deliberately different algorithms, so a mistake in
// one is not repeated in the other, and both are checked against
// golang.org/x/mod/sumdb/tlog in the interop module.
package merkle

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/bits"
)

// ErrInvalidProof means a proof does not show what it was checked for: the
// leaf is not in the tree at that index, or the smaller tree is not a prefix
// of the larger one. A malformed proof, of the wrong length or for sizes it
// cannot hold, is invalid too.
var ErrInvalidProof = errors.New("merkle: invalid proof")

// NodeHash is an interior node, SHA-256(0x01 || left || right). 0x01 is the
// prefix RS-01 reserves for it, so no interior node can be read as a leaf.
func NodeHash(left, right [32]byte) [32]byte {
	var buf [1 + 32 + 32]byte
	buf[0] = 0x01
	copy(buf[1:33], left[:])
	copy(buf[33:], right[:])
	return sha256.Sum256(buf[:])
}

// ErrPruned means a proof or root needs leaves below a tree's first retained
// leaf, which only a compact range stands for: a root of a smaller size, the
// inclusion of a pruned leaf, or a consistency proof from a size below it.
var ErrPruned = errors.New("merkle: the leaves it needs were pruned")

// Tree is a tree whose leaves from Start on are known, and whose leaves below
// Start are known only by their compact range: the root of each maximal
// aligned subtree of [0, Start), largest first, one per bit set in Start. That
// is at most 64 hashes, and what a pruned log keeps (#59, ADR-0012). From it,
// a Tree builds every root of a size at least Start, the inclusion of every
// leaf from Start on, and consistency from every size at least Start: each
// needs, below Start, only whole subtrees of the range.
type Tree struct {
	start  uint64
	prefix [][32]byte
	leaves [][32]byte
}

// NewTree returns the tree of the leaves from start on, after the compact
// range prefix of the leaves below start. With start 0, prefix is empty and
// the tree holds every leaf. The tree must not be empty.
func NewTree(start uint64, prefix, leaves [][32]byte) (*Tree, error) {
	if len(prefix) != bits.OnesCount64(start) {
		return nil, fmt.Errorf("merkle: a compact range below %d has %d hashes, not %d", start, bits.OnesCount64(start), len(prefix))
	}
	if start+uint64(len(leaves)) == 0 {
		return nil, errors.New("merkle: a tree has at least one leaf")
	}
	return &Tree{start: start, prefix: prefix, leaves: leaves}, nil
}

// Size is the number of leaves, pruned ones included.
func (t *Tree) Size() uint64 { return t.start + uint64(len(t.leaves)) }

// Start is the first leaf the tree holds itself.
func (t *Tree) Start() uint64 { return t.start }

// Root is RFC 6962's MTH of the first n leaves.
func (t *Tree) Root(n uint64) ([32]byte, error) {
	if n == 0 || n > t.Size() {
		return [32]byte{}, fmt.Errorf("merkle: no root of size %d in a tree of %d", n, t.Size())
	}
	if n < t.start {
		return [32]byte{}, ErrPruned
	}
	return t.mth(0, n)
}

// InclusionProof is RFC 6962's PATH: the hashes that, with the leaf at index,
// recompute the root of the first n leaves.
func (t *Tree) InclusionProof(index, n uint64) ([][32]byte, error) {
	if index >= n || n > t.Size() {
		return nil, fmt.Errorf("merkle: no inclusion proof of %d in size %d of a tree of %d", index, n, t.Size())
	}
	if index < t.start {
		return nil, ErrPruned
	}
	return t.path(index, 0, n)
}

// ConsistencyProof is RFC 6962's PROOF: the hashes that show the tree of the
// first m leaves is a prefix of the tree of the first n. For m equal to n,
// the proof is empty.
func (t *Tree) ConsistencyProof(m, n uint64) ([][32]byte, error) {
	if m == 0 || m > n || n > t.Size() {
		return nil, fmt.Errorf("merkle: no consistency proof from size %d to %d in a tree of %d", m, n, t.Size())
	}
	if m < t.start {
		return nil, ErrPruned
	}
	if m == n {
		return nil, nil
	}
	return t.subproof(m, 0, n, true)
}

// CompactRange is the compact range of the first n leaves: the root of each
// maximal aligned subtree of [0, n), largest first. It is what a Tree with
// start n needs below it.
func (t *Tree) CompactRange(n uint64) ([][32]byte, error) {
	if n > t.Size() {
		return nil, fmt.Errorf("merkle: no compact range of %d in a tree of %d", n, t.Size())
	}
	var out [][32]byte
	off := uint64(0)
	for b := 63; b >= 0; b-- {
		w := uint64(1) << b
		if n&w == 0 {
			continue
		}
		h, err := t.mth(off, off+w)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
		off += w
	}
	return out, nil
}

// Root is the tree hash of leaves, RFC 6962's MTH. tally's tree is never empty
// (genesis is leaf 0), so Root of no leaves is an error rather than RFC 6962's
// hash of the empty string, which no tally checkpoint can name.
func Root(leaves [][32]byte) ([32]byte, error) {
	t, err := NewTree(0, nil, leaves)
	if err != nil {
		return [32]byte{}, err
	}
	return t.Root(t.Size())
}

// InclusionProof is Tree.InclusionProof over every leaf.
func InclusionProof(leaves [][32]byte, index uint64) ([][32]byte, error) {
	return (&Tree{leaves: leaves}).InclusionProof(index, uint64(len(leaves)))
}

// ConsistencyProof is Tree.ConsistencyProof from size m to every leaf.
func ConsistencyProof(leaves [][32]byte, m uint64) ([][32]byte, error) {
	return (&Tree{leaves: leaves}).ConsistencyProof(m, uint64(len(leaves)))
}

// mth is RFC 6962 §2.1's MTH of the leaves [lo, hi), hi > lo. Below start,
// it can answer only for a whole subtree of the compact range, or a union of
// them; RFC 6962's splits never ask for less when the request is at or above
// start, and ErrPruned says so if they ever did.
func (t *Tree) mth(lo, hi uint64) ([32]byte, error) {
	if lo >= t.start {
		if hi-lo == 1 {
			return t.leaves[lo-t.start], nil
		}
	} else if hi <= t.start {
		if h, ok := t.prefixNode(lo, hi); ok {
			return h, nil
		}
		if hi-lo == 1 {
			return [32]byte{}, ErrPruned
		}
	}
	k := split(hi - lo)
	l, err := t.mth(lo, lo+k)
	if err != nil {
		return [32]byte{}, err
	}
	r, err := t.mth(lo+k, hi)
	if err != nil {
		return [32]byte{}, err
	}
	return NodeHash(l, r), nil
}

// prefixNode is the compact range's subtree [lo, hi), if it is one.
func (t *Tree) prefixNode(lo, hi uint64) ([32]byte, bool) {
	off, i := uint64(0), 0
	for b := 63; b >= 0 && off <= lo; b-- {
		w := uint64(1) << b
		if t.start&w == 0 {
			continue
		}
		if off == lo && off+w == hi {
			return t.prefix[i], true
		}
		off += w
		i++
	}
	return [32]byte{}, false
}

// path is RFC 6962 §2.1.1's PATH(m, D[lo:hi]), with m an absolute index.
func (t *Tree) path(m, lo, hi uint64) ([][32]byte, error) {
	if hi-lo == 1 {
		return nil, nil
	}
	k := lo + split(hi-lo)
	// The leaf's side, then the other side's root.
	sideLo, sideHi, otherLo, otherHi := lo, k, k, hi
	if m >= k {
		sideLo, sideHi, otherLo, otherHi = k, hi, lo, k
	}
	p, err := t.path(m, sideLo, sideHi)
	if err != nil {
		return nil, err
	}
	sib, err := t.mth(otherLo, otherHi)
	if err != nil {
		return nil, err
	}
	return append(p, sib), nil
}

// subproof is RFC 6962 §2.1.2's SUBPROOF(m, D[lo:hi], b), with m absolute.
func (t *Tree) subproof(m, lo, hi uint64, b bool) ([][32]byte, error) {
	if m == hi {
		if b {
			return nil, nil
		}
		h, err := t.mth(lo, hi)
		if err != nil {
			return nil, err
		}
		return [][32]byte{h}, nil
	}
	k := lo + split(hi-lo)
	// m inside the left subtree keeps b; past it, the left subtree is whole
	// in both trees and the recursion goes right with b false.
	sideLo, sideHi, otherLo, otherHi := lo, k, k, hi
	if m > k {
		sideLo, sideHi, otherLo, otherHi, b = k, hi, lo, k, false
	}
	p, err := t.subproof(m, sideLo, sideHi, b)
	if err != nil {
		return nil, err
	}
	sib, err := t.mth(otherLo, otherHi)
	if err != nil {
		return nil, err
	}
	return append(p, sib), nil
}

// split is the largest power of two smaller than n, for n > 1.
func split(n uint64) uint64 {
	return 1 << (bits.Len64(n-1) - 1)
}

// VerifyInclusion checks that leaf is at index in the tree of size whose root
// is root, by RFC 9162 §2.1.3.2.
func VerifyInclusion(leaf [32]byte, index, size uint64, proof [][32]byte, root [32]byte) error {
	if index >= size {
		return ErrInvalidProof
	}
	fn, sn := index, size-1
	r := leaf
	for _, p := range proof {
		if sn == 0 {
			return ErrInvalidProof // the proof is longer than the tree is deep
		}
		if fn&1 == 1 || fn == sn {
			r = NodeHash(p, r)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			r = NodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 || r != root {
		return ErrInvalidProof
	}
	return nil
}

// VerifyConsistency checks that the tree of size m with root oldRoot is a
// prefix of the tree of size n with root newRoot, by RFC 9162 §2.1.4.2.
func VerifyConsistency(m, n uint64, proof [][32]byte, oldRoot, newRoot [32]byte) error {
	if m == 0 || m > n {
		return ErrInvalidProof
	}
	if m == n {
		if len(proof) != 0 || oldRoot != newRoot {
			return ErrInvalidProof
		}
		return nil
	}
	if len(proof) == 0 {
		return ErrInvalidProof
	}
	// A size that is a power of two is a whole subtree of the larger tree,
	// and RFC 6962 leaves its root out of the proof.
	if m&(m-1) == 0 {
		proof = append([][32]byte{oldRoot}, proof...)
	}
	fn, sn := m-1, n-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr, sr := proof[0], proof[0]
	for _, c := range proof[1:] {
		if sn == 0 {
			return ErrInvalidProof
		}
		if fn&1 == 1 || fn == sn {
			fr = NodeHash(c, fr)
			sr = NodeHash(c, sr)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			sr = NodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 || fr != oldRoot || sr != newRoot {
		return ErrInvalidProof
	}
	return nil
}
