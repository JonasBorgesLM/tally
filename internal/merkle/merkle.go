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

// Root is the tree hash of leaves, RFC 6962's MTH. tally's tree is never empty
// (genesis is leaf 0), so Root of no leaves is an error rather than RFC 6962's
// hash of the empty string, which no tally checkpoint can name.
func Root(leaves [][32]byte) ([32]byte, error) {
	if len(leaves) == 0 {
		return [32]byte{}, errors.New("merkle: a tree has at least one leaf")
	}
	return mth(leaves), nil
}

// InclusionProof is RFC 6962's PATH: the hashes that, with the leaf at index,
// recompute the root of leaves.
func InclusionProof(leaves [][32]byte, index uint64) ([][32]byte, error) {
	if index >= uint64(len(leaves)) {
		return nil, fmt.Errorf("merkle: index %d is not below the tree size %d", index, len(leaves))
	}
	return path(index, leaves), nil
}

// ConsistencyProof is RFC 6962's PROOF: the hashes that show the tree of the
// first m leaves is a prefix of the tree of all of them. For m equal to the
// size, the proof is empty.
func ConsistencyProof(leaves [][32]byte, m uint64) ([][32]byte, error) {
	n := uint64(len(leaves))
	if m == 0 || m > n {
		return nil, fmt.Errorf("merkle: no consistency proof from size %d to size %d", m, n)
	}
	if m == n {
		return nil, nil
	}
	return subproof(m, leaves, true), nil
}

// mth is RFC 6962 §2.1's MTH, for at least one leaf.
func mth(d [][32]byte) [32]byte {
	if len(d) == 1 {
		return d[0]
	}
	k := split(uint64(len(d)))
	return NodeHash(mth(d[:k]), mth(d[k:]))
}

// path is RFC 6962 §2.1.1's PATH(m, D[n]).
func path(m uint64, d [][32]byte) [][32]byte {
	if len(d) == 1 {
		return nil
	}
	k := split(uint64(len(d)))
	if m < k {
		return append(path(m, d[:k]), mth(d[k:]))
	}
	return append(path(m-k, d[k:]), mth(d[:k]))
}

// subproof is RFC 6962 §2.1.2's SUBPROOF(m, D[n], b).
func subproof(m uint64, d [][32]byte, b bool) [][32]byte {
	n := uint64(len(d))
	if m == n {
		if b {
			return nil
		}
		return [][32]byte{mth(d)}
	}
	k := split(n)
	if m <= k {
		return append(subproof(m, d[:k], b), mth(d[k:]))
	}
	return append(subproof(m-k, d[k:], false), mth(d[:k]))
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
