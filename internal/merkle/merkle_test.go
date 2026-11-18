package merkle

import (
	"crypto/sha256"
	"errors"
	"testing"
)

func leavesN(n int) [][32]byte {
	out := make([][32]byte, n)
	for i := range out {
		out[i] = sha256.Sum256(append([]byte{0x00}, byte(i), byte(i>>8)))
	}
	return out
}

func rootOf(t *testing.T, l [][32]byte) [32]byte {
	t.Helper()
	r, err := Root(l)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// The tree hash by hand, for the shapes RFC 6962's recursion splits
// differently: one leaf, a power of two, and a right edge that is not.
func TestRootByHand(t *testing.T) {
	l := leavesN(5)
	cases := []struct {
		n    int
		want [32]byte
	}{
		{1, l[0]},
		{2, NodeHash(l[0], l[1])},
		{3, NodeHash(NodeHash(l[0], l[1]), l[2])},
		{4, NodeHash(NodeHash(l[0], l[1]), NodeHash(l[2], l[3]))},
		{5, NodeHash(NodeHash(NodeHash(l[0], l[1]), NodeHash(l[2], l[3])), l[4])},
	}
	for _, c := range cases {
		if got := rootOf(t, l[:c.n]); got != c.want {
			t.Errorf("Root of %d leaves = %x, want %x", c.n, got, c.want)
		}
	}
	if _, err := Root(nil); err == nil {
		t.Error("Root of no leaves succeeded; a tally tree always has genesis")
	}
}

// An interior node can never be read as a leaf: the prefixes differ (RS-01).
func TestNodeHashIsDomainSeparated(t *testing.T) {
	var a, b [32]byte
	a[0], b[0] = 1, 2
	buf := append(append([]byte{0x00}, a[:]...), b[:]...)
	if NodeHash(a, b) == sha256.Sum256(buf) {
		t.Fatal("NodeHash uses the leaf prefix")
	}
}

const maxN = 40

// Every inclusion proof, for every leaf of every size up to maxN, verifies,
// and is refused for any other leaf, index or root, for another tree (another
// size with that size's root), or with any hash changed, dropped or added.
//
// A size and a root go together: a checkpoint signs both. A proof checked
// with another size but this tree's root can verify, since RFC 9162's check
// only walks the path's shape, and two sizes can share it (index 0 in sizes 3
// and 4). That is not a forgery, as no signed checkpoint pairs them.
func TestInclusionProofs(t *testing.T) {
	all := leavesN(maxN + 1)
	ran := 0
	for n := 1; n <= maxN; n++ {
		l := all[:n]
		root := rootOf(t, l)
		nextRoot := rootOf(t, all[:n+1])
		for i := range n {
			idx := uint64(i)
			p, err := InclusionProof(l, idx)
			if err != nil {
				t.Fatal(err)
			}
			ran++
			if err := VerifyInclusion(l[i], idx, uint64(n), p, root); err != nil {
				t.Fatalf("size %d, index %d: a correct proof is refused: %v", n, i, err)
			}
			refused := func(what string, err error) {
				t.Helper()
				if !errors.Is(err, ErrInvalidProof) {
					t.Fatalf("size %d, index %d: %s verified", n, i, what)
				}
			}
			refused("another leaf", VerifyInclusion(sha256.Sum256([]byte("x")), idx, uint64(n), p, root))
			refused("index = size", VerifyInclusion(l[i], uint64(n), uint64(n), p, root))
			if n > 1 {
				refused("another index", VerifyInclusion(l[i], (idx+1)%uint64(n), uint64(n), p, root))
			}
			refused("the next tree", VerifyInclusion(l[i], idx, uint64(n)+1, p, nextRoot))
			refused("another root", VerifyInclusion(l[i], idx, uint64(n), p, sha256.Sum256(nil)))
			refused("an extra hash", VerifyInclusion(l[i], idx, uint64(n), append(clone(p), root), root))
			for j := range p {
				q := clone(p)
				q[j][0] ^= 1
				refused("a changed hash", VerifyInclusion(l[i], idx, uint64(n), q, root))
				refused("a dropped hash", VerifyInclusion(l[i], idx, uint64(n), append(clone(p[:j]), p[j+1:]...), root))
			}
		}
	}
	if want := maxN * (maxN + 1) / 2; ran != want {
		t.Fatalf("checked %d proofs, want %d", ran, want)
	}
	if _, err := InclusionProof(all[:3], 3); err == nil {
		t.Error("a proof for an index past the tree was built")
	}
	if _, err := InclusionProof(nil, 0); err == nil {
		t.Error("a proof for an index past the tree was built")
	}
}

// Every consistency proof between every pair of sizes up to maxN verifies,
// and is refused for any other root, for another pair of trees (other sizes
// with their own roots), or with any hash changed, dropped or added.
//
// Negative control: with VerifyConsistency's `fr != oldRoot` check removed,
// "another old root" verified, first at 3 -> 4. (A power-of-two old size
// puts the old root into the proof itself, so it is checked either way.)
// Verified by hand, restored before committing.
func TestConsistencyProofs(t *testing.T) {
	all := leavesN(maxN)
	ran := 0
	for n := 1; n <= maxN; n++ {
		newRoot := rootOf(t, all[:n])
		for m := 1; m <= n; m++ {
			oldRoot := rootOf(t, all[:m])
			mm, nn := uint64(m), uint64(n) // #nosec G115 -- m and n are loop bounds up to maxN
			p, err := ConsistencyProof(all[:n], mm)
			if err != nil {
				t.Fatal(err)
			}
			ran++
			if err := VerifyConsistency(mm, nn, p, oldRoot, newRoot); err != nil {
				t.Fatalf("%d -> %d: a correct proof is refused: %v", m, n, err)
			}
			refused := func(what string, err error) {
				t.Helper()
				if !errors.Is(err, ErrInvalidProof) {
					t.Fatalf("%d -> %d: %s verified", m, n, what)
				}
			}
			other := sha256.Sum256([]byte("other"))
			refused("another old root", VerifyConsistency(mm, nn, p, other, newRoot))
			refused("another new root", VerifyConsistency(mm, nn, p, oldRoot, other))
			refused("an extra hash", VerifyConsistency(mm, nn, append(clone(p), other), oldRoot, newRoot))
			if m < n {
				refused("the next old tree", VerifyConsistency(mm+1, nn, p, rootOf(t, all[:m+1]), newRoot))
				refused("the previous new tree", VerifyConsistency(mm, nn-1, p, oldRoot, rootOf(t, all[:n-1])))
			}
			for j := range p {
				q := clone(p)
				q[j][0] ^= 1
				refused("a changed hash", VerifyConsistency(mm, nn, q, oldRoot, newRoot))
				refused("a dropped hash", VerifyConsistency(mm, nn, append(clone(p[:j]), p[j+1:]...), oldRoot, newRoot))
			}
		}
	}
	if want := maxN * (maxN + 1) / 2; ran != want {
		t.Fatalf("checked %d proofs, want %d", ran, want)
	}
	for _, c := range [][2]uint64{{0, 3}, {4, 3}} {
		if _, err := ConsistencyProof(all[:c[1]], c[0]); err == nil {
			t.Errorf("a proof from size %d to %d was built", c[0], c[1])
		}
		if err := VerifyConsistency(c[0], c[1], nil, [32]byte{}, [32]byte{}); !errors.Is(err, ErrInvalidProof) {
			t.Errorf("sizes %d -> %d verified", c[0], c[1])
		}
	}
}

func clone(p [][32]byte) [][32]byte { return append([][32]byte(nil), p...) }
