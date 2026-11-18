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

// A tree that keeps only the compact range below start gives the same root,
// inclusion and consistency proofs as the whole tree, for every size, leaf and
// old size at or above start, and ErrPruned below it. Every start up to maxN,
// with every size above it (#59).
//
// Negative control: with prefixNode never matching, so that the range is not
// used, every pruned tree's root failed with ErrPruned. Verified by hand,
// restored before committing.
func TestPrunedTreeAgreesWithTheWhole(t *testing.T) {
	all := leavesN(maxN)
	whole, err := NewTree(0, nil, all)
	if err != nil {
		t.Fatal(err)
	}
	ran := 0
	for start := uint64(0); start <= maxN; start++ {
		prefix, err := whole.CompactRange(start)
		if err != nil {
			t.Fatal(err)
		}
		pr, err := NewTree(start, prefix, all[start:])
		if err != nil {
			t.Fatalf("start %d: %v", start, err)
		}
		for n := max(start, 1); n <= maxN; n++ {
			ran++
			want, _ := whole.Root(n)
			if got, err := pr.Root(n); err != nil || got != want {
				t.Fatalf("start %d: root of %d = %x, %v; want %x", start, n, got, err, want)
			}
			for i := range n {
				got, err := pr.InclusionProof(i, n)
				if i < start {
					if !errors.Is(err, ErrPruned) {
						t.Fatalf("start %d: inclusion of pruned leaf %d: %v, want ErrPruned", start, i, err)
					}
					continue
				}
				w, _ := whole.InclusionProof(i, n)
				if err != nil || !equal(got, w) {
					t.Fatalf("start %d: inclusion of %d in %d differs: %v", start, i, n, err)
				}
			}
			for m := uint64(1); m <= n; m++ {
				got, err := pr.ConsistencyProof(m, n)
				if m < start {
					if !errors.Is(err, ErrPruned) {
						t.Fatalf("start %d: consistency from pruned size %d: %v, want ErrPruned", start, m, err)
					}
					continue
				}
				w, _ := whole.ConsistencyProof(m, n)
				if err != nil || !equal(got, w) {
					t.Fatalf("start %d: consistency %d -> %d differs: %v", start, m, n, err)
				}
			}
		}
		if start > 1 {
			if _, err := pr.Root(start - 1); !errors.Is(err, ErrPruned) {
				t.Fatalf("start %d: root of a pruned size: %v, want ErrPruned", start, err)
			}
		}
	}
	if want := maxN + maxN*(maxN+1)/2; ran != want { // start 0: sizes 1..maxN; start s: s..maxN
		t.Fatalf("checked %d (start, size) pairs, want %d", ran, want)
	}
}

// A compact range extends from an earlier one: what a second prune needs,
// once the leaves below the first are gone.
func TestCompactRangeExtends(t *testing.T) {
	all := leavesN(maxN)
	whole, _ := NewTree(0, nil, all)
	ran := 0
	for s1 := uint64(0); s1 <= maxN; s1++ {
		p1, _ := whole.CompactRange(s1)
		pr, err := NewTree(s1, p1, all[s1:])
		if err != nil {
			t.Fatal(err)
		}
		for s2 := s1; s2 <= maxN; s2++ {
			got, err := pr.CompactRange(s2)
			want, _ := whole.CompactRange(s2)
			if err != nil || !equal(got, want) {
				t.Fatalf("range %d extended to %d: %v", s1, s2, err)
			}
			ran++
		}
	}
	if want := (maxN + 1) * (maxN + 2) / 2; ran != want {
		t.Fatalf("checked %d pairs, want %d", ran, want)
	}
	if _, err := NewTree(5, make([][32]byte, 1), nil); err == nil {
		t.Error("a range of 1 hash below 5 was accepted; 5 needs 2")
	}
}

func equal(a, b [][32]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
