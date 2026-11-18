package merkle

import "testing"

// A range grown leaf by leaf has, at every size, the root and the compact
// range the whole tree has; and it grows the same from a range taken at any
// earlier size, as a pruned log's writer starts.
//
// Negative control: with Append's carry loop removed, the range at size 2 had
// two hashes instead of one. Verified by hand, restored before committing.
func TestRangeGrowsAsTheTree(t *testing.T) {
	all := leavesN(maxN)
	whole, _ := NewTree(0, nil, all)
	ran := 0
	for start := uint64(0); start <= maxN; start++ {
		prefix, _ := whole.CompactRange(start)
		r, err := NewRange(start, prefix)
		if err != nil {
			t.Fatal(err)
		}
		for n := start + 1; n <= maxN; n++ {
			r.Append(all[n-1])
			want, _ := whole.Root(n)
			if got, err := r.Root(); err != nil || got != want {
				t.Fatalf("from %d: root at %d = %x, %v; want %x", start, n, got, err, want)
			}
			wantRange, _ := whole.CompactRange(n)
			if !equal(r.Hashes(), wantRange) {
				t.Fatalf("from %d: range at %d has %d hashes, want %d", start, n, len(r.Hashes()), len(wantRange))
			}
			ran++
		}
	}
	if want := maxN * (maxN + 1) / 2; ran != want {
		t.Fatalf("checked %d sizes, want %d", ran, want)
	}
	empty, _ := NewRange(0, nil)
	if _, err := empty.Root(); err == nil {
		t.Error("an empty range has a root")
	}
	if _, err := NewRange(3, nil); err == nil {
		t.Error("a range below 3 with no hashes was accepted")
	}
}

// A clone grows apart from its original.
func TestRangeCloneIsIndependent(t *testing.T) {
	all := leavesN(3)
	r, _ := NewRange(0, nil)
	r.Append(all[0])
	c := r.Clone()
	c.Append(all[1])
	if r.Size() != 1 || c.Size() != 2 {
		t.Fatalf("sizes %d and %d, want 1 and 2", r.Size(), c.Size())
	}
	if got, _ := r.Root(); got != all[0] {
		t.Fatal("appending to the clone changed the original")
	}
}
