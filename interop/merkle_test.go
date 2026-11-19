package interop

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"testing"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/internal/merkle"
	tnote "github.com/JonasBorgesLM/tally/internal/note"
	"github.com/JonasBorgesLM/tally/tallytest"
)

// Differential tests of tally's Merkle tree (internal/merkle, #59) against
// golang.org/x/mod/sumdb/tlog, an independent RFC 6962 implementation: the
// same roots, the same proofs, and each side's proofs accepted by the other.
//
// Negative control: with internal/merkle's interior prefix changed from 0x01
// to 0x02, the roots differed at size 2. Verified by hand, restored.

// tlogTree is x/mod's own storage of a tree: every stored hash, by its
// stored-hash index.
type tlogTree struct{ stored []tlog.Hash }

func (tr *tlogTree) ReadHashes(idx []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(idx))
	for i, x := range idx {
		if x >= int64(len(tr.stored)) {
			return nil, fmt.Errorf("no stored hash %d", x)
		}
		out[i] = tr.stored[x]
	}
	return out, nil
}

// add appends one leaf, by its record hash, as x/mod does.
func (tr *tlogTree) add(t *testing.T, n int64, leaf tlog.Hash) {
	t.Helper()
	h, err := tlog.StoredHashesForRecordHash(n, leaf, tr)
	if err != nil {
		t.Fatal(err)
	}
	tr.stored = append(tr.stored, h...)
}

func toTlog(p [][32]byte) []tlog.Hash {
	out := make([]tlog.Hash, len(p))
	for i := range p {
		out[i] = tlog.Hash(p[i])
	}
	return out
}

func fromTlog(p []tlog.Hash) [][32]byte {
	out := make([][32]byte, len(p))
	for i := range p {
		out[i] = [32]byte(p[i])
	}
	return out
}

// leavesOf writes n-1 entries to a real log (genesis is leaf 0, so the tree
// has n leaves) and returns the leaf hash of every stored record, from the
// bytes the store holds.
func leavesOf(t *testing.T, n int) [][32]byte {
	t.Helper()
	ctx := context.Background()
	signer, err := tnote.NewSigner(tallytest.TestSignerKey)
	if err != nil {
		t.Fatal(err)
	}
	store := tallytest.NewMemStore()
	log, err := tally.Open(ctx, store, signer)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < n; i++ {
		ev := tally.Event{ID: tally.EventID(fmt.Sprintf("e%d", i)), Actor: tally.System(), Action: "interop.merkle", Outcome: tally.OutcomeSuccess}
		ev.OccurredAt = ev.OccurredAt.AddDate(2026, 0, 0)
		if _, err := log.Append(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _ = log.Close() }) // closing the log closes the store
	var leaves [][32]byte
	for rec, err := range store.Records(ctx, 0) {
		if err != nil {
			t.Fatal(err)
		}
		leaves = append(leaves, tally.LeafHash(rec.Body))
	}
	if len(leaves) != n {
		t.Fatalf("the log holds %d records, want %d", len(leaves), n)
	}
	return leaves
}

const interopN = 70

func TestMerkleMatchesXMod(t *testing.T) {
	leaves := leavesOf(t, interopN)
	tr := &tlogTree{}
	roots := make([][32]byte, interopN+1)
	for n := 1; n <= interopN; n++ {
		tr.add(t, int64(n-1), tlog.Hash(leaves[n-1]))
		want, err := tlog.TreeHash(int64(n), tr)
		if err != nil {
			t.Fatal(err)
		}
		got, err := merkle.Root(leaves[:n])
		if err != nil {
			t.Fatal(err)
		}
		if got != [32]byte(want) {
			t.Fatalf("size %d: root %x, x/mod %x", n, got, [32]byte(want))
		}
		roots[n] = got
	}

	inclusions, consistencies := 0, 0
	for n := 1; n <= interopN; n++ {
		nn := int64(n)
		for i := range n {
			ours, err := merkle.InclusionProof(leaves[:n], uint64(i))
			if err != nil {
				t.Fatal(err)
			}
			theirs, err := tlog.ProveRecord(nn, int64(i), tr)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(toTlog(ours), theirs) {
				t.Fatalf("inclusion of %d in %d: tally %x, x/mod %x", i, n, ours, fromTlog(theirs))
			}
			if err := tlog.CheckRecord(toTlog(ours), nn, tlog.Hash(roots[n]), int64(i), tlog.Hash(leaves[i])); err != nil {
				t.Fatalf("x/mod refuses tally's inclusion proof of %d in %d: %v", i, n, err)
			}
			if err := merkle.VerifyInclusion(leaves[i], uint64(i), uint64(n), fromTlog(theirs), roots[n]); err != nil {
				t.Fatalf("tally refuses x/mod's inclusion proof of %d in %d: %v", i, n, err)
			}
			inclusions++
		}
		for m := 1; m <= n; m++ {
			ours, err := merkle.ConsistencyProof(leaves[:n], uint64(m))
			if err != nil {
				t.Fatal(err)
			}
			theirs, err := tlog.ProveTree(nn, int64(m), tr)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(toTlog(ours), theirs) {
				t.Fatalf("consistency %d -> %d: tally %x, x/mod %x", m, n, ours, fromTlog(theirs))
			}
			if err := tlog.CheckTree(toTlog(ours), nn, tlog.Hash(roots[n]), int64(m), tlog.Hash(roots[m])); err != nil {
				t.Fatalf("x/mod refuses tally's consistency proof %d -> %d: %v", m, n, err)
			}
			if err := merkle.VerifyConsistency(uint64(m), uint64(n), fromTlog(theirs), roots[m], roots[n]); err != nil {
				t.Fatalf("tally refuses x/mod's consistency proof %d -> %d: %v", m, n, err)
			}
			consistencies++
		}
	}
	if want := interopN * (interopN + 1) / 2; inclusions != want || consistencies != want {
		t.Fatalf("checked %d inclusion and %d consistency proofs, want %d of each", inclusions, consistencies, want)
	}
}

// testdata/vectors/merkle.json, which internal/merkle writes, checked against
// x/mod: its roots, its proofs, and its compact ranges, each range hash read
// as x/mod's stored hash of that aligned subtree.
func TestMerkleVectorsMatchXMod(t *testing.T) {
	data, err := os.ReadFile("../testdata/vectors/merkle.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		LeafHashesHex []string `json:"leaf_hashes_hex"`
		Roots         []struct {
			Size    int64  `json:"size"`
			RootHex string `json:"root_hex"`
		} `json:"roots"`
		Inclusion []struct {
			Index, Size int64
			ProofHex    []string `json:"proof_hex"`
		} `json:"inclusion"`
		Consistency []struct {
			From, To int64
			ProofHex []string `json:"proof_hex"`
		} `json:"consistency"`
		CompactRanges []struct {
			Start     int64    `json:"start"`
			HashesHex []string `json:"hashes_hex"`
		} `json:"compact_ranges"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	h := func(s string) tlog.Hash {
		b, err := hex.DecodeString(s)
		if err != nil || len(b) != 32 {
			t.Fatalf("hash %q", s)
		}
		return tlog.Hash(b)
	}
	hs := func(ss []string) []tlog.Hash {
		out := make([]tlog.Hash, len(ss))
		for i, s := range ss {
			out[i] = h(s)
		}
		return out
	}
	tr := &tlogTree{}
	for i, l := range v.LeafHashesHex {
		tr.add(t, int64(i), h(l))
	}
	n := int64(len(v.LeafHashesHex))
	checked := 0
	for _, r := range v.Roots {
		want, err := tlog.TreeHash(r.Size, tr)
		if err != nil || want != h(r.RootHex) {
			t.Fatalf("root of %d: %v", r.Size, err)
		}
		checked++
	}
	for _, p := range v.Inclusion {
		want, err := tlog.ProveRecord(p.Size, p.Index, tr)
		if err != nil || !slices.Equal(want, hs(p.ProofHex)) {
			t.Fatalf("inclusion of %d in %d: %v", p.Index, p.Size, err)
		}
		checked++
	}
	for _, p := range v.Consistency {
		want, err := tlog.ProveTree(p.To, p.From, tr)
		if err != nil || !slices.Equal(want, hs(p.ProofHex)) {
			t.Fatalf("consistency %d -> %d: %v", p.From, p.To, err)
		}
		checked++
	}
	for _, c := range v.CompactRanges {
		var want []tlog.Hash
		off := int64(0)
		for b := 62; b >= 0; b-- {
			if c.Start&(1<<b) == 0 {
				continue
			}
			x, err := tr.ReadHashes([]int64{tlog.StoredHashIndex(b, off>>b)})
			if err != nil {
				t.Fatal(err)
			}
			want = append(want, x[0])
			off += 1 << b
		}
		if !slices.Equal(want, hs(c.HashesHex)) {
			t.Fatalf("compact range below %d", c.Start)
		}
		checked++
	}
	if want := 4 * int(n); checked != want { // n roots, n inclusions, n consistencies, n ranges
		t.Fatalf("checked %d vector entries, want %d", checked, want)
	}
}
