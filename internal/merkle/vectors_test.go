package merkle

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"testing"
)

var writeVectors = flag.Bool("write-vectors", false, "regenerate testdata/vectors/merkle.json (review the diff before committing)")

const (
	recordVectorsPath = "../../testdata/vectors/records.json"
	merkleVectorsPath = "../../testdata/vectors/merkle.json"
)

type merkleVectorFile struct {
	Comment       string              `json:"comment"`
	LeafHashesHex []string            `json:"leaf_hashes_hex"`
	Roots         []merkleRoot        `json:"roots"`
	Inclusion     []merkleInclusion   `json:"inclusion"`
	Consistency   []merkleConsistency `json:"consistency"`
	CompactRanges []merkleRange       `json:"compact_ranges"`
}

type merkleRoot struct {
	Size    uint64 `json:"size"`
	RootHex string `json:"root_hex"`
}

type merkleInclusion struct {
	Index    uint64   `json:"index"`
	Size     uint64   `json:"size"`
	ProofHex []string `json:"proof_hex"`
}

type merkleConsistency struct {
	From     uint64   `json:"from"`
	To       uint64   `json:"to"`
	ProofHex []string `json:"proof_hex"`
}

type merkleRange struct {
	Start     uint64   `json:"start"`
	HashesHex []string `json:"hashes_hex"`
}

func hexes(p [][32]byte) []string {
	out := make([]string, len(p))
	for i := range p {
		out[i] = hex.EncodeToString(p[i][:])
	}
	return out
}

// The published Merkle vector (SPEC §3.6, §8), over the five leaves of
// records.json: every root, every inclusion and consistency proof in the
// tree of five, and the compact range below every start. Each is also
// checked against golang.org/x/mod/sumdb/tlog in interop.
func TestMerkleVectors(t *testing.T) {
	var recs struct {
		Records []struct {
			LeafHashHex string `json:"leaf_hash_hex"`
		} `json:"records"`
	}
	data, err := os.ReadFile(recordVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &recs); err != nil {
		t.Fatal(err)
	}
	leaves := make([][32]byte, 0, len(recs.Records))
	for _, r := range recs.Records {
		b, herr := hex.DecodeString(r.LeafHashHex)
		if herr != nil || len(b) != 32 {
			t.Fatalf("leaf hash %q", r.LeafHashHex)
		}
		leaves = append(leaves, [32]byte(b))
	}
	if len(leaves) != 5 {
		t.Fatalf("records.json has %d leaves, want 5", len(leaves))
	}
	tree, err := NewTree(0, nil, leaves)
	if err != nil {
		t.Fatal(err)
	}
	n := tree.Size()

	got := merkleVectorFile{
		Comment: "tally SPEC v1 Merkle tree (RFC 6962) over the leaves of records.json: every root, every proof " +
			"in the tree of 5, and the compact range below every start (SPEC §3.6). Hashes are hex. See README.md.",
		LeafHashesHex: hexes(leaves),
	}
	for size := uint64(1); size <= n; size++ {
		r, _ := tree.Root(size)
		got.Roots = append(got.Roots, merkleRoot{size, hex.EncodeToString(r[:])})
	}
	for i := range n {
		p, _ := tree.InclusionProof(i, n)
		got.Inclusion = append(got.Inclusion, merkleInclusion{i, n, hexes(p)})
	}
	for m := uint64(1); m <= n; m++ {
		p, _ := tree.ConsistencyProof(m, n)
		got.Consistency = append(got.Consistency, merkleConsistency{m, n, hexes(p)})
	}
	for s := uint64(1); s <= n; s++ {
		p, _ := tree.CompactRange(s)
		got.CompactRanges = append(got.CompactRanges, merkleRange{s, hexes(p)})
	}
	out, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')
	if *writeVectors {
		if err = os.WriteFile(merkleVectorsPath, out, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(merkleVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, want) {
		t.Fatal("merkle.json differs from what the tree computes; run with -write-vectors and review the diff")
	}
}
