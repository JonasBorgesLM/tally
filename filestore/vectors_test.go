package filestore

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var writeVectors = flag.Bool("write-vectors", false, "regenerate testdata/vectors/segments.json (review the diff before committing)")

const segmentVectorsPath = "../testdata/vectors/segments.json"

type segmentVectorFile struct {
	Comment string          `json:"comment"`
	Files   []segmentVector `json:"files"`
}

type segmentVector struct {
	Name string `json:"name"`
	Hex  string `json:"hex"`
}

// The published segment vector (SPEC §3, §8): records.json and the checkpoint
// of checkpoints.json as a file store writes them, rotating at the
// checkpoint. An independent implementation reading these files must find
// the same records and checkpoint; one writing them must produce the same
// bytes.
func TestSegmentVectors(t *testing.T) {
	dir := writeVectorLog(t)
	var got segmentVectorFile
	got.Comment = "tally SPEC v1 segment files: records.json in segment 0, the checkpoint of checkpoints.json, " +
		"and the header-only segment 5 a writer starts after it (ADR-0019). Each file is hex. See README.md."
	for _, name := range []string{segmentName(0), segmentName(5), checkpointsName} {
		b, err := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- a test's own file
		if err != nil {
			t.Fatal(err)
		}
		got.Files = append(got.Files, segmentVector{Name: name, Hex: hex.EncodeToString(b)})
	}
	out, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')

	if *writeVectors {
		if werr := os.WriteFile(segmentVectorsPath, out, 0o600); werr != nil {
			t.Fatal(werr)
		}
		return
	}
	want, err := os.ReadFile(segmentVectorsPath)
	if err != nil {
		t.Fatalf("%v (run with -write-vectors once, and review the result)", err)
	}
	if !bytes.Equal(out, want) {
		t.Fatalf("the files a filestore writes differ from %s", segmentVectorsPath)
	}
}

const pruneRangeVectorsPath = "../testdata/vectors/pruned-range.json"

// The published pruned-range vector (SPEC §3.6): the file a prune that keeps
// records from 3 on and from 5 on writes, over the leaves of records.json,
// from the compact ranges in merkle.json. Each decodes back to its range.
func TestPruneRangeVectors(t *testing.T) {
	var m struct {
		CompactRanges []struct {
			Start     uint64   `json:"start"`
			HashesHex []string `json:"hashes_hex"`
		} `json:"compact_ranges"`
	}
	data, err := os.ReadFile("../testdata/vectors/merkle.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	type file struct {
		Start uint64 `json:"start"`
		Text  string `json:"text"`
	}
	got := struct {
		Comment string `json:"comment"`
		Files   []file `json:"files"`
	}{Comment: "tally SPEC v1 pruned.range files (SPEC §3.6) over records.json, for the compact ranges of merkle.json. See README.md."}
	for _, c := range m.CompactRanges {
		if c.Start != 3 && c.Start != 5 {
			continue
		}
		prefix := make([][32]byte, 0, len(c.HashesHex))
		for _, h := range c.HashesHex {
			b, herr := hex.DecodeString(h)
			if herr != nil || len(b) != 32 {
				t.Fatalf("hash %q", h)
			}
			prefix = append(prefix, [32]byte(b))
		}
		text := encodePruneRange(c.Start, prefix)
		if start, back, derr := decodePruneRange(text); derr != nil || start != c.Start || len(back) != len(prefix) {
			t.Fatalf("start %d does not round-trip: %v", c.Start, derr)
		}
		got.Files = append(got.Files, file{c.Start, string(text)})
	}
	if len(got.Files) != 2 {
		t.Fatalf("wrote %d files, want 2", len(got.Files))
	}
	out, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')
	if *writeVectors {
		if err = os.WriteFile(pruneRangeVectorsPath, out, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(pruneRangeVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, want) {
		t.Fatal("pruned-range.json differs; run with -write-vectors and review the diff")
	}
}
