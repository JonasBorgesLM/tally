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
