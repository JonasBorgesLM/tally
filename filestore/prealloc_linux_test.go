//go:build linux

package filestore

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// On Linux, a new segment has its blocks reserved up to the segment size and
// keeps its length: a reader still finds it ending at its last frame (RNF-10).
//
// Seen failing with the Preallocate call removed from startSegment.
func TestPreallocationReservesBlocksAndKeepsTheLength(t *testing.T) {
	const size = 1 << 20
	dir := logDir(t)
	s := mustOpen(t, dir, WithPreallocation(), WithSegmentSize(size))
	if err := s.AppendBatch(t.Context(), records(vectorBodies(t), 0)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(dir, segmentName(0))
	fi, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("no Stat_t")
	}
	if fi.Size() >= size {
		t.Errorf("length %d: preallocation changed the file's length", fi.Size())
	}
	if allocated := st.Blocks * 512; allocated < size {
		t.Errorf("%d bytes allocated, want at least %d", allocated, size)
	}
	// The log reopens without recovering anything.
	s = mustOpen(t, dir, WithPreallocation(), WithSegmentSize(size))
	defer func() { _ = s.Close() }()
	if s.Recovered() != 0 {
		t.Errorf("reopening recovered %d bytes", s.Recovered())
	}
}
