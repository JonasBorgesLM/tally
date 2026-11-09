package tally

// Hooks for the external tests in package tally_test. Compiled only into
// tests.

// LeafHashForTest is leafHash.
func LeafHashForTest(body []byte) [32]byte { return leafHash(body) }

// VerifyBodiesForTest frames bodies and verifies them as a log from leaf 0,
// with a trusted head over the last one.
func VerifyBodiesForTest(bodies [][]byte, last [32]byte) (uint64, error) {
	var log []byte
	for _, b := range bodies {
		log = appendFrame(log, b)
	}
	size, v := verifyFrames(log, &trustedHead{size: uint64(len(bodies)), hash: last})
	if v != nil {
		return size, v
	}
	return size, nil
}

// QueuedForTest is how many Appends wait in the writer's queue.
func (l *Log) QueuedForTest() int { return len(l.reqs) }
