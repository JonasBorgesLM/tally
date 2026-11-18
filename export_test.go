package tally

// TreeRootForTest is the Merkle root the Log keeps over its leaves, and false
// when the tree is unknown (#60). It reads the writer's state: call it only
// after Close, once the writer has stopped.
func TreeRootForTest(l *Log) ([32]byte, bool) {
	if l.head.tree == nil {
		return [32]byte{}, false
	}
	r, err := l.head.tree.Root()
	return r, err == nil
}
