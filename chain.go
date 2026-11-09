package tally

import (
	"errors"
	"fmt"
)

// This file is the core of SPEC §7 step 4, and the head comparison of step 5,
// over one framed log that starts at leaf 0. Verify (#27) adds segments, the
// incremental and pruned starts, signed checkpoints and the Report around it.

// failureKind is a violation kind of SPEC §7.2. It becomes the public
// FailureKind when Report does (#28); until then only the kinds this file
// reports exist.
type failureKind uint8

const (
	kindMalformedRecord failureKind = iota + 1
	kindNonCanonicalEncoding
	kindPrevHashMismatch
	kindSeqGap
	kindSeqRegression
	kindTimeRegression
	kindCheckpointMismatch
	kindTruncatedBelowCheckpoint
)

func (k failureKind) String() string {
	switch k {
	case kindMalformedRecord:
		return "MalformedRecord"
	case kindNonCanonicalEncoding:
		return "NonCanonicalEncoding"
	case kindPrevHashMismatch:
		return "PrevHashMismatch"
	case kindSeqGap:
		return "SeqGap"
	case kindSeqRegression:
		return "SeqRegression"
	case kindTimeRegression:
		return "TimeRegression"
	case kindCheckpointMismatch:
		return "CheckpointMismatch"
	case kindTruncatedBelowCheckpoint:
		return "TruncatedBelowCheckpoint"
	default:
		return fmt.Sprintf("failureKind(%d)", uint8(k))
	}
}

// violation is the first rule a log breaks. seq is the leaf index it concerns:
// the record that broke a rule, the leaf a head disagrees with, or the first
// leaf missing below a head.
type violation struct {
	kind failureKind
	seq  uint64
	err  error
}

func (v *violation) Error() string {
	return fmt.Sprintf("%v at leaf %d: %v", v.kind, v.seq, v.err)
}

// trustedHead is what a checkpoint asserts once its signature is accepted: the
// log had size leaves, and the last one hashed to hash.
type trustedHead struct {
	size uint64
	hash [32]byte
}

// chainState is the running state of SPEC §7 step 4 over a log read from leaf
// 0: what the next record must agree with. Verify and Open share it, so the
// writer reopens a log by exactly the verifier's rules.
type chainState struct {
	size     uint64 // leaves accepted so far
	logID    [16]byte
	origin   string
	prevLeaf [32]byte
	prevTime int64
}

// add checks body as the next leaf and, if it is valid, advances the state and
// returns the decoded record. On a violation the state is unchanged.
func (c *chainState) add(body []byte) (record, *violation) {
	r, err := decodeStrict(body)
	if err != nil {
		return nil, &violation{kind: decodeKind(err), seq: c.size, err: err}
	}
	if kind, err := checkChain(r, c.size, c.logID, c.prevLeaf, c.prevTime); err != nil {
		return nil, &violation{kind: kind, seq: c.size, err: err}
	}
	if err := validate(r); err != nil {
		return nil, &violation{kind: kindMalformedRecord, seq: c.size, err: err}
	}
	switch r := r.(type) {
	case *genesis:
		c.logID, c.origin, c.prevTime = r.logID, r.origin, r.createdAt
	case *entry:
		c.prevTime = r.recordedAt
	}
	c.prevLeaf = leafHash(body)
	c.size++
	return r, nil
}

// verifyFrames verifies a log held as concatenated frames from leaf 0. It
// stops at the first violation (ADR-0016) and returns it with the size of the
// verified prefix. head, if given, is compared with the leaf at size - 1, or
// reports a truncation when the log is shorter and was read without violation.
func verifyFrames(log []byte, head *trustedHead) (uint64, *violation) {
	var (
		c        chainState
		headSeen bool
	)
	for rest := log; len(rest) > 0 || c.size == 0; {
		body, next, err := readFrame(rest)
		if err != nil {
			return c.size, &violation{kind: kindMalformedRecord, seq: c.size, err: err}
		}
		rest = next
		if _, v := c.add(body); v != nil {
			return c.size, v
		}
		if head != nil && head.size == c.size {
			if c.prevLeaf != head.hash {
				return c.size, &violation{kind: kindCheckpointMismatch, seq: c.size - 1,
					err: errors.New("the trusted head differs from the stored leaf")}
			}
			headSeen = true
		}
	}
	if head != nil && !headSeen && head.size > c.size {
		return c.size, &violation{kind: kindTruncatedBelowCheckpoint, seq: c.size,
			err: fmt.Errorf("the trusted head covers %d leaves, the log holds %d", head.size, c.size)}
	}
	return c.size, nil
}

// decodeKind maps a strict-decoding failure to its §7.2 kind.
func decodeKind(err error) failureKind {
	if errors.Is(err, errNonCanonical) {
		return kindNonCanonicalEncoding
	}
	return kindMalformedRecord
}

// checkChain applies the rules of SPEC §2 that relate r to the record before
// it, in the order §2.2 lists them: log_id, seq, recorded_at, prev_hash. The
// record-local rules run after it (§7 step 4).
func checkChain(r record, index uint64, logID [16]byte, prevLeaf [32]byte, prevTime int64) (failureKind, error) {
	switch r := r.(type) {
	case *genesis:
		if index != 0 {
			return kindMalformedRecord, fmt.Errorf("%w: a genesis at leaf %d", errMalformed, index)
		}
	case *entry:
		switch {
		case index == 0:
			return kindMalformedRecord, fmt.Errorf("%w: the log does not start with a genesis", errMalformed)
		case r.logID != logID:
			return kindMalformedRecord, fmt.Errorf("%w: log_id differs from the log's", errMalformed)
		case r.seq > index:
			return kindSeqGap, fmt.Errorf("seq %d, want %d", r.seq, index)
		case r.seq < index:
			return kindSeqRegression, fmt.Errorf("seq %d, want %d", r.seq, index)
		case r.recordedAt < prevTime:
			return kindTimeRegression, errors.New("recorded_at is before the previous record's")
		case r.prevHash != prevLeaf:
			return kindPrevHashMismatch, errors.New("prev_hash differs from the previous leaf hash")
		}
	}
	return 0, nil
}
