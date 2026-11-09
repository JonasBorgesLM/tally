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

// verifyFrames verifies a log held as concatenated frames from leaf 0. It
// stops at the first violation (ADR-0016) and returns it with the size of the
// verified prefix. head, if given, is compared with the leaf at size - 1, or
// reports a truncation when the log is shorter and was read without violation.
func verifyFrames(log []byte, head *trustedHead) (uint64, *violation) {
	var (
		size     uint64 // leaves verified so far
		logID    [16]byte
		prevLeaf [32]byte
		prevTime int64
		headSeen bool
	)
	for rest := log; len(rest) > 0 || size == 0; {
		body, next, err := readFrame(rest)
		if err != nil {
			return size, &violation{kind: kindMalformedRecord, seq: size, err: err}
		}
		rest = next

		r, err := decodeStrict(body)
		if err != nil {
			return size, &violation{kind: decodeKind(err), seq: size, err: err}
		}
		if kind, err := checkChain(r, size, logID, prevLeaf, prevTime); err != nil {
			return size, &violation{kind: kind, seq: size, err: err}
		}
		if err := validate(r); err != nil {
			return size, &violation{kind: kindMalformedRecord, seq: size, err: err}
		}

		switch r := r.(type) {
		case *genesis:
			logID, prevTime = r.logID, r.createdAt
		case *entry:
			prevTime = r.recordedAt
		}
		prevLeaf = leafHash(body)
		size++

		if head != nil && head.size == size {
			if prevLeaf != head.hash {
				return size, &violation{kind: kindCheckpointMismatch, seq: size - 1,
					err: errors.New("the trusted head differs from the stored leaf")}
			}
			headSeen = true
		}
	}
	if head != nil && !headSeen && head.size > size {
		return size, &violation{kind: kindTruncatedBelowCheckpoint, seq: size,
			err: fmt.Errorf("the trusted head covers %d leaves, the log holds %d", head.size, size)}
	}
	return size, nil
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
