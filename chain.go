package tally

import (
	"errors"
	"fmt"
)

// This file is the core of SPEC §7 step 4, and the head comparison of step 5,
// over one framed log that starts at leaf 0. Verify (#27) adds segments, the
// incremental and pruned starts, signed checkpoints and the Report around it.

// FailureKind is a violation kind of SPEC §7.2 and REQUIREMENTS §5.1. Each
// check of the verification algorithm reports exactly one.
type FailureKind uint8

// The violation kinds. SPEC §7.2 says, for each, the check that reports it.
const (
	MalformedRecord FailureKind = iota + 1
	NonCanonicalEncoding
	PrevHashMismatch
	SeqGap
	SeqRegression
	TimeRegression
	CheckpointMismatch
	TruncatedBelowCheckpoint
	BadSignature
	UnknownKey
	ForkDetected
	HeartbeatGap
	PrunedWithoutTrustedCheckpoint
	UnattestedTail
)

func (k FailureKind) String() string {
	switch k {
	case MalformedRecord:
		return "MalformedRecord"
	case NonCanonicalEncoding:
		return "NonCanonicalEncoding"
	case PrevHashMismatch:
		return "PrevHashMismatch"
	case SeqGap:
		return "SeqGap"
	case SeqRegression:
		return "SeqRegression"
	case TimeRegression:
		return "TimeRegression"
	case CheckpointMismatch:
		return "CheckpointMismatch"
	case TruncatedBelowCheckpoint:
		return "TruncatedBelowCheckpoint"
	case BadSignature:
		return "BadSignature"
	case UnknownKey:
		return "UnknownKey"
	case ForkDetected:
		return "ForkDetected"
	case HeartbeatGap:
		return "HeartbeatGap"
	case PrunedWithoutTrustedCheckpoint:
		return "PrunedWithoutTrustedCheckpoint"
	case UnattestedTail:
		return "UnattestedTail"
	default:
		return fmt.Sprintf("FailureKind(%d)", uint8(k))
	}
}

// violation is the first rule a log breaks. seq is the leaf index it concerns:
// the record that broke a rule, the leaf a head disagrees with, or the first
// leaf missing below a head.
type violation struct {
	kind FailureKind
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
		return nil, &violation{kind: MalformedRecord, seq: c.size, err: err}
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
			return c.size, &violation{kind: MalformedRecord, seq: c.size, err: err}
		}
		rest = next
		if _, v := c.add(body); v != nil {
			return c.size, v
		}
		if head != nil && head.size == c.size {
			if c.prevLeaf != head.hash {
				return c.size, &violation{kind: CheckpointMismatch, seq: c.size - 1,
					err: errors.New("the trusted head differs from the stored leaf")}
			}
			headSeen = true
		}
	}
	if head != nil && !headSeen && head.size > c.size {
		return c.size, &violation{kind: TruncatedBelowCheckpoint, seq: c.size,
			err: fmt.Errorf("the trusted head covers %d leaves, the log holds %d", head.size, c.size)}
	}
	return c.size, nil
}

// decodeKind maps a strict-decoding failure to its §7.2 kind.
func decodeKind(err error) FailureKind {
	if errors.Is(err, errNonCanonical) {
		return NonCanonicalEncoding
	}
	return MalformedRecord
}

// checkChain applies the rules of SPEC §2 that relate r to the record before
// it, in the order §2.2 lists them: log_id, seq, recorded_at, prev_hash. The
// record-local rules run after it (§7 step 4).
func checkChain(r record, index uint64, logID [16]byte, prevLeaf [32]byte, prevTime int64) (FailureKind, error) {
	switch r := r.(type) {
	case *genesis:
		if index != 0 {
			return MalformedRecord, fmt.Errorf("%w: a genesis at leaf %d", errMalformed, index)
		}
	case *entry:
		switch {
		case index == 0:
			return MalformedRecord, fmt.Errorf("%w: the log does not start with a genesis", errMalformed)
		case r.logID != logID:
			return MalformedRecord, fmt.Errorf("%w: log_id differs from the log's", errMalformed)
		case r.seq > index:
			return SeqGap, fmt.Errorf("seq %d, want %d", r.seq, index)
		case r.seq < index:
			return SeqRegression, fmt.Errorf("seq %d, want %d", r.seq, index)
		case r.recordedAt < prevTime:
			return TimeRegression, errors.New("recorded_at is before the previous record's")
		case r.prevHash != prevLeaf:
			return PrevHashMismatch, errors.New("prev_hash differs from the previous leaf hash")
		}
	}
	return 0, nil
}
