package tally

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/JonasBorgesLM/tally/internal/note"
)

// This file is SPEC §7: Verify reads a Source in streaming, checks every
// record against the chain, and judges every checkpoint against what it read.
// Checkpoints read from an anchor and the heartbeat are #29; requiring full
// attestation is #28.

// ErrUntrustedStart means the checkpoint given to FromCheckpoint is not
// accepted under the trusted keys (SPEC §5.4). Verifying from a start that
// cannot be trusted is a misuse, so it is an error, not a violation.
var ErrUntrustedStart = errors.New("tally: the start checkpoint is not accepted")

// Verifiers is a set of trusted public keys (SPEC §5.3). Several keys allow a
// signing key to be rotated (RF-10).
type Verifiers struct {
	keys []*note.Verifier
}

// NewVerifiers parses signed-note verifier keys,
// `<name>+<key_id hex>+<base64(0x01 || public key)>` (SPEC §5.3).
func NewVerifiers(keys ...string) (Verifiers, error) {
	vs := Verifiers{keys: make([]*note.Verifier, 0, len(keys))}
	for i, k := range keys {
		v, err := note.NewVerifier(k)
		if err != nil {
			return Verifiers{}, fmt.Errorf("tally: verifier key %d: %w", i, err)
		}
		vs.keys = append(vs.keys, v)
	}
	return vs, nil
}

// Report is the result of Verify. Its Failures are the violations found; a
// log that verifies has none. Verify's error, not the Report, says that
// verification could not run (SPEC §7.1).
type Report struct {
	// Size is the number of leaves verified: with a violation, those before
	// it (ADR-0016).
	Size uint64
	// AttestedSize is the largest size matched by a trusted checkpoint, or 0.
	AttestedSize uint64
	// UnattestedEntries is Size - AttestedSize, counted in leaves: entries no
	// checkpoint covers, which a rewrite of the tail would leave undetected
	// even without the key (T-01).
	UnattestedEntries uint64
	// Failures lists every violation, the first record-level one included.
	Failures []Failure
}

// OK reports whether no violation of any kind was found (SPEC §7.1). It
// asserts nothing about entries past AttestedSize, and a trust that rests only
// on checkpoints read from the host being verified is worth no more than that
// host.
func (r *Report) OK() bool { return len(r.Failures) == 0 }

// Failure is one violation. Seq is the leaf it concerns: the record that broke
// a rule, the leaf a checkpoint disagrees with, or a checkpoint's size.
type Failure struct {
	Kind FailureKind
	Seq  uint64
	Note string
}

// VerifyOption configures Verify.
type VerifyOption func(*verifyConfig)

type verifyConfig struct {
	start       SignedCheckpoint
	requireFull bool
}

// FromCheckpoint verifies incrementally (RF-08): from cp's head on, trusting
// what cp attests below it. cp must be accepted under the trusted keys, or
// Verify returns an error: a start it cannot trust is a misuse, not a
// violation of the log.
func FromCheckpoint(cp SignedCheckpoint) VerifyOption {
	return func(c *verifyConfig) { c.start = cp }
}

// WithRequireFullyAttested makes an unattested tail a failure, UnattestedTail
// (RF-18, ADR-0018): every leaf read must be covered by a trusted checkpoint.
//
// Without it, an unattested tail is not a violation, and OK can be true while
// UnattestedEntries is not zero: the leaf hash is not stored, so the entries
// past the last checkpoint can be rewritten undetected, even without the key
// (T-01). A live log always has such a tail between checkpoints (RF-06), so
// the option suits the audit of a closed or quiesced log.
func WithRequireFullyAttested() VerifyOption {
	return func(c *verifyConfig) { c.requireFull = true }
}

// checkpoint is an accepted checkpoint (SPEC §5.4 step 5).
type checkpoint struct {
	origin string
	size   uint64
	head   [32]byte
	at     int64
	closed bool
	start  bool // the caller's start checkpoint
}

// readCheckpoint applies SPEC §5.4. It returns the accepted checkpoint, or the
// Failure that rejects it.
func readCheckpoint(cp SignedCheckpoint, keys Verifiers) (checkpoint, *Failure) {
	n, err := note.Open(cp, keys.keys)
	if err != nil {
		kind := MalformedRecord
		switch {
		case errors.Is(err, note.ErrNonCanonical):
			kind = NonCanonicalEncoding
		case errors.Is(err, note.ErrBadSignature):
			kind = BadSignature
		case errors.Is(err, note.ErrUnknownKey):
			kind = UnknownKey
		}
		return checkpoint{}, &Failure{Kind: kind, Note: "checkpoint: " + err.Error()}
	}
	c, f := parseCheckpointBody(n.Text)
	if f != nil {
		return checkpoint{}, f
	}
	for _, v := range n.SignedBy {
		if v.Name() != c.origin {
			return checkpoint{}, &Failure{Kind: MalformedRecord, Seq: c.size,
				Note: "checkpoint: origin differs from a signing key's name"}
		}
	}
	return c, nil
}

// parseCheckpointBody is SPEC §5.2, strictly.
func parseCheckpointBody(text []byte) (checkpoint, *Failure) {
	bad := func(why string) (checkpoint, *Failure) {
		return checkpoint{}, &Failure{Kind: MalformedRecord, Note: "checkpoint: " + why}
	}
	lines := strings.Split(string(bytes.TrimSuffix(text, []byte("\n"))), "\n")
	if len(lines) != 6 || !bytes.HasSuffix(text, []byte("\n")) {
		return bad("the body is not six lines")
	}
	if lines[1] != "tally-chain/v1" {
		return bad("line 2 is not tally-chain/v1")
	}
	sizeLine := lines[2]
	if sizeLine == "" || (len(sizeLine) > 1 && sizeLine[0] == '0') {
		return bad("size is not a decimal without leading zeros")
	}
	size, err := strconv.ParseUint(sizeLine, 10, 64)
	if err != nil || size == 0 || strconv.FormatUint(size, 10) != sizeLine {
		return bad("size is not a decimal of at least 1")
	}
	raw, err := base64.StdEncoding.DecodeString(lines[3])
	if err != nil || len(raw) != 32 {
		return bad("the head is not base64 of 32 bytes")
	}
	if base64.StdEncoding.EncodeToString(raw) != lines[3] {
		return checkpoint{}, &Failure{Kind: NonCanonicalEncoding, Seq: size, Note: "checkpoint: the head is not canonical base64"}
	}
	t, err := time.Parse(checkpointTimeLayout, lines[4])
	if err != nil || t.UTC().Format(checkpointTimeLayout) != lines[4] {
		return bad("recorded_at is not in SPEC §5.2's layout")
	}
	var closed bool
	switch lines[5] {
	case stateOpen:
	case stateClosed:
		closed = true
	default:
		return bad("state is neither open nor closed")
	}
	c := checkpoint{origin: lines[0], size: size, at: t.UnixNano(), closed: closed}
	copy(c.head[:], raw)
	return c, nil
}

// Verify verifies the log held by src (SPEC §7) and returns a Report of the
// violations it found. Its error means that verification could not run: an IO
// error reading src, an empty src, a start checkpoint that is not accepted, or
// accepted checkpoints naming more than one origin when genesis was not read.
// A caller must never read that error as "intact" (RS-04).
//
// Verify streams: its memory is constant in the number of records, plus the
// checkpoints, which it holds (RNF-04).
func Verify(ctx context.Context, src Source, keys Verifiers, opts ...VerifyOption) (*Report, error) {
	var cfg verifyConfig
	for _, o := range opts {
		o(&cfg)
	}
	rep := &Report{}

	// Step 1: read every checkpoint; set aside those not accepted.
	var cps []checkpoint
	var start *checkpoint
	if cfg.start != nil {
		c, f := readCheckpoint(cfg.start, keys)
		if f != nil {
			return nil, fmt.Errorf("%w: %v: %s", ErrUntrustedStart, f.Kind, f.Note)
		}
		c.start = true
		cps = append(cps, c)
		start = &cps[0]
	}
	for raw, err := range src.Checkpoints(ctx) {
		if err != nil {
			return nil, fmt.Errorf("tally: reading checkpoints: %w", err)
		}
		c, f := readCheckpoint(raw, keys)
		if f != nil {
			rep.Failures = append(rep.Failures, *f)
			continue
		}
		cps = append(cps, c)
	}

	// Step 2: where reading starts. Incremental: at leaf s-1 of the start.
	from := uint64(0)
	if start != nil {
		from = start.size - 1
	}

	// Steps 3 and 4: read the records in streaming, and compare checkpoints
	// with the leaves as they pass.
	slices.SortStableFunc(cps, func(a, b checkpoint) int {
		if a.size != b.size {
			return cmpU64(a.size, b.size)
		}
		return cmpI64(a.at, b.at)
	})
	matched := make([]bool, len(cps))
	var (
		chain    chainState
		first    = true
		f        uint64 // first_seq of the first record read
		boundary [32]byte
		broke    *violation // the first record-level violation
		read     bool
	)
	next := 0 // the first checkpoint not yet reached by the stream
	for r, err := range src.Records(ctx, from) {
		if err != nil {
			return nil, fmt.Errorf("tally: reading records: %w", err)
		}
		read = true
		if first {
			first = false
			f = r.Seq
			if f > 0 {
				// The first record read stands in for its own predecessor,
				// as a segment header does (SPEC §7 step 4).
				e, ok := startEntry(r.Body)
				if !ok {
					broke = &violation{kind: MalformedRecord, seq: f, err: errors.New("the first record read is not a valid entry")}
					break
				}
				chain = chainState{size: f, logID: e.logID, prevLeaf: e.prevHash, prevTime: math.MinInt64}
				boundary = e.prevHash
			}
			for next < len(cps) && cps[next].size < f+1 {
				next++ // below what is read: judged after the stream
			}
		}
		if r.Seq != chain.size {
			broke = &violation{kind: MalformedRecord, seq: chain.size,
				err: fmt.Errorf("the source returned seq %d at leaf %d", r.Seq, chain.size)}
			break
		}
		if _, v := chain.add(r.Body); v != nil {
			broke = v
			break
		}
		for next < len(cps) && cps[next].size == chain.size {
			c := cps[next]
			if c.origin == chain.origin || chain.origin == "" {
				switch {
				case c.head != chain.prevLeaf:
					rep.Failures = append(rep.Failures, Failure{Kind: CheckpointMismatch, Seq: c.size - 1,
						Note: "a checkpoint's head differs from the stored leaf"})
				case c.at < chain.prevTime:
					rep.Failures = append(rep.Failures, Failure{Kind: TimeRegression, Seq: c.size - 1,
						Note: "a checkpoint's recorded_at is before its head leaf's"})
				default:
					matched[next] = true
				}
			}
			next++
		}
	}
	if !read {
		return nil, errors.New("tally: the source holds no record")
	}
	rep.Size = chain.size
	if broke != nil {
		rep.Failures = append(rep.Failures, Failure{Kind: broke.kind, Seq: broke.seq, Note: broke.err.Error()})
	}

	// Step 3: the log's origin, from genesis or, without it, the checkpoints.
	origin := chain.origin
	if origin == "" {
		for _, c := range cps {
			if origin != "" && c.origin != origin {
				return nil, errors.New("tally: genesis was not read and the accepted checkpoints name more than one origin")
			}
			origin = c.origin
		}
	}

	// Step 5, for the checkpoints the stream did not reach.
	for i, c := range cps {
		switch {
		case c.origin != origin:
			rep.Failures = append(rep.Failures, Failure{Kind: CheckpointMismatch, Seq: c.size, Note: "a checkpoint names another origin"})
			matched[i] = false
		case c.size == f && f > 0:
			if c.head == boundary {
				matched[i] = true
			} else {
				rep.Failures = append(rep.Failures, Failure{Kind: CheckpointMismatch, Seq: c.size - 1,
					Note: "a checkpoint's head differs from the first record's prev_hash"})
			}
		case c.size > rep.Size && broke == nil:
			rep.Failures = append(rep.Failures, Failure{Kind: TruncatedBelowCheckpoint, Seq: rep.Size,
				Note: fmt.Sprintf("a checkpoint covers %d leaves, the log holds %d", c.size, rep.Size)})
		}
	}

	// Step 6: order. Two checkpoints of one size with different heads are a
	// fork; recorded_at never decreases along increasing size.
	for i := 1; i < len(cps); i++ {
		a, b := cps[i-1], cps[i]
		if a.origin != origin || b.origin != origin {
			continue
		}
		if a.size == b.size && a.head != b.head {
			rep.Failures = append(rep.Failures, Failure{Kind: ForkDetected, Seq: a.size, Note: "two checkpoints of one size with different heads"})
		}
		if b.at < a.at {
			rep.Failures = append(rep.Failures, Failure{Kind: TimeRegression, Seq: b.size, Note: "a checkpoint of larger size claims an earlier time"})
		}
	}

	// Step 7: a start above leaf 0 needs a matched checkpoint at or above it.
	if f > 0 {
		covered := false
		for i, c := range cps {
			if matched[i] && c.size >= f {
				covered = true
			}
		}
		if !covered {
			rep.Failures = append(rep.Failures, Failure{Kind: PrunedWithoutTrustedCheckpoint, Seq: f,
				Note: "the log starts above leaf 0 and no trusted checkpoint covers the start"})
		}
	}

	// Step 9.
	for i, c := range cps {
		if matched[i] && c.size > rep.AttestedSize {
			rep.AttestedSize = c.size
		}
	}
	rep.UnattestedEntries = rep.Size - rep.AttestedSize

	// Step 10: full attestation, if required (ADR-0018).
	if cfg.requireFull && rep.UnattestedEntries > 0 {
		rep.Failures = append(rep.Failures, Failure{Kind: UnattestedTail, Seq: rep.AttestedSize,
			Note: fmt.Sprintf("%d leaves past the last trusted checkpoint", rep.UnattestedEntries)})
	}
	return rep, nil
}

// startEntry decodes the first record of a read that starts above leaf 0,
// for its log_id and prev_hash. The chain rules then check it like any other.
func startEntry(body []byte) (*entry, bool) {
	r, err := decodeStrict(body)
	if err != nil {
		return nil, false
	}
	e, ok := r.(*entry)
	return e, ok
}

func cmpU64(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func cmpI64(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
