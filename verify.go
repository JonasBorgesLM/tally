package tally

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"iter"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/JonasBorgesLM/tally/internal/merkle"
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
	anchor      AnchorReader
	heartbeat   *heartbeat
}

// heartbeat is WithHeartbeat's input.
type heartbeat struct {
	interval, tolerance time.Duration
	now                 time.Time
}

// WithAnchor adds the checkpoints read from an anchor (RF-09). They are the
// ones that matter: a host attacker can rewrite every checkpoint it stores,
// but not one it has already published to an anchor it cannot alter (RS-17).
// An anchored checkpoint that disagrees with the log is ForkDetected rather
// than CheckpointMismatch: the host showed the anchor another history.
func WithAnchor(a AnchorReader) VerifyOption {
	return func(c *verifyConfig) { c.anchor = a }
}

// WithHeartbeat checks the anchored checkpoints for gaps (SPEC §7 step 8). A
// gap above interval + tolerance between two consecutive anchored
// checkpoints, or between the last one and now, is HeartbeatGap, unless the
// earlier one was signed by a clean Close (state "closed"). now comes from the
// caller: the log's own clock is what is in question. It requires WithAnchor.
//
// A gap is evidence that the signer stopped, or that its checkpoints did not
// reach the anchor. It is never evidence of which events are missing, nor its
// absence of completeness: a host can keep signing heartbeats over a log it
// is dropping entries from (T-15). The times are the signer's own claims
// (ADR-0006); a gap is credible only if the anchor side records arrival.
func WithHeartbeat(interval, tolerance time.Duration, now time.Time) VerifyOption {
	return func(c *verifyConfig) {
		c.heartbeat = &heartbeat{interval: interval, tolerance: tolerance, now: now}
	}
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
	// head, at and closed are set when hasHead: a tally-chain/v1 checkpoint
	// or a tally-heartbeat/v1 note. A tlog-checkpoint has neither (SPEC §5.2).
	head    [32]byte
	at      int64
	closed  bool
	hasHead bool
	// root is set when hasRoot: a tlog-checkpoint or a heartbeat note.
	root     [32]byte
	hasRoot  bool
	start    bool // the caller's start checkpoint
	anchored bool // read from an anchor
}

// mismatchKind is SPEC §7.2's kind for a checkpoint whose head disagrees with
// the log: a fork when the checkpoint came from an anchor.
func mismatchKind(c checkpoint) FailureKind {
	if c.anchored {
		return ForkDetected
	}
	return CheckpointMismatch
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

// VerifyCheckpoint applies SPEC §5.4 to cp alone: it opens the signed note
// under keys and parses its body strictly. A nil error means cp is accepted.
// It says nothing about any log: whether cp agrees with one is Verify's
// question (FromCheckpoint, WithAnchor).
func VerifyCheckpoint(cp SignedCheckpoint, keys Verifiers) error {
	if _, f := readCheckpoint(cp, keys); f != nil {
		return fmt.Errorf("tally: checkpoint not accepted: %v: %s", f.Kind, f.Note)
	}
	return nil
}

// The second line of each tally body (SPEC §5.2). A tlog-checkpoint has the
// size there instead, so no body is ever read as another.
const (
	bodyChainV1     = "tally-chain/v1"
	bodyHeartbeatV1 = "tally-heartbeat/v1"
)

// parseCheckpointBody is SPEC §5.2, strictly: a tally-chain/v1 checkpoint
// (v0.1), a tally-heartbeat/v1 note, or a tlog-checkpoint (v0.2, #60).
func parseCheckpointBody(text []byte) (checkpoint, *Failure) {
	bad := func(why string) (checkpoint, *Failure) {
		return checkpoint{}, &Failure{Kind: MalformedRecord, Note: "checkpoint: " + why}
	}
	if !bytes.HasSuffix(text, []byte("\n")) {
		return bad("the body does not end in a newline")
	}
	lines := strings.Split(string(bytes.TrimSuffix(text, []byte("\n"))), "\n")
	if len(lines) < 3 {
		return bad("the body has fewer than three lines")
	}
	var c checkpoint
	var f *Failure
	switch lines[1] {
	case bodyChainV1:
		if len(lines) != 6 {
			return bad("a tally-chain/v1 body is not six lines")
		}
		c.origin = lines[0]
		if c.size, f = parseSize(lines[2]); f != nil {
			return checkpoint{}, f
		}
		if c.head, f = parseHash(lines[3], c.size, "the head"); f != nil {
			return checkpoint{}, f
		}
		if c.at, c.closed, f = parseTimeState(lines[4], lines[5]); f != nil {
			return checkpoint{}, f
		}
		c.hasHead = true
	case bodyHeartbeatV1:
		if len(lines) != 7 {
			return bad("a tally-heartbeat/v1 body is not seven lines")
		}
		c.origin = lines[0]
		if c.size, f = parseSize(lines[2]); f != nil {
			return checkpoint{}, f
		}
		if c.head, f = parseHash(lines[3], c.size, "the head"); f != nil {
			return checkpoint{}, f
		}
		if c.root, f = parseHash(lines[4], c.size, "the root"); f != nil {
			return checkpoint{}, f
		}
		if c.at, c.closed, f = parseTimeState(lines[5], lines[6]); f != nil {
			return checkpoint{}, f
		}
		c.hasHead, c.hasRoot = true, true
	default:
		// A tlog-checkpoint: origin, size, root. tally writes no extension
		// lines and accepts none (ADR-0006's amendment).
		if len(lines) != 3 {
			return bad("neither a tally body nor a three-line tlog-checkpoint")
		}
		c.origin = lines[0]
		if c.size, f = parseSize(lines[1]); f != nil {
			return checkpoint{}, f
		}
		if c.root, f = parseHash(lines[2], c.size, "the root"); f != nil {
			return checkpoint{}, f
		}
		c.hasRoot = true
	}
	return c, nil
}

// parseSize is a size line: a decimal of at least 1, no leading zeros, that
// fits in a uint64.
func parseSize(line string) (uint64, *Failure) {
	bad := &Failure{Kind: MalformedRecord, Note: "checkpoint: size is not a decimal of at least 1 without leading zeros"}
	if line == "" || (len(line) > 1 && line[0] == '0') {
		return 0, bad
	}
	size, err := strconv.ParseUint(line, 10, 64)
	if err != nil || size == 0 || strconv.FormatUint(size, 10) != line {
		return 0, bad
	}
	return size, nil
}

// parseHash is a hash line: canonical, padded, standard base64 of 32 bytes.
func parseHash(line string, size uint64, what string) ([32]byte, *Failure) {
	var h [32]byte
	raw, err := base64.StdEncoding.DecodeString(line)
	if err != nil || len(raw) != 32 {
		return h, &Failure{Kind: MalformedRecord, Note: "checkpoint: " + what + " is not base64 of 32 bytes"}
	}
	if base64.StdEncoding.EncodeToString(raw) != line {
		return h, &Failure{Kind: NonCanonicalEncoding, Seq: size, Note: "checkpoint: " + what + " is not canonical base64"}
	}
	copy(h[:], raw)
	return h, nil
}

// parseTimeState is the recorded_at and state lines.
func parseTimeState(timeLine, stateLine string) (at int64, closed bool, fail *Failure) {
	bad := func(why string) (int64, bool, *Failure) {
		return 0, false, &Failure{Kind: MalformedRecord, Note: "checkpoint: " + why}
	}
	t, err := time.Parse(checkpointTimeLayout, timeLine)
	if err != nil || t.UTC().Format(checkpointTimeLayout) != timeLine {
		return bad("recorded_at is not in SPEC §5.2's layout")
	}
	// The layout admits years 0000 to 9999, and int64 nanoseconds only 1677
	// to 2262: outside that, UnixNano wraps and the checkpoint would be judged
	// at another time entirely (found by FuzzCheckpointBody).
	if time.Unix(0, t.UnixNano()).UTC().Format(checkpointTimeLayout) != timeLine {
		return bad("recorded_at is outside the range of int64 nanoseconds")
	}
	switch stateLine {
	case stateOpen:
		return t.UnixNano(), false, nil
	case stateClosed:
		return t.UnixNano(), true, nil
	}
	return bad("state is neither open nor closed")
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
		if !c.hasHead {
			// Reading starts at the leaf before the start, which only a head
			// names; a tlog-checkpoint's root needs the tree below it.
			return nil, fmt.Errorf("%w: a tlog-checkpoint has no head to start from; start from the heartbeat note of its size", ErrUntrustedStart)
		}
		c.start = true
		cps = append(cps, c)
		start = &cps[0]
	}
	if cfg.heartbeat != nil && cfg.anchor == nil {
		return nil, errors.New("tally: WithHeartbeat needs WithAnchor: a heartbeat is judged on anchored checkpoints")
	}
	sources := []struct {
		seq      iter.Seq2[SignedCheckpoint, error]
		anchored bool
	}{{src.Checkpoints(ctx), false}}
	if cfg.anchor != nil {
		sources = append(sources, struct {
			seq      iter.Seq2[SignedCheckpoint, error]
			anchored bool
		}{cfg.anchor.Checkpoints(ctx), true})
	}
	for _, s := range sources {
		for raw, err := range s.seq {
			var me *MalformedError
			if errors.As(err, &me) {
				// The rest of this source is unreadable; what came before stands.
				rep.Failures = append(rep.Failures, Failure{Kind: MalformedRecord, Note: "checkpoints: " + me.Err.Error()})
				break
			}
			if err != nil {
				return nil, fmt.Errorf("tally: reading checkpoints: %w", err)
			}
			c, f := readCheckpoint(raw, keys)
			if f != nil {
				rep.Failures = append(rep.Failures, *f)
				continue
			}
			c.anchored = s.anchored
			cps = append(cps, c)
		}
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
		if a.at != b.at {
			return cmpI64(a.at, b.at)
		}
		// Open before closed: Close signs after the last batch, so of two
		// checkpoints sharing a size and an instant, which a clock regression
		// produces (RF-03), the closed one is the later. Left to the anchor's
		// order, a clean close could read as a crash (SPEC §7 step 6).
		return cmpBool(a.closed, b.closed)
	})
	matched := make([]bool, len(cps))
	var (
		chain    chainState
		first    = true
		f        uint64 // first_seq of the first record read
		boundary [32]byte
		// boundaryRoot is the tree's root at f, when a stored range gives it:
		// what a tlog-checkpoint of size f is compared with.
		boundaryRoot    [32]byte
		hasBoundaryRoot bool
		broke           *violation // the first record-level violation
		read            bool
	)
	chain.tree = new(merkle.Range) // from leaf 0, unless the read starts above it
	next := 0                      // the first checkpoint not yet reached by the stream
	for r, err := range src.Records(ctx, from) {
		var me *MalformedError
		if errors.As(err, &me) {
			// Stored bytes break the format (SPEC §3): a violation at the
			// first leaf not verified, not a failure to verify (RS-04).
			if !read {
				read = true
				f, chain.size = me.Seq, me.Seq
			}
			broke = &violation{kind: MalformedRecord, seq: chain.size, err: me.Err}
			break
		}
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
				// The tree below f comes only from a stored range, which the
				// host wrote: it is worth what the signed roots it reproduces
				// say. Without one, or with one that does not fit, roots are
				// not compared (SPEC §3.6).
				if tree, pending, err := storedTree(ctx, src, f); err == nil {
					chain.tree, chain.pending = tree, pending
					if tree != nil {
						if r, rerr := tree.Root(); rerr == nil {
							boundaryRoot, hasBoundaryRoot = r, true
						}
					}
				}
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
				fail := compareWithLeaf(c, chain)
				rep.Failures = append(rep.Failures, fail...)
				matched[next] = len(fail) == 0 && (c.hasHead || (c.hasRoot && chain.tree != nil))
			}
			next++
		}
	}
	if !read {
		// No record at all is something to judge only against a checkpoint
		// that says there should be: then it is a truncation below it, a
		// violation like any other (RS-04, audit A-04, #128). With none, an
		// empty source is more likely the wrong directory than a log.
		var want uint64
		for _, c := range cps {
			want = max(want, c.size)
		}
		if want == 0 {
			return nil, errors.New("tally: the source holds no record")
		}
		rep.Failures = append(rep.Failures, Failure{Kind: TruncatedBelowCheckpoint, Seq: from,
			Note: fmt.Sprintf("no record at or after leaf %d, below a checkpoint covering %d leaves", from, want)})
		return rep, nil
	}
	rep.Size = chain.size
	if broke != nil {
		rep.Failures = append(rep.Failures, Failure{Kind: broke.kind, Seq: broke.seq, Note: broke.err.Error()})
	}
	if broke != nil && f == 0 && chain.size == 0 {
		// Genesis itself is a violation: the log has no verified identity,
		// and steps 5 to 8 are skipped (SPEC §7 step 3, audit A-04).
		return rep, nil
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
		case c.size == f && f > 0 && !first: // only once the boundary was read
			switch {
			case c.hasHead && c.head != boundary:
				rep.Failures = append(rep.Failures, Failure{Kind: mismatchKind(c), Seq: c.size - 1,
					Note: "a checkpoint's head differs from the first record's prev_hash"})
			case c.hasRoot && hasBoundaryRoot && c.root != boundaryRoot:
				rep.Failures = append(rep.Failures, Failure{Kind: mismatchKind(c), Seq: c.size - 1,
					Note: "a checkpoint's root differs from the stored range's"})
			case c.hasHead || hasBoundaryRoot:
				matched[i] = true
			}
		case c.size > rep.Size && broke == nil:
			rep.Failures = append(rep.Failures, Failure{Kind: TruncatedBelowCheckpoint, Seq: rep.Size,
				Note: fmt.Sprintf("a checkpoint covers %d leaves, the log holds %d", c.size, rep.Size)})
		}
	}

	// Step 6: order. Two checkpoints of one size with different heads, or
	// different roots, are a fork; recorded_at never decreases along
	// increasing size, among the checkpoints that carry one.
	rep.Failures = append(rep.Failures, forks(cps, origin)...)
	var prevTimed *checkpoint
	for i := range cps {
		c := &cps[i]
		if c.origin != origin || !c.hasHead {
			continue
		}
		if prevTimed != nil && c.at < prevTimed.at {
			rep.Failures = append(rep.Failures, Failure{Kind: TimeRegression, Seq: c.size, Note: "a checkpoint of larger size claims an earlier time"})
		}
		prevTimed = c
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

	// Step 8: the heartbeat, over the anchored checkpoints in step 6's order.
	if hb := cfg.heartbeat; hb != nil {
		rep.Failures = append(rep.Failures, heartbeatGaps(cps, origin, hb)...)
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

func cmpBool(a, b bool) int {
	switch {
	case a == b:
		return 0
	case b:
		return -1
	}
	return 1
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

// heartbeatGaps is SPEC §7 step 8. cps is in step 6's order: size, time, state.
func heartbeatGaps(cps []checkpoint, origin string, hb *heartbeat) []Failure {
	limit := hb.interval + hb.tolerance
	var (
		gaps []Failure
		prev *checkpoint
	)
	for i := range cps {
		c := &cps[i]
		if !c.anchored || c.origin != origin || !c.hasHead {
			continue // a tlog-checkpoint carries no time (ADR-0006's amendment)
		}
		// A time after now cannot be judged against now, and would hide every
		// gap behind it: report it rather than let it pass (audit A-06, #128).
		if ahead := time.Unix(0, c.at).Sub(hb.now); ahead > hb.tolerance {
			gaps = append(gaps, Failure{Kind: HeartbeatGap, Seq: c.size,
				Note: fmt.Sprintf("an anchored checkpoint dated %v after now, over the tolerance of %v", ahead, hb.tolerance)})
		}
		if prev != nil && !prev.closed && time.Duration(c.at-prev.at) > limit {
			gaps = append(gaps, Failure{Kind: HeartbeatGap, Seq: c.size,
				Note: fmt.Sprintf("%v between anchored checkpoints, over %v", time.Duration(c.at-prev.at), limit)})
		}
		prev = c
	}
	switch {
	case prev == nil:
		gaps = append(gaps, Failure{Kind: HeartbeatGap, Note: "no anchored checkpoint: the gap is unbounded"})
	case !prev.closed && hb.now.Sub(time.Unix(0, prev.at)) > limit:
		gaps = append(gaps, Failure{Kind: HeartbeatGap, Seq: prev.size,
			Note: fmt.Sprintf("%v since the last anchored checkpoint, over %v", hb.now.Sub(time.Unix(0, prev.at)), limit)})
	}
	return gaps
}

// compareWithLeaf is SPEC §7 step 5 for a checkpoint whose size the stream
// has just reached: its head against the leaf, its time against the leaf's,
// and its root against the tree when the tree is known.
func compareWithLeaf(c checkpoint, chain chainState) []Failure {
	if c.hasHead {
		if c.head != chain.prevLeaf {
			return []Failure{{Kind: mismatchKind(c), Seq: c.size - 1, Note: "a checkpoint's head differs from the stored leaf"}}
		}
		if c.at < chain.prevTime {
			return []Failure{{Kind: TimeRegression, Seq: c.size - 1, Note: "a checkpoint's recorded_at is before its head leaf's"}}
		}
	}
	if c.hasRoot && chain.tree != nil {
		if root, err := chain.tree.Root(); err == nil && root != c.root {
			return []Failure{{Kind: mismatchKind(c), Seq: c.size - 1, Note: "a checkpoint's root differs from the log's tree"}}
		}
	}
	return nil
}

// forks is step 6's fork rule: within each size, every pair that carries a
// head, and every pair that carries a root, must agree. cps is sorted by size.
func forks(cps []checkpoint, origin string) []Failure {
	var out []Failure
	for lo := 0; lo < len(cps); {
		hi := lo
		for hi < len(cps) && cps[hi].size == cps[lo].size {
			hi++
		}
		var head, root *checkpoint
		forked := false
		for i := lo; i < hi && !forked; i++ {
			c := &cps[i]
			if c.origin != origin {
				continue
			}
			if c.hasHead {
				if head != nil && head.head != c.head {
					forked = true
				}
				head = c
			}
			if c.hasRoot {
				if root != nil && root.root != c.root {
					forked = true
				}
				root = c
			}
		}
		if forked {
			out = append(out, Failure{Kind: ForkDetected, Seq: cps[lo].size, Note: "two checkpoints of one size with different heads or roots"})
		}
		lo = hi
	}
	return out
}
