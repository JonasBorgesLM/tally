package tally_test

import (
	"testing"

	"github.com/JonasBorgesLM/tally"
)

// R-23, T-01: OK must not read as "everything is intact". The leaf hash is not
// stored in any record, so a change to an entry past the last trusted
// checkpoint, with no entry after it, leaves nothing that disagrees: no
// successor's prev_hash covers it, and no checkpoint does. Verify then says OK,
// and says how much it could not attest. This test pins that limit, so the
// docs cannot claim more.
func TestAnAlteredUnattestedTailPassesAndIsCounted(t *testing.T) {
	src := honestLog(t, 6, 3) // a checkpoint at size 4; Close adds one at 7
	src.cps = src.cps[:1]     // keep only the size-4 checkpoint: leaves 4 to 6 are the tail
	last := len(src.recs) - 1
	src.recs[last].Body[offOccurredAt] ^= 1 // rewrite the last entry

	rep := verify(t, src)
	if !rep.OK() || rep.AttestedSize != 4 || rep.UnattestedEntries != 3 {
		t.Fatalf("report %+v: want OK, AttestedSize 4, UnattestedEntries 3", rep)
	}
}

// RF-18, ADR-0018: requiring full attestation turns that tail into a failure,
// UnattestedTail, and a fully attested log still passes.
//
// Negative control: removing step 10 from Verify made the first case pass.
func TestRequireFullyAttested(t *testing.T) {
	tail := honestLog(t, 6, 3)
	tail.cps = tail.cps[:1]
	rep := verify(t, tail, tally.WithRequireFullyAttested())
	if got := kinds(rep); len(got) != 1 || got[0] != tally.UnattestedTail || rep.OK() || rep.Failures[0].Seq != 4 {
		t.Fatalf("failures %+v, want one UnattestedTail at leaf 4", rep.Failures)
	}

	full := honestLog(t, 6, 3) // Close's checkpoint covers every leaf
	if rep := verify(t, full, tally.WithRequireFullyAttested()); !rep.OK() || rep.UnattestedEntries != 0 {
		t.Fatalf("a fully attested log under the requirement: %+v", rep)
	}

	// Without the requirement, the same tail is reported, not failed.
	if rep := verify(t, tail); !rep.OK() || rep.UnattestedEntries != 3 {
		t.Fatalf("without the requirement: %+v", rep)
	}
}
