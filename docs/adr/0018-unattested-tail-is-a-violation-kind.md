# ADR-0018: Requiring full attestation reports UnattestedTail, a violation kind of its own

## Status
Accepted — 2026-11-10

## Context
RF-18 says `WithRequireFullyAttested` "makes an unattested tail a failure". A failure in a `Report`
is a `Failure` with a kind, and REQUIREMENTS §5.1 and SPEC §7.2 list every kind. None of them was
this one, so under the option `Verify` had nothing to report (#65, found while closing the SPEC
review in #10).

The tail matters because of T-01's residual: the leaf hash is not stored, so the entries past the
last checkpoint can be rewritten undetected, even without the key. A caller who will act only on
a fully attested log needs that to be a failure, not a number to remember to read.

## Decision
A new kind, `UnattestedTail`, joins REQUIREMENTS §5.1 and SPEC §7.2. It is reported in a new final
step of §7 (step 10), only when the caller required full attestation and `UnattestedEntries > 0`.
Without the requirement, an unattested tail is not a violation; `UnattestedEntries` reports it, as
before.

`OK()` keeps one meaning in both cases: no violation of any kind was reported. The option adds a
check, and the check adds a kind. It does not change what `OK()` means.

## The alternative that was rejected
**A check on the caller's side.** The option would become a helper reading
`Report.UnattestedEntries`, with no new kind and no change to the format document. Rejected because
`OK()` would then depend on something outside the `Report`: the same report would be "OK" to one
reader and not to another, according to an option neither of them can see in it. RF-18 asks that
`OK()` speak only to what was checked, and a check that ran should leave its result in the
`Report`.

## Consequences
- SPEC §7.2 gains a kind that a verifier reports only on request, so two conforming verifiers can
  disagree on `OK()` for the same log if one of them was asked for full attestation. That is the
  point of the option. The request is a verifier input (§7, Input), not a property of the log.
- An unattested tail is still the normal state of a live log between checkpoints (RF-06 sets the
  window). Requiring full attestation on a live log will usually fail, so it suits audits of a
  closed or quiesced log.
