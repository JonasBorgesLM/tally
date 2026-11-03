<!--
Title: a Conventional Commit, ≤ 72 characters including " (#N)". It becomes the
subject on a squash merge. Add `!` for an incompatible API change.
  feat(wire): reject trailing bytes after the last field
Branch: <type>/<issue>-<name>, into develop (CONTRIBUTING.md).
-->

## What and why

<!-- The diff says what changed. Say why it needed to. -->

## Traceability

- Requirements: <!-- RF-01, RS-02 -- or "none" with a reason -->
- Threats: <!-- T-13 -- or "none" -->
- Decisions: <!-- ADR-0003 -- or "none" -->
- Closes: <!-- #11 -->

## Correctness checklist

Delete the lines that do not apply; keep the ones that do.

- [ ] Every new protection has a test that was **seen failing** with the
      protection removed; the negative control is noted above the test.
- [ ] A security test asserts the expected detection, not the absence of an error.
- [ ] Mutation tests recompute the CRC, or they test the CRC and not the chain (R-28).
- [ ] No `Receipt` before `AppendBatch` returned; a store error poisons (RF-01, ADR-0009).
- [ ] Sizes are checked before allocating (RS-05).
- [ ] No secret reaches an error, a log or `%v` (RS-07); no payload reaches the `Observer` (RF-16).
- [ ] `go test -race -shuffle=on ./...` passes; a new goroutine stops at `Close` (RNF-06).
- [ ] The threat model's residuals still describe the code.

## Documentation

- [ ] Exported identifiers document the contract, not the signature.
- [ ] A format change updates `docs/SPEC.md` and the vectors in the same pull request.
- [ ] A structural decision has an ADR, written **before** the code; existing ADRs amended, never rewritten.
- [ ] `CHANGELOG.md` `[Unreleased]` updated for a user-visible change.
- [ ] `./.github/scripts/check-docs.sh` and `./.github/scripts/check-boundaries.sh` pass locally.
