# ADR-0014: The verifier's release is reproducible, signed and attested

## Status
Accepted — 2026-11-03

## Context
`tally verify` is what an auditor trusts to say the log is intact. A tampered binary says
intact to anything (R-11, T-18). moat's lessons include a published tag that did not
resolve.

## Decision
Release through CI from a signed tag on `main`: `-trimpath` and embedded version, signed
checksums, SBOM, build provenance. The checklist includes a clean-room `go install` and a
retract plan. `docs/SPEC.md` is enough to write an independent verifier, which is the real
defence.

## The alternative that was rejected
**Publishing source only, and telling auditors to build it.** No release pipeline to
secure, and the auditor's own toolchain is the trust root. Rejected as the only route
because most auditors will not, though it stays possible: that is what reproducibility is
for.

## Consequences
A release workflow to maintain and watch fail before trusting it. A compromised CI still
signs what it built; provenance names the pipeline, not its honesty.
