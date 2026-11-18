# ADR-0013: Core libraries do not depend on each other, and consumers host the adapters

## Status
Accepted — 2026-11-03

## Context
v0.1 had a `crierexport` adapter in this repository, coupling versions and feeding audit
through a lossy pipeline (R-05). The ecosystem has several libraries that could plausibly
call each other.

## Decision
tally imports no ecosystem library (RI-01), enforced by the resolver, not a grep. Whoever
owns an interface hosts the adapter. Wiring is in applications. A ~30-line redaction type
is reimplemented rather than imported from moat. crier is an optional mirror of confirmed
events, and bastion wraps only `Anchor.Publish`, never `Append`.

## The alternative that was rejected
**A shared `ecosystem-core` module** for redaction, clocks and WAL. It removes real
duplication. Rejected under the rule of three: there are not three real consumers, and
shared code here would be a compatibility promise across every library. **Importing moat's
`secret`** is one line, and it puts a third-party module graph in an audit library's core
for 30 lines of code.

## Consequences
Some duplicated code. Each consumer writes an adapter. The usher integration is not a
drop-in (R-25, RI-02): it needs a new usher ADR.
