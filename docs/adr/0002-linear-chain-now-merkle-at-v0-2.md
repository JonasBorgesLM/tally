# ADR-0002: The MVP is a linear hash chain, and v0.2 adds a Merkle tree over the same leaves

## Status
Accepted — 2026-11-03

## Context
A Merkle tree gives inclusion and consistency proofs, which is what witnesses need, and it
costs interior-node storage, a proof format and tree logic. No consumer needs proofs yet.

## Decision
v0.1 is a linear chain. Leaves are RFC 6962 from the start (ADR-0004), so the tree at v0.2
needs no format change. Verification is linear in log size until then.

## The alternative that was rejected
**Merkle from day one.** It is the eventual shape and it would avoid carrying two
checkpoint bodies. Rejected for the MVP because the whole of M1 to M6 can be validated
without it, and because an auditor reading a log end to end does not need logarithmic
proofs.

## Consequences
Split view (T-09) stays undetected in v0.1. Pruning (ADR-0012) has to be re-examined at
v0.2, as consistency proofs need interior hashes from the pruned range.

## Reopening criterion
When a consumer needs an inclusion proof without reading the log, or M11 begins.
