# ADR-0004: Leaf hashes follow RFC 6962, and genesis is leaf 0

## Status
Accepted — 2026-11-03

## Context
The v0.2 tree is meant to reuse v0.1's leaves. That promise fails on two details: the
domain-separation prefix, and whether genesis is a leaf at all. v0.2 said `size` is the
number of entries and gave genesis a leaf hash, leaving the indices ambiguous (R-27).

## Decision
`leaf_hash = SHA-256(0x00 || record_bytes)`; `0x01` is reserved for interior nodes
(RS-01). Genesis is leaf 0 with `seq = 0`, and the first entry is `seq = 1`, so `size =
head_seq + 1` and an index is always a `seq`.

## The alternative that was rejected
**Genesis outside the tree, with `size` counting only entries.** It reads naturally, since
`size = 3` means three events. Rejected because the first entry's `prev_hash` still needs
genesis, so `log_id` and `origin` would be bound to the chain and not to the tree, and
every index would be off by one against RFC 6962 verifiers.

## Consequences
`size` is one more than the number of events, which every reader has to be told once. A
new log has size 1, not 0.
