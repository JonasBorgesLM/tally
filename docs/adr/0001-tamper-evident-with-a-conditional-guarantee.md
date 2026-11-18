# ADR-0001: tally is tamper-evident, and its guarantee is conditional on an off-host checkpoint

## Status
Accepted — 2026-11-03

## Context
An audit log can be sold as more than it is. An append-only hash chain on a compromised
host proves nothing, since whoever rewrites the file recomputes the chain. v0.2 also let
`OK()` read as "everything is intact", though the leaf hash is not stored, so the tail
past the last checkpoint is unprotected (R-23).

## Decision
The guarantee is written as a condition: given a trusted checkpoint obtained from outside
the compromised host, any alteration, removal, insertion or reordering of entries it
covers is detectable. `Verify` reports what it covered: `Report` separates `AttestedSize`
from `UnattestedEntries` (RF-18), and `WithRequireFullyAttested` fails on an unattested
tail.

## The alternative that was rejected
**Storing a per-entry signature or MAC, so each entry stands alone.** A signature per
entry would close the tail for an attacker without the key, at a cost of one signature per
entry on the writer's hot path. It does nothing against the host attacker, who holds the
key, and that is the threat that matters. A MAC chain is revisited for forward security in
v0.3 and later.

## Consequences
An honest `verify` can print OK with a non-zero unattested count, which is less satisfying
than a green tick. Applications must set a checkpoint interval knowing it is their
exposure window (RF-06).
