# ADR-0012: Retention is Prune below a verified checkpoint, and the CLI requires the anchor

## Status
Accepted — 2026-11-03

## Context
The log would grow forever, LGPD asks for minimisation, and deleting old segments would
break verification from genesis (R-10). v0.2 wanted "anchored" checkpoints, but
`Prune(cp)` could only see a checkpoint it was given (R-32).

## Decision
`filestore.Prune` removes only segments wholly below a checkpoint whose signature
verifies, and writes a marker. The CLI's `prune` also requires that checkpoint to be in
the anchor. Later verification needs it as trusted; otherwise
`PrunedWithoutTrustedCheckpoint`. The library cannot itself prove anchoring, and says so
(RS-20).

## The alternative that was rejected
**A retention setting that prunes by age automatically.** The operator's work disappears,
and a background deletion in an audit library is the wrong default: destroying evidence
should be an explicit act. **Giving `Prune` an `AnchorReader`** makes the library check,
but the host then decides what it trusts about an anchor it may have been told to read.

## Consequences
A library caller can prune with a valid but never-anchored checkpoint. An auditor needs
the checkpoint to verify at all. Pruning deletes evidence with legal retention
implications, which remain the operator's call. M11 must check this against interior
hashes.

## Amendment — a prune keeps the compact range (#59)

M11's tree needs interior hashes from below the first record a prune keeps. `Prune` now
writes the **compact range** below that record to `pruned.range` before removing anything
(SPEC §3.6): at most 64 hashes, one per bit of its seq. With it, every root of a size at
least that record, the inclusion of every record kept, and consistency from every size at
least it stay provable. The prune checkpoint's size is such a size, and it is anchored, so
a witness or auditor holding it gets a consistency proof to any later checkpoint.

**The option not taken: keep every pruned leaf hash.** It would make every proof possible,
from any old size, and would grow by 32 bytes per pruned record. It also keeps, for every
record whose evidence was destroyed on purpose, a hash that confirms a guess of its bytes,
which is less than minimisation asks. A consistency proof from a size below the prune is
what is lost: a witness that last saw such a size has to accept the anchored prune
checkpoint as its new starting point.

A log a v0.1 writer pruned has lost the leaves a range needs. It is pruned further without
one, and has no tree below its first segment. Nothing needs rewriting.
