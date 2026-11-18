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
