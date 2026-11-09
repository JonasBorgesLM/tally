# ADR-0016: The verifier stops at the first broken record, and judges checkpoints only against the prefix it verified

## Status
Accepted — 2026-11-09

## Context
The independent review of SPEC v1 (#10) wrote a verifier from the spec alone. It hit four
behaviours that the spec left open:

- **What happens after a violation.** SPEC v1 compared a checkpoint's head only with the
  leaf at `size - 1`. After a broken link at `seq` 2, the stored leaves 3 to 5 still hash
  to the values a checkpoint signed. So the reviewer's report said `PrevHashMismatch` and
  `AttestedSize = 6` together: the log was attested past its own break.
- **How a log that does not start at leaf 0 is judged.** SPEC v1 said a prune marker "is
  present" and a checkpoint "MUST cover the boundary". It never defined the marker. It was
  also unclear whether the marker was a condition or a requirement, and whether "cover"
  meant `size = first_seq` exactly.
- **What "across checkpoints, `size` and `recorded_at` MUST not decrease" is ordered by.**
  Checkpoints arrive as a set. In the order supplied, two anchors listed in reverse would
  pass or fail depending on the listing.
- **What the start checkpoint of an incremental verification does** (RF-08).

## Decision
1. **Stop at the first record violation.** The verified prefix is the leaves before it.
   Checkpoints are compared only with leaves in that prefix, so `AttestedSize ≤ Size`. A
   checkpoint above the prefix is `TruncatedBelowCheckpoint` only when the log was read
   without violation. After a violation it is not evaluated. The checks within one record
   run in a fixed order, so every verifier names the same violation. If genesis itself is
   broken, the log has no identity to judge checkpoints by, and only that violation is
   reported.
2. **A start above leaf 0 needs a matched checkpoint at or above the start.** It does not
   need one at exactly the start. If the first segment read starts at `f > 0`, some
   accepted checkpoint with `size ≥ f` must match: at `size = f` against the header's
   `prev_hash`, and above it against the leaf at `size - 1`. This one rule serves both a
   pruned log and an incremental start. The prune marker is not a verifier input.
3. **Checkpoints are ordered by `size`, then `recorded_at`.** `recorded_at` must not
   decrease along that order, so no checkpoint claims a later time than one of larger
   `size`. The secondary key matters because heartbeats produce many checkpoints of one
   `size`. Two accepted checkpoints of one `size` with different heads are `ForkDetected`.
4. **An incremental start skips earlier segments.** Reading starts at the segment that holds
   leaf `s - 1` of a start checkpoint of size `s`. The checkpoint must be accepted, or the
   result is an `error`, because a caller that names a start it cannot trust has misused the
   API.

## The alternative that was rejected
**Keep reading after a violation and report every failure.** One run would then show the
full extent of damage, and an auditor with one corrupted frame in a large log could see
whether the rest is sound. Rejected because every downstream conclusion would rest on a
chain known to be broken. A checkpoint that matches leaf 5 says nothing once leaf 2 does
not link to leaf 1, yet it would show up as attestation. Downstream failures would also be
consequences of the first one, burying the cause. An auditor who needs the rest of the log
can verify from the next accepted checkpoint above the break, with the incremental start
of decision 4. That keeps every claim tied to a signed starting point.

**Require a checkpoint at exactly the boundary (`size = f`).** This is the literal reading
of SPEC v1, and it names one specific checkpoint as the prune's evidence. Rejected because
it adds no protection. Rotation writes a checkpoint at every segment boundary (RF-06), so an
attacker who deletes whole leading segments can always stop at a checkpointed boundary. It
also rejects a log whose boundary checkpoint was lost while a later one, which commits to
the same `prev_hash` through the chain, survives.

**Use the prune marker as evidence.** Rejected because the marker is a file the host
writes. The checkpoint is signed, and the verifier already trusts it or does not.

**Order checkpoints as supplied.** Rejected because the result would depend on how an anchor
lists files, which is not part of the format.

## Consequences
- A run reports at most one record-level violation. A second, independent tamper further
  on is found only by verifying again from a checkpoint above the first.
- **Deleting whole leading segments, down to any segment boundary that an accepted
  checkpoint covers, cannot be told apart from a legitimate prune** by the verifier. The
  evidence that a prune was authorised is outside the log: the CLI requiring the checkpoint
  in the anchor (ADR-0012, RS-20) and the operator's records. This residual was implicit in
  ADR-0012. It is now stated, and the threat model should name it.
- Without genesis, the log's `origin` comes from the checkpoints. Several origins among the
  accepted checkpoints is an error, so a trust set spanning several logs needs genesis or a
  start checkpoint.
- The streaming verifier needs the accepted checkpoints before it reads the records, sorted
  by `size`. That is the "checkpoint window" RNF-04 already allows.
