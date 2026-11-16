# ADR-0019: A file store rotates segments only after storing a checkpoint that covers every record

## Status
Accepted — 2026-11-16

## Context
RF-06 says a checkpoint is signed on every segment rotation. The two halves of that sentence live
in different places. The store decides when a segment is full, because only it knows the file
sizes. The `Log` holds the `Signer`. The `Store` interface has no way back from the first to the
second: `AppendBatch` and `PutCheckpoint` return an error and nothing else (#33).

The boundary between segments is also where the format needs a checkpoint most. A segment set
that starts at `first_seq = f > 0`, after a prune (#35) or an incremental start, verifies only if
some matched checkpoint has `size ≥ f` (SPEC §7 step 7). A checkpoint of exactly `size = f` is
matched against that segment header's `prev_hash` (step 5).

## Decision
`filestore` rotates **only inside `PutCheckpoint`**, after the checkpoint is durable, and only when
the current segment has reached the configured size. The new segment's `first_seq` is one past
the last stored record.

That is the checkpoint's `size` because the `Store` contract gains a sentence: **the checkpoint
given to `PutCheckpoint` covers every record stored.** The `Log` already does this. Its writer
goroutine calls both methods and signs over its head, which advances only after `AppendBatch`
returned.

So every segment boundary `f > 0` has a checkpoint of `size = f`, stored locally before the new
segment exists, whose `head` is the new header's `prev_hash`. RF-06's rotation trigger is met by
construction, and the `Store` interface does not change.

## The alternative that was rejected
**Rotate by size inside `AppendBatch`, and let the `Log` ask the store whether it rotated** (an
optional interface, say `Rotated() bool`, checked after each batch, followed by a checkpoint). It
keeps the size bound exact, which matters on a filesystem with a file-size limit or a backup tool
that copies whole files.

It is rejected because the checkpoint then follows the rotation instead of preceding it, and
nothing makes it happen. A crash between the two leaves a boundary with no checkpoint. So does a
signing error, since `autoCheckpoint` drops it and retries at the next trigger. Either way, RF-06
is broken silently, and the store, which made the boundary, cannot tell. The design also adds a
concept to the root package's API to serve one implementation.

## Consequences
- **The size bound is soft.** A segment exceeds the target by what arrives before the next
  checkpoint: up to 1,000 entries or 60 seconds at the defaults. With the default 64 KiB payload
  limit, that is up to about 64 MiB more. With `WithCheckpointEvery(0, 0)`, a segment grows
  until `Checkpoint` or `Close`. With a signer that keeps failing, it grows without bound, and
  that failure is already reported at `Checkpoint` and `Close`.
- **A rotation failure poisons the log** with the checkpoint stored but not yet published to any
  anchor. That is the safe order (architecture.md, "Checkpoint"): stored and unpublished never
  looks like a rollback.
- **The boundary checkpoint is local.** It satisfies RF-06 and SPEC §7 step 5. It is not by itself
  a trusted start for a pruned log: `Prune` (#35) asks for a checkpoint verified against the
  caller's keys.
- Another `Store` is free not to rotate at all. The contract sentence above holds for any store.

## Reopening criterion
When a deployment needs a hard bound on segment size, or the `Log` gains a channel through which
a store can request a checkpoint before it rotates.
