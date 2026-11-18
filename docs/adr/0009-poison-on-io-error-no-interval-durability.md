# ADR-0009: An IO error poisons the log, and there is no interval durability mode

## Status
Accepted — 2026-11-03

## Context
On Linux, after a failed fsync, the kernel can mark dirty pages clean, and a retry then
reports success with the data gone (PostgreSQL's "fsyncgate"). A new file also needs its
directory synced to survive a crash (R-04). An acknowledged entry that is then lost
falsifies the library's only promise.

## Decision
Any write or fsync error poisons: every later `Append` returns `ErrPoisoned`. There is no
retry. Reopening means closing, and recovery validates the tail. `AppendBatch` is durable
on return, directories are synced on creation and rotation, and v0.1's `SyncInterval` is
gone. Recovery quarantines rather than deletes (RF-20).

## The alternative that was rejected
**Retrying fsync with backoff.** It keeps the application up through a transient error,
which is genuinely attractive for fail-closed actions. Rejected because it is exactly what
fsyncgate showed to be unsound. **A `SyncInterval` mode** would raise throughput, and it
means an entry can be acknowledged and lost, so `Append`'s return would mean nothing.

## Consequences
A disk hiccup becomes an outage for fail-closed actions, on purpose. **Residual (R-31):**
after a failed fsync the page cache can show data that never reached disk, and a reopen in
the same boot reads it, CRC valid, and builds on it. Recovery cannot detect this. The
runbook says: after `ErrPoisoned`, restart, verify, and treat the most recent data as
suspect. Throughput is bound by fsync.

## Reopening criterion
If a filesystem or kernel offers a reliable way to learn what reached disk after a failed
fsync.
