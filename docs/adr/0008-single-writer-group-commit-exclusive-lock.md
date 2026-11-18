# ADR-0008: One writer goroutine, group commit, and an exclusive lock per log

## Status
Accepted — 2026-11-03

## Context
A chain is a total order: each entry names the previous one's hash. Writers therefore
serialise somewhere, and the choice is what that costs.

## Decision
One goroutine assigns `seq`, chains, batches and calls `AppendBatch` (`MaxBatch`,
`MaxDelay`). Validation and sealing stay on the caller's goroutine. A `flock` makes a
second writer fail with `ErrLocked` (RS-09). Replicas have one log each, and each has its
own `origin`.

## The alternative that was rejected
**A mutex around the chain, with an fsync per `Append`.** Far simpler, with no channels or
goroutine lifecycle. Rejected because fsync is the cost, and group commit is what makes
one fsync pay for many entries (RNF-03). **Several writers on one log** would need
consensus, which is a non-goal.

## Consequences
A goroutine to manage, with no leak after `Close` (RNF-06). Up to `MaxDelay` of added
latency under light load. `flock` is unreliable on NFS and SMB, so they are unsupported.
Multi-replica deployments verify several logs.
