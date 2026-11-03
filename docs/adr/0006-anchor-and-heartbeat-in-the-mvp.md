# ADR-0006: The MVP anchors checkpoints off the host, where the host cannot alter them, and heartbeats are partial evidence

## Status
Accepted — 2026-11-03

## Context
v0.1 deferred anchoring, leaving the key and the log on one host, so T-05, T-07 and T-08
were undetectable in practice (R-01). v0.2 added it, but offered a directory mounted from
another machine (R-22): root on the host rewrites that. It also presented heartbeats as
detecting suppression (R-15), though a heartbeat proves only that the signer ran (R-24).

## Decision
Anchoring is in the MVP, asynchronous, and never blocks `Append` (RF-07, RF-19). An anchor
is defined by a property: **the host holds no credential that can alter or delete what it
published** (RS-17). `anchor.Dir` is a create-only spool that something off the host pulls
from. `Anchor` writes and `AnchorReader` reads, as separate interfaces. Heartbeats are
checkpoints on a timer, and T-15 is classified as partial: they detect a stop, not a
selective omission. A clean `Close` writes `closed` so an honest restart is not an alarm.

## The alternative that was rejected
**Synchronous publication, so nothing is acknowledged before it is anchored.** It would
shrink T-07's window to nothing, and it is the strongest available claim. Rejected because
it makes every audited action depend on the network, and a host attacker can still act
before the write reaches the log. **`anchor.Dir` over a mount as the default recipe** is
the simplest setup, and it is rejected because it silently provides nothing.

## Consequences
A window remains between an entry and its anchored checkpoint, set by RF-06 plus any pull
interval. Pull-based anchoring needs a second machine, which is real operational cost. The
library cannot verify RS-17 in a deployment, so a wrong setup runs and reports intact.
Heartbeat times are self-asserted, so a gap is credible only if the anchor side records
arrival. `state` can be forged by a key holder.

## Reopening criterion
The time source at v0.2, when tlog-checkpoint removes the time line: decide in #60,
between witness cosignature timestamps and a separate signed heartbeat note.
