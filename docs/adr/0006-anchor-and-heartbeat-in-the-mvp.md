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

## Amendment — time moves to a heartbeat note beside the tlog-checkpoint (#60)

**Decision.** At v0.2 a checkpoint is published as two notes, both signed by the log's key:

1. A **checkpoint**, in plain `tlog-checkpoint` form: the origin, the size, and the Merkle
   root (#59, SPEC §3.6). It has no time and no state, so a witness (#61) cosigns it as it
   cosigns any log's.
2. A **heartbeat note**, `tally-heartbeat/v1`: the origin, the size, the head leaf hash, the
   root, `recorded_at` and `state`. It carries what the v0.1 body carried, plus the root
   that binds it to the checkpoint of the same size.

The heartbeat check (T-15) reads heartbeat notes. A verifier matches a heartbeat note
against the log by its head, as it matched a v0.1 checkpoint, so an incremental start and a
pruned log still verify without the tree below them. It checks the root whenever it holds
the tree: from leaf 0, or from a pruned range (SPEC §3.6) that reproduces a root a trusted
note signs. A checkpoint and a heartbeat note of one size with different roots, or a root
that differs from the tree, is a fork or a mismatch, as two heads are today.

**What does not change:** time and state remain the signer's own claims. A heartbeat still
proves that the signer ran, not that the log is complete (T-15), and a key holder can still
forge `closed`.

**The transition.** A log written by v0.1 holds `tally-chain/v1` checkpoints, and its
anchors hold them too. A v0.2 verifier accepts both kinds in one log; a v0.2 writer writes
only the new pair. Nothing stored is rewritten.

**The options not taken.**

- **Extension lines** in the checkpoint, after the root: one note instead of two, and the
  heartbeat check unchanged. Not taken because c2sp's `tlog-checkpoint` discourages them,
  and a witness may refuse a checkpoint that carries them, which is what #61 needs.
- **Witness cosignature timestamps** as the only time: a third party's claim, stronger than
  the signer's. Not taken as the source because a deployment without a witness would lose
  the heartbeat entirely. Once a witness exists (#61), its timestamps can be checked as
  additional evidence; they replace nothing here.

**Cost.** Two notes per publication: twice the signatures, the checkpoints file and the
anchor hold both, and SPEC gains a format. The writer keeps the tree's compact range in
memory to sign a root on every checkpoint, which is O(log n) per append.
