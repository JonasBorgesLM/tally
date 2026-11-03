# ADR-0007: Entries carry two timestamps, and recorded_at is monotonic

## Status
Accepted — 2026-11-03

## Context
A caller knows when something happened; the log knows when it was told. Neither alone is
enough, and a host clock can step backwards. v0.1 treated a regression as a warning
(R-14).

## Decision
`occurred_at` comes from the caller and is untrusted. `recorded_at` comes from the log's
`Clock` and never decreases: a regression clamps to the previous value and alarms (RF-03).
A verifier fails on a regression in `recorded_at`, and never on `occurred_at`.

## The alternative that was rejected
**One timestamp.** Simpler, but a late retry then either lies about when it happened or
about when it was recorded. **Failing `Append` on a clock regression** rejects a real
event because of an NTP step, and an audit log should not lose an event for that.

## Consequences
After a large backwards step, `recorded_at` stalls until the clock catches up, and it is
still not proof of real time (T-14). RFC 3161 is deferred.
