# ADR-0017: A panicking Observer is recovered, its event dropped, and the panic counted

## Status
Accepted — 2026-11-09

## Context
The `Observer` (RF-16) is the caller's metrics code. tally calls it from the writer goroutine,
the one goroutine that orders and stores every entry (ADR-0008). A panic there, left alone,
ends the process: Go does not let a panic in one goroutine be caught by another. So a bug in a
dashboard counter would take down the application being audited.

#22 asked for this behaviour to be decided rather than inherited.

## Decision
Every Observer call is wrapped in `recover`. A call that panics loses its one event, and the
Observer goes on being called for later events. `Log.ObserverPanics()` returns how many calls
have panicked, so the caller can monitor it like any other health signal.

A panic changes nothing else: the entry whose batch triggered the event is already durable, its
`Receipt` is returned, and the log is not poisoned.

## The alternative that was rejected
**Let it crash.** The bug is visible at once, and nothing is hidden. Rejected because the cost
lands on the wrong component: an error in observability code becomes an outage of the whole
application, in the library whose job is to keep a record while the application runs.

**Recover and poison the log.** This is visible to every caller of `Append`, which is the
strongest signal tally has. Rejected because it turns an observability bug into an audit
outage. ADR-0010 leaves failing closed to the application, and poisoning is reserved for the
one condition after which writing is unsafe: a store error (ADR-0009). A panicking counter is
not that condition.

**Recover and stop calling the Observer.** After the first panic the Observer is disabled, so
a repeating panic costs nothing on the hot path. Rejected because every later signal is then
lost, `Poisoned` included, at the moment something has already gone wrong. A panic on every
call also costs only a `recover` per event, which is small next to an fsync.

## Consequences
- A panic is silent unless someone reads `ObserverPanics()`. tally has no logger, so the counter
  is the only trace, and its godoc says so.
- An Observer that panics on every call loses every event. Nothing reports it except the counter.
- The non-blocking contract is unchanged. `recover` does not help a call that blocks, which
  stalls every `Append`. The godoc of `Observer` states that as the caller's obligation.
