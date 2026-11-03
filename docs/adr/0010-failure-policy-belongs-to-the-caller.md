# ADR-0010: Failure policy belongs to the caller, with explicit outcomes and idempotency

## Status
Accepted — 2026-11-03

## Context
Uniform fail-closed blocks a token revocation when audit fails, leaving a compromised
token valid (R-02), so the right answer depends on the action, which only the application
knows. Cancellation after enqueueing leaves the outcome unknown (R-09). And v0.2 returned
a success for any repeated `EventID`, which would hide an event (R-29).

## Decision
The library has no `FailClosed` or `BestEffort`: `Append` reports the real error, and the
application applies policy by privilege direction (§11.2). Cancelled before enqueueing is
`ctx.Err()`; after, `ErrOutcomeUnknown`. Retrying with the same `EventID` is safe,
returning the original receipt. A repeated id with different metadata is
`ErrEventConflict`; sealed bytes are excluded, since a random nonce makes each retry
differ.

## The alternative that was rejected
**A per-action policy option in the library.** It would make the safe behaviour
declarative and shared by every consumer. Rejected because the library would then need an
action catalogue, and the direction of privilege is domain knowledge. **Comparing the
whole event, sealed bytes included,** would catch more conflicts, and it would make every
sealed retry a conflict.

## Consequences
Each consumer must implement the policy, and can get it wrong. A sealed payload changed on
a retry with the same metadata is undetected. Past the window, a retry is a new entry
(T-11).
