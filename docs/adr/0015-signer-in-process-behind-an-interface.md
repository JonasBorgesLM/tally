# ADR-0015: The signer runs in process in the MVP, behind an interface

## Status
Accepted — 2026-11-03

## Context
The signing key on the host is what makes T-07 possible. A separate signer process, over a
Unix socket, would stop an application compromise from reading the key outright. The
question was open in v0.2 (§16.3).

## Decision
The MVP signs in process, from a key file at 0600, through the `Signer` interface. A
separate process or a KMS implements that interface from outside the library. The key is
never usher's token key (RS-06), and never appears in output (RS-07).

## The alternative that was rejected
**A signer process in the MVP.** Argued properly: it raises the bar against a read-only or
application-level compromise, and the key survives process memory disclosure. Not taken
because, against root on the host, the attacker asks the signer to sign whatever they
like, so the key's secrecy matters less than it seems; **the anchor is the control that
holds against that attacker,** and a socket protocol, its authentication and its lifecycle
are real scope for a benefit against the weaker attacker only.

## Consequences
An application-level memory disclosure yields the key. Rotation (RF-10) is the response,
and anything anchored before it stays valid. T-07's residual stands.

## Reopening criterion
When a real deployment holds an application whose compromise is credibly below root, such
that a signer process changes the outcome, or when an audit finding asks for it.
