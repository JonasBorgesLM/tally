# ADR-0005: Checkpoints are C2SP signed notes, with tlog-checkpoint at v0.2

## Status
Accepted — 2026-11-03

## Context
A private checkpoint format would need its own review and would talk to nothing.
c2sp.org/signed-note is small, has an existing Go implementation, and is what the
transparency-log witness ecosystem speaks.

## Decision
The MVP body has a `tally-chain/v1` second line, which deliberately fails a
tlog-checkpoint parser, because a chain head is not a Merkle root. Implementation is
minimal, in `internal/note`, and tested differentially against
`golang.org/x/mod/sumdb/note` in the separate `interop` module, keeping the core stdlib
only. The private key file uses the signed-note key encoding at mode 0600. The key name is
the log's `origin`, so there is no `WithOrigin` to disagree with it.

## The alternative that was rejected
**Importing `x/mod/sumdb/note` in the core.** It is the reference, and it would save about
200 lines. Rejected because RNF-01 is stdlib only for the whole core, and that module
brings a dependency into every consumer for a format that fits in one small package.
**PKCS#8 PEM for the key** is familiar to tools, but it would make `keygen` output differ
from every other tool in that ecosystem.

## Consequences
A second signed-note implementation to maintain. tlog-checkpoint has no time line, so the
v0.2 move has to settle how heartbeats survive it (ADR-0006).
