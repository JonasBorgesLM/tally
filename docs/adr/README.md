# Architecture Decision Records

Every structural decision is recorded here. **An ADR is never edited to reflect a later
change of mind.** It is amended in place with a section naming what superseded which part,
so the reasoning that was current at the time stays readable.

CI enforces the mechanical form: an existing ADR may gain lines, never lose them.

New records start from [`TEMPLATE.md`](TEMPLATE.md), which is deliberately not named `0000-`
so it does not read as a decision or trip the index check.

All of these were accepted before any code exists. A record that turns out to be wrong
when M1 to M6 implement it gets an amendment.

## Index

| ADR | Title | Status | Amended by |
| --- | --- | --- | --- |
| [`0001`](0001-tamper-evident-with-a-conditional-guarantee.md) | tally is tamper-evident, and its guarantee is conditional on an off-host checkpoint | Accepted | — |
| [`0002`](0002-linear-chain-now-merkle-at-v0-2.md) | The MVP is a linear hash chain, and v0.2 adds a Merkle tree over the same leaves | Accepted | — |
| [`0003`](0003-strict-fixed-width-binary-encoding.md) | Records use a strict fixed-width binary encoding, and stored bytes are hashed bytes | Accepted | — |
| [`0004`](0004-rfc-6962-leaves-with-genesis-as-leaf-zero.md) | Leaf hashes follow RFC 6962, and genesis is leaf 0 | Accepted | — |
| [`0005`](0005-c2sp-signed-note-checkpoints.md) | Checkpoints are C2SP signed notes, with tlog-checkpoint at v0.2 | Accepted | — |
| [`0006`](0006-anchor-and-heartbeat-in-the-mvp.md) | The MVP anchors checkpoints off the host, where the host cannot alter them, and heartbeats are partial evidence | Accepted | — |
| [`0007`](0007-two-timestamps-monotonic-recorded-at.md) | Entries carry two timestamps, and recorded_at is monotonic | Accepted | — |
| [`0008`](0008-single-writer-group-commit-exclusive-lock.md) | One writer goroutine, group commit, and an exclusive lock per log | Accepted | — |
| [`0009`](0009-poison-on-io-error-no-interval-durability.md) | An IO error poisons the log, and there is no interval durability mode | Accepted | — |
| [`0010`](0010-failure-policy-belongs-to-the-caller.md) | Failure policy belongs to the caller, with explicit outcomes and idempotency | Accepted | — |
| [`0011`](0011-vault-with-random-refs-and-typed-principal.md) | A vault holds random refs, with incarnations, and Principal is typed | Accepted | — |
| [`0012`](0012-retention-through-anchored-prune.md) | Retention is Prune below a verified checkpoint, and the CLI requires the anchor | Accepted | — |
| [`0013`](0013-ecosystem-dependency-rules.md) | Core libraries do not depend on each other, and consumers host the adapters | Accepted | — |
| [`0014`](0014-verifier-supply-chain.md) | The verifier's release is reproducible, signed and attested | Accepted | — |
| [`0015`](0015-signer-in-process-behind-an-interface.md) | The signer runs in process in the MVP, behind an interface | Accepted | — |
| [`0016`](0016-verifier-stops-at-first-broken-record.md) | The verifier stops at the first broken record, and judges checkpoints only against the prefix it verified | Accepted | — |

## Reopening criteria on the record

Decisions carrying an explicit trigger, so "revisit later" is not a synonym for never.

| ADR | Reopen when |
| --- | --- |
| [`0002`](0002-linear-chain-now-merkle-at-v0-2.md) | When a consumer needs an inclusion proof without reading the log, or M11 begins. |
| [`0006`](0006-anchor-and-heartbeat-in-the-mvp.md) | The time source at v0.2, when tlog-checkpoint removes the time line: decide in #60, between witness cosignature timestamps and a separate signed heartbeat note. |
| [`0009`](0009-poison-on-io-error-no-interval-durability.md) | If a filesystem or kernel offers a reliable way to learn what reached disk after a failed fsync. |
| [`0015`](0015-signer-in-process-behind-an-interface.md) | When a real deployment holds an application whose compromise is credibly below root, such that a signer process changes the outcome, or when an audit finding asks for it. |

## Open questions

Deferred deliberately, listed rather than left implicit.

| Question | Where it gets answered |
| --- | --- |
| The vault's on-disk format and KEK rotation | #43 (M6), then `docs/SPEC.md` |
| Whether usher's new port replaces or sits beside `audit.Emitter`; a process death before a retry on a reducing event | #51: usher's own ADR, superseding `usher/ADR-0017` |
| How heartbeats keep a time source under tlog-checkpoint | #60 (M11) |
| Whether SPEC v1 is sufficient for an independent verifier | #10: a clean-session review found 27 gaps over three rounds, closed in `docs/SPEC.md` and [`0016`](0016-verifier-stops-at-first-broken-record.md) |
