# tally

**A tamper-evident audit log library for Go:** a hash chain, signed checkpoints anchored off the
host, offline verification, and crypto-shredding for LGPD.

> **Status: design stage. There is no library code yet, and nothing here can be installed.**
> The requirements, threat model, format specification and decisions are written and enforced by
> CI, and they are what the implementation is checked against. Progress is on the
> [project board](https://github.com/users/JonasBorgesLM/projects/9).

## What it will do

Someone who compromises a host, or an insider with privileged access, tries to erase the trace of what
they did. An ordinary log cannot prove its history is intact. tally records events in an append-only
chain, signs checkpoints, publishes them where the host cannot change them, and verifies offline,
pointing at exactly where and how the chain was violated. Personal data is sealed so it can be erased
without breaking the chain.

## The guarantee, stated honestly

> **tally detects tampering; it does not prevent it.** Given a trusted checkpoint obtained from outside
> the compromised host, any alteration, removal, insertion or reordering of entries covered by that
> checkpoint is detectable.

What that does not cover, in the terms you would otherwise assume:

- **Anything past the last anchored checkpoint**, against whoever holds the host and the key.
- **An event that was never submitted.** A heartbeat proves the signer ran, not that the log is complete.
- **A host-writable "anchor".** An anchor must be something the host holds no credential to alter. A
  directory mounted on the host runs fine, reports intact, and protects nothing.
- **Real time,** split view (until v0.2), and legal compliance. Crypto-shredding is a mechanism, and LGPD
  conformance depends on the operator's process and counsel.

The full list, with a residual for each threat, is in [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).

## Anchoring off the host

**A directory the host can write to is not an anchor.** Whoever has root on the host rewrites or deletes
it, and the protection against truncation, rollback, a rewrite with the key and a heartbeat gap goes
with it (T-05, T-07, T-08, T-15, T-21). `anchor.Dir` runs, reports intact, and on its own protects
nothing: it is a **create-only spool**, the host's half of an anchor. It never overwrites or deletes a
checkpoint, so that something off the host can take each one, once, to a place the host cannot reach.
The library cannot check that the other half exists (RS-17).

Each recipe below completes it. What makes it an anchor is the last column: the host holds no credential
that can change what it already published.

| Recipe | The host holds | The host cannot |
| --- | --- | --- |
| **Pull over rsync from another machine.** The anchor machine runs `rsync --ignore-existing` from the spool on a schedule, over SSH, into storage only it can write. | Nothing on the anchor machine. The anchor side holds an SSH key to the host, restricted to reading the spool (for example `rrsync -ro`). | Reach the anchor machine at all. It cannot alter or delete a copy already pulled. Between publication and the next pull, the checkpoint is as safe as the host. |
| **Push to a Git remote that refuses force pushes.** A job on the host commits new spool files and pushes. The server sets `receive.denyNonFastForwards` and `receive.denyDeletes`, or an equivalent branch protection. | A deploy key that can push. | Rewrite or delete history. It **can** push a commit that removes files from the tip, so the auditor reads every commit, never only the tip. |
| **Upload to a bucket with object lock.** A job on the host uploads each new spool file. The bucket has versioning and object lock in *compliance* mode, with a retention longer than your audit horizon. | A credential with `PutObject` only, and no delete, retention or governance-bypass permission. | Overwrite a version or delete it before its retention ends, not even with the account's root, in compliance mode. *Governance* mode can be bypassed by a privileged principal, and does not qualify. |

In each recipe, the auditor verifies against the copy off the host, with `tally.WithAnchor` over a `Dir`
opened on it. Read on the host, a spool says only what the host chose to leave there. The pull or upload
interval adds to the window in which the newest entries are unprotected.

## Personal data and crypto-shredding

The log is immutable, so personal data cannot be deleted from it. tally keeps people out of it instead:
a person enters only as a `SubjectRef`, 128 random bits from a vault (`seal`), and what identifies them goes
in a payload sealed under that subject's key. Destroying the key, a **shred**, makes those payloads
unreadable and leaves the chain intact, so the log still verifies.

**What each stored field holds** (SPEC §2.2). Everything except a sealed payload is in clear, for as long
as the log exists:

| Field | Stored | What it may hold |
| --- | --- | --- |
| `log_id`, `seq`, `prev_hash` | in clear | Nothing about a person, by construction. |
| `recorded_at` | in clear | The host's clock when the entry was written. |
| `occurred_at` | in clear | The caller's claim of when the action happened. A time a person acted is still metadata about them. |
| `event_id` | in clear | Random or opaque. Never derive it from personal data: a hash of an email is reversed by hashing guesses. |
| actor (`actor_kind`, `actor_id`) | in clear | A `SubjectRef`, a service name, or the system. A person enters only as a `SubjectRef` (RS-14). A service name refuses `@` and whitespace (RS-18), so it refuses an email, but not a CPF passed off as a service: that is digits. |
| `action` | in clear | A dotted lowercase name of what happened, never to whom. |
| `resource` | in clear | What was acted on. It must hold no personal data. RS-18 refuses `@` and whitespace, which catches an email but not a CPF, which is digits. |
| `outcome` | in clear | Success, failure, denied or error. |
| `subject_ref` | in clear | Whose sealed payload this is. |
| plain payload | in clear | Never personal data; seal it instead. |
| sealed payload | encrypted | The details: an IP, a user agent, an email, a reason. A shred makes it unreadable. |

**What a shred does not do.** tally provides a mechanism. It does not make a deployment conform to the LGPD
or any other law: that depends on the operator's process and must be validated with legal counsel.

- **The ref still links the subject's entries to each other.** A shred removes the mapping from the ref to
  the person, not the entries. Their actions, resources and timing remain, and a pattern can re-identify
  someone, so what remains may still be personal data (T-20).
- **A vault backup from before the shred undoes it.** The backup still holds the key.
- **Deleting a file does not destroy its bytes** on an SSD or a journaling filesystem. A wrapped key
  recovered from the medium, together with a later compromise of the KEK that wrapped it, opens the
  payloads again. Rotating the KEK, and destroying the old one, narrows this; it does not close it.
- **Copies in memory are out of the library's control.** A plaintext held by the application, swapped to
  disk, or left behind by the garbage collector is not erased by a shred, and Go cannot promise to erase
  any of it.
- **Whatever the application put in clear stays.** A `resource` or `event_id` that carries personal data,
  through a mistake RS-18 cannot catch, is in the log for good.

The procedure, and how to handle vault backups, is in the [RUNBOOK](docs/RUNBOOK.md#shredding-a-subject-draft-46).

## Documents

| | |
| --- | --- |
| [`REQUIREMENTS.md`](REQUIREMENTS.md) | What it must do, with the ids everything else cites, and the review record |
| [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) | Threats, mitigations and residuals |
| [`docs/SPEC.md`](docs/SPEC.md) | The format, enough to write an independent verifier |
| [`docs/architecture.md`](docs/architecture.md) | Packages, real signatures, flows |
| [`docs/adr/`](docs/adr/README.md) | Decisions, with the alternatives they rejected |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Git flow and commit format, checked by CI |
| [`SECURITY.md`](SECURITY.md) | Private vulnerability reporting |

## Part of an ecosystem, depending on none of it

tally imports no other library from this ecosystem, and that is enforced against the Go resolver.
Applications wire things together: [usher](https://github.com/JonasBorgesLM/usher) is the first
intended consumer, through an integration that still needs a decision on its side.

## License

[MIT](LICENSE).
