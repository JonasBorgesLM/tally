# tally — Requirements

**Version:** 0.3 (2026-11-03)
**Status:** baseline for implementation — no library code written yet

A Go library for **tamper-evident** audit logging: a hash chain, signed
checkpoints anchored off the host, offline verification, and crypto-shredding
for LGPD.

This document is binding. Every `RF-`, `RS-`, `RNF-` and `RI-` identifier below
is cited from commit messages, ADRs, godoc and tests.

> **A requirement without a test that fails when the protection is removed
> counts as unimplemented.**

Cross-project citations are written qualified — `usher/RI-03` — so they are not
silently checked against this project's numbering.

---

## 0. Review record

v0.1 and v0.2 were Portuguese drafts. v0.2 recorded a first review (R-01 to
R-21) and eight proposals awaiting approval. v0.3 records their approval and a
second review (R-22 to R-38), which checked v0.2 against the real `usher` code,
the C2SP specifications and the `foundation` method.

Ids changed in v0.3. `A1` meant both an attack and the audit phase, and `T0`
read like a threat id, so attacks are now threats `T-01`…`T-22` and phases are
milestones `M0`…`M11`. The kit's `check-docs.sh` resolves `T-nn`.

### 0.1 Findings

| ID | Sev. | Finding | Handled in |
| --- | --- | --- | --- |
| R-01 | HIGH | Anchor deferred while the signing key sits on the host: whoever takes the host takes the key | RF-07, ADR-0006 |
| R-02 | HIGH | Uniform fail-closed blocks revocation when audit fails, so a compromised token stays valid | §11.2, ADR-0010 |
| R-03 | HIGH | Global-secret HMAC of an enumerable space (CPF ~10⁹), and `actor` in clear | §9, ADR-0011 |
| R-04 | HIGH | No handling of fsync failure or directory fsync (fsyncgate) | §10.4, ADR-0009 |
| R-05 | MED | crier as an audit *source* contradicts audit semantics | RI-03 |
| R-06 | MED | Unspecified encoding; `binary.Uvarint` accepts `0x80 0x00` as `0` | RS-02, ADR-0003 |
| R-07 | MED | AAD with `seq` forces sealing into the writer goroutine | RS-12, RS-19 |
| R-08 | MED | Private checkpoint format, entry hash unrelated to the future Merkle tree | ADR-0004, ADR-0005 |
| R-09 | MED | Cancellation leaves an ambiguous outcome | §10.3, ADR-0010 |
| R-10 | MED | No retention; deleting segments would break verification | RF-14, ADR-0012 |
| R-11 | MED | The verifier binary is a root of trust with no supply-chain protection | §13, ADR-0014 |
| R-12 | MED | The CLI prints attacker-controlled fields | RS-13 |
| R-13 | MED | A full disk denies every fail-closed action | RNF-10, T-16 |
| R-14 | MED | `recorded_at` regression treated as a warning | RF-03 |
| R-15 | MED | An attacker can simply stop logging | RF-06, T-15 (see R-24) |
| R-16 | LOW | Too many public packages | `docs/architecture.md` |
| R-17 | LOW | `Store.Sync` separate from append invites misuse | `docs/architecture.md` |
| R-18 | LOW | Failure policy inside the library | ADR-0010 |
| R-19 | LOW | Free-form `key_id` | §8.4 |
| R-20 | LOW | Free-form `action` and `outcome` | RF-02 |
| R-21 | LOW | Security policy arrived after launch on moat | §13 |
| R-22 | HIGH | A directory mounted on the host is in the host's domain: root rewrites the "anchor", and T-05, T-07, T-08, T-15 fall | RS-17, T-21, ADR-0006 |
| R-23 | HIGH | `OK()` overclaims: the leaf hash is not stored, so the tail past the last checkpoint is unprotected even from an attacker without the key | RF-18, ADR-0001 |
| R-24 | HIGH | A heartbeat proves the signer is alive, not that the log is complete; tlog-checkpoint has no time line, so the v0.2 move breaks it | T-15, ADR-0006 |
| R-25 | HIGH | usher's `audit.Emitter` returns no error and must not block, and `usher/ADR-0017` rejected failing closed; the policy here is not "just an adapter" | RI-02 |
| R-26 | MED | `Store` has nowhere for checkpoints, `Anchor` has no read path, several types undefined | `docs/architecture.md` |
| R-27 | MED | `size` does not say whether genesis counts, which misaligns v0.2 leaf indices | §8.2, ADR-0004 |
| R-28 | MED | Mutation tests pass on the CRC without reaching the hash chain | §12 |
| R-29 | MED | A repeated `EventID` with different content silently returns success; no size limit on it | RF-02, RF-17 |
| R-30 | MED | Recovery cannot tell a torn write from a flipped bit in an acknowledged entry | RF-20, T-22 |
| R-31 | MED | After a failed fsync the page cache may show data not on disk, and reopen trusts it | ADR-0009 |
| R-32 | MED | R-10 says "anchored", RF-14 says "given"; the library cannot prove anchoring | RS-20, ADR-0012 |
| R-33 | MED | Go 1.24 no longer receives security fixes | RNF-01 |
| R-34 | MED | Shred limits understated: refs still link entries, deletion on SSD, no KEK rotation, ambiguous AAD, `Service("a@b")` type-checks | RS-18, RS-19, T-20, ADR-0011 |
| R-35 | MED | Anchor queue has no overflow or `Close` policy | RF-19 |
| R-36 | LOW | Colliding ids (`A1`, `T0`) and three-digit ADRs | this section |
| R-37 | LOW | The 85% coverage gate contradicts `foundation`'s rule against coverage thresholds | RNF-07 |
| R-38 | LOW | Module path availability | resolved: repository exists, no module at that path |

### 0.2 Decisions approved in v0.3

| ID | Decision | Amended by the second review |
| --- | --- | --- |
| P1 | Minimal anchor and heartbeats in the MVP | The anchor must be unalterable from the host (R-22); heartbeat detection is partial (R-24) |
| P2 | Failure policy follows privilege direction, decided in usher | Requires a new ADR in usher that supersedes `usher/ADR-0017` (R-25) |
| P3 | Vault with random refs and a typed `Principal` | Charset guard, canonical AAD, stated limits (R-34) |
| P4 | C2SP signed-note, RFC 6962 leaf hash | Genesis is leaf 0 (R-27) |
| P5 | crier is an optional mirror; adapters live with the consumer | — |
| P6 | Retention through `Prune` limited to an anchored checkpoint | The library verifies the signature, the CLI compares with the anchor (R-32) |
| P7 | No `SyncInterval`, no failure policy in the library; IO errors poison | Residual after a failed fsync recorded (R-31) |
| P8 | CLI release with reproducible build, signed checksums, SBOM, provenance | — |

---

## 1. Overview

### 1.1 Problem

Whoever compromises a host, or an insider with privileged access, tries to erase
or alter the trace of what they did: a suspicious login, a revocation, a key
rotation, a role change. Ordinary logs cannot prove their history is intact.

### 1.2 Goal

A small, well-finished Go library that:

1. records events in an append-only **hash chain**;
2. emits **signed checkpoints** and publishes them **off the host** (the anchor);
3. allows **offline verification** (library and CLI) that says exactly where and
   how the chain was violated;
4. allows **erasing personal data without breaking the chain** (crypto-shredding);
5. has retention that preserves verifiability;
6. integrates with the ecosystem **with no core-to-core coupling**.

### 1.3 The honesty principle

tally **detects** tampering; it does not prevent it. The guarantee is conditional
and is written that way:

> *Given a trusted checkpoint obtained from outside the compromised host, any
> alteration, removal, insertion or reordering of entries covered by that
> checkpoint is detectable.*

It says nothing about entries past the last trusted checkpoint (RF-18). Without
an anchor, the library only detects tampering by someone without the signing
key, and only over entries a checkpoint covers.

### 1.4 Design principles

- **The safe path is the easy path:** types that prevent mistakes (`Principal`,
  `Outcome`, validated `Action`), safe defaults, no implicit insecure mode.
- **Fail loudly:** an IO error poisons the log; verification fails closed; nothing
  is silently repaired.
- **Spec first:** `docs/SPEC.md` is enough to build an independent verifier.
- **Core without dependencies;** small interfaces, defined by the consumer.
- **Small scope:** what is not essential to the MVP is explicitly deferred.

### 1.5 Non-goals

| Not this | Owner instead |
| --- | --- |
| SIEM or query engine | The operator's tooling, fed by `export` |
| Blockchain, consensus, server | Out of scope (library and CLI only) |
| Preventing deletion | The anchor makes deletion detectable, not impossible |
| Observability | crier |
| Failure policy (open or closed) | The application (§11.2) |
| Multiple witnesses and gossip | v0.2 and later |

---

## 2. Actors

| Actor | Role | Assumed capability | Assumed *not* to have |
| --- | --- | --- | --- |
| Application | Writes events through `Append` | Runs the writer, usually holds the signing key | Write access to the anchor's history |
| Host attacker | Controls the application's host | Root: log, key, clock, process memory | Credentials to alter what the anchor already holds |
| Insider | Privileged operator | As the host attacker, often legitimately | As the host attacker |
| Auditor | Runs `tally verify` elsewhere | Trusted public keys, a verified binary, the anchor | Trust in anything read only from the host |
| Data subject | Whose data is recorded | May request erasure | Any access to the log |

---

## 3. Threat summary

The threat model is [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md). Its one-line
result: **the MVP's security depends on the anchor being outside the host's
domain**, meaning the host holds no credential that can alter or delete what the
anchor already has (RS-17).

---

## 4. Glossary

- **Entry:** a chained audit record.
- **Leaf hash:** the entry's hash in RFC 6962 leaf form, `SHA-256(0x00 || entry_bytes)`.
- **Head:** the last record. **Size:** the number of leaves, genesis included, so
  `size = head_seq + 1`.
- **Checkpoint:** a C2SP signed note declaring `origin`, `size`, `head` and `time`.
- **Anchor:** a destination off the host, unalterable from the host, holding checkpoints.
- **Attested:** covered by a trusted checkpoint. **Tail:** entries past the last one.
- **Heartbeat:** a checkpoint emitted on a timer, even with no new entries.
- **Origin:** the log's unique textual identity (`tally.local/usher-prod-1`).
- **Principal:** who acted: a subject, a service, or the system.
- **Subject / SubjectRef:** the data subject / a random reference to them.
- **Vault:** holds DEKs and the subject index. **Shred:** destroys both for a subject.

---

## 5. Functional requirements

| ID | Requirement |
| --- | --- |
| **RF-01** | `Append` returns `Receipt{Seq, LeafHash, Duplicate}` only once the entry is durable |
| **RF-02** | Events are validated: `Action` matches `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$` up to 128 bytes; `Outcome` is an enum; `Resource` has a restricted charset up to 256 bytes; `EventID` is required, up to 128 bytes; a service name is up to 256 bytes; payload up to 64 KiB (configurable) |
| **RF-03** | `occurred_at` comes from the caller; `recorded_at` comes from the log's `Clock` and is **monotonically non-decreasing** (clamped to the previous value, with the regression reported to the `Observer`) |
| **RF-04** | Idempotency by `EventID` over a configurable window (default 10,000 entries), rebuilt on open. A duplicate returns the original `Receipt` with `Duplicate=true` |
| **RF-05** | Genesis is a special record, leaf 0 with `seq = 0`, carrying a random `log_id`, `origin`, format version and creation time |
| **RF-06** | Checkpoints are signed every N entries, every T of time (a heartbeat, even with no entries), on segment rotation, on demand and on `Close`. Defaults: 1,000 entries or 60 s |
| **RF-07** | Each checkpoint is published to the configured `Anchor`s asynchronously; a publication failure alarms through the `Observer` and never blocks `Append` |
| **RF-08** | `Verify` is full or incremental from a trusted checkpoint, in streaming |
| **RF-09** | `Verify` accepts checkpoints from the anchor and detects truncation, rollback, fork and a missing heartbeat (a gap above `T + tolerance`). "Now" is supplied by the caller. A checkpoint from a clean `Close` carries `closed` and what follows it is not a gap |
| **RF-10** | A verifier set with several keys allows rotating the signing key; unknown signatures are ignored as the signed-note spec requires, but a checkpoint with no trusted signature is a failure |
| **RF-11** | `seal`: the vault resolves an identifier to a random `SubjectRef`, seals and opens payloads; `Shred` is idempotent |
| **RF-12** | Reading a sealed entry after a shred returns `ErrShredded` and does not affect verification |
| **RF-13** | CLI `tally` with `verify`, `head`, `checkpoint`, `export`, `keygen` and `prune` |
| **RF-14** | `filestore.Prune(cp)` removes only segments wholly below a checkpoint and writes a prune marker; later verification requires that checkpoint as trusted |
| **RF-15** | `export` produces JSONL or an **audit bundle** (segments, checkpoints, public keys, quarantined bytes and a manifest of hashes) |
| **RF-16** | `Observer`, with no external dependency: appends, batch size, fsync latency, anchor publication, disk space, clock regression, poisoning, recovery. It never receives payload, and must not block |
| **RF-17** | A repeated `EventID` whose metadata differs (actor, action, resource, outcome, payload kind, the subject a sealed payload is for, and the bytes when plain) returns `ErrEventConflict` and records nothing. Sealed bytes are excluded, because a random nonce makes each retry differ; the subject is not random, so it is compared |
| **RF-18** | `Report` separates `AttestedSize` from `UnattestedEntries`; `OK()` speaks only to what was checked; `WithRequireFullyAttested` makes an unattested tail a failure |
| **RF-19** | The publish queue is bounded. On overflow it drops the oldest checkpoint other than the newest, counts it and alarms. `Close` flushes with a deadline |
| **RF-20** | Recovery moves truncated bytes to a quarantine file and reports them; it never deletes them, and never truncates below the last local checkpoint |

### 5.1 Verification result

`Verify` returns `(*Report, error)`. The `error` only means **verification was not
possible** (IO, misuse); an integrity violation is in the `Report` with
`OK() == false`. This separation stops a caller reading "could not read" as
"intact".

Failure kinds: `PrevHashMismatch`, `SeqGap`, `SeqRegression`, `TimeRegression`,
`NonCanonicalEncoding`, `MalformedRecord`, `BadSignature`, `UnknownKey`,
`CheckpointMismatch`, `TruncatedBelowCheckpoint`, `ForkDetected`, `HeartbeatGap`,
`PrunedWithoutTrustedCheckpoint`.

v0.2's `LeafHashMismatch` is removed: the leaf hash is not stored, so there is
nothing to compare it with. A changed entry surfaces as `PrevHashMismatch` on its
successor or `CheckpointMismatch` at a checkpoint (R-23).

CLI exit codes: `0` intact · `1` violation · `2` usage or IO error.

---

## 6. Security requirements

| ID | Requirement |
| --- | --- |
| **RS-01** | Domain separation: RFC 6962 leaf (`0x00`), interior node reserved for v0.2 (`0x01`), sealing tagged `tally/v1/seal`, checkpoints in the signed-note envelope |
| **RS-02** | Strict encoding: fixed-width big-endian integers, no varint; the decoder rejects trailing bytes, unknown version, unknown type and invalid UTF-8; every decoded record is re-encoded and compared byte for byte |
| **RS-03** | The verifier hashes bytes **as stored**, never a reconstruction |
| **RS-04** | `Verify` fails closed: any parse error is a violation, nothing is skipped |
| **RS-05** | Size limits on decoding, applied **before** allocating |
| **RS-06** | tally's signing key differs from every usher key. `Signer` is an interface, allowing a separate process or a KMS |
| **RS-07** | Private keys, DEKs and the KEK never appear in an error, a log or `%v`/`%+v` (a redaction type of its own, with `fmt.Formatter`) |
| **RS-08** | `crypto/subtle` for comparing secret values; public hashes need no constant-time comparison, a decision that is documented |
| **RS-09** | One writer per log: exclusive, non-blocking `flock`; a second open fails with `ErrLocked` |
| **RS-10** | Files at `0600`, directories at `0700`, genesis created with `O_EXCL`, auxiliary files written atomically (tmp, fsync, rename, directory fsync) |
| **RS-11** | No `unsafe` anywhere, and no reflection in the encoding and hash path |
| **RS-12** | Sealing with AES-256-GCM, a per-subject DEK, a random 96-bit nonce (volume per key stays far below the safe limit), and AAD binding the tag, `log_id`, `event_id` and `subject_ref` |
| **RS-13** | The CLI removes or escapes control characters and ANSI sequences from every log-derived field before printing |
| **RS-14** | No API accepts a human identifier in clear as a `Principal`; humans enter only through `SubjectRef` |
| **RS-15** | `Open` fails if the directory's permissions are looser than expected (an explicit option relaxes it) |
| **RS-16** | The final audit runs in a **clean session**, by someone who did not write the code |
| **RS-17** | An anchor must be unalterable from the log's host: the host holds no credential that can modify or delete what it already published. `anchor.Dir` is a create-only spool, and the documentation states that a host-writable directory alone gives no protection. **Partial:** the library cannot check this property of a deployment |
| **RS-18** | Service names and `Resource` reject `@` and whitespace. **Partial:** this catches the common way an identifier leaks into clear text, not all of them; a CPF is digits |
| **RS-19** | The AAD is length-prefixed in the wire encoding, not concatenated, so a boundary cannot shift between fields |
| **RS-20** | `Prune` refuses a checkpoint whose signature does not verify; the CLI's `prune` also requires it to be present in the anchor. **Partial:** the library alone cannot prove a checkpoint was anchored |

---

## 7. Non-functional requirements

| ID | Requirement |
| --- | --- |
| **RNF-01** | Go 1.26 floor, the oldest release still receiving security fixes, and CI tests the floor and `stable`. Core is stdlib only (`crypto/*`, `hash/crc32`, `syscall`, …). A library's `go` line is a promise about who can import it, and a crypto library should not promise support for a toolchain nobody patches (R-33) |
| **RNF-02** | Modules: `tally` (core, `filestore`, `seal`, `anchor`, `tallytest`, CLI) and `interop` (tests only, may depend on `golang.org/x/mod`) |
| **RNF-03** | **Provisional** targets, to be measured: batched append ≥ 10k entries/s on NVMe; `Append` p99 ≤ 5 ms with a 2 ms `MaxDelay`; verify ≥ 100k entries/s per core. Also measured on a Raspberry Pi |
| **RNF-04** | `Verify` uses O(1) memory in log size, plus the checkpoint window |
| **RNF-05** | Small public API; details in `internal/`; godoc and `ExampleXxx` in every public package; no global state |
| **RNF-06** | `*Log` is safe for concurrent use; `Close` is idempotent; no goroutine leaks after `Close`, verified by test |
| **RNF-07** | Coverage is measured and reported, with attention to error and recovery branches, and is **not** a gate: a threshold is a number gamed by testing what is easy (R-37). The gate is RS-04's negative controls and the attack suite |
| **RNF-08** | Documentation: `README.md`, `docs/SPEC.md`, `docs/THREAT-MODEL.md`, `docs/architecture.md`, `docs/RUNBOOK.md` (key rotation, compromise, disk full, shred, prune), `docs/adr/`, `testdata/vectors/` |
| **RNF-09** | Linux and macOS (Go's `File.Sync` uses `F_FULLFSYNC` on macOS since Go 1.12). Windows is out of scope |
| **RNF-10** | Optional segment preallocation and a free-space threshold reported to the `Observer` |
| **RNF-11** | `Clock`, randomness source and filesystem are injectable for tests |

---

## 8. Format

The normative version is [`docs/SPEC.md`](docs/SPEC.md); this is the shape.

### 8.1 General rules

Fixed-width big-endian integers. Bytes and strings are a `uint32` length then
content; strings are valid UTF-8 and not normalised. Fields in a fixed order, no
implicit optional fields. `version` first; an unknown version is a failure.

### 8.2 Entry (v1)

`version, type, log_id, seq, recorded_at, occurred_at, event_id, actor_kind,
actor_id, action, resource, outcome, payload_kind, subject_ref, payload,
prev_hash`.

`leaf_hash = SHA-256(0x00 || entry_bytes)`, exactly the RFC 6962 leaf. Genesis is
leaf 0 (`seq = 0`), and the first entry has `seq = 1` with genesis's leaf hash as
`prev_hash`. `size = head_seq + 1`, so at v0.2 the Merkle tree is built over the
same leaves with the same indices.

### 8.3 Segments

`NNNNNNNNNNNNNNNN.tlog` (first `seq` in hex). Header with magic, version, `log_id`,
first `seq` and `prev_hash`. Records framed `uint32 len || body || crc32c(body)`.
The CRC detects partial writes and accidental corruption; it is **not** a security
mechanism. Rotation by size; each rotation emits a checkpoint and syncs the
directory.

### 8.4 Checkpoint (C2SP signed-note)

MVP body:

```
<origin>
tally-chain/v1
<size>
<base64(head_leaf_hash)>
<recorded_at RFC 3339>
<open | closed>
```

Line 2 deliberately stops a `tlog-checkpoint` parser from reading this as a tree
head: a hash chain head is not a Merkle root. Signed with Ed25519, with the key id
derived from name and public key per the spec. At v0.2 the body becomes
`tlog-checkpoint`, which has no time line (R-24, ADR-0006).

---

## 9. Crypto-shredding (LGPD)

### 9.1 Problem

The log is immutable, yet personal data must be erasable. Deleting the entry breaks
the chain; pseudonymising with a global secret is reversible by enumeration.

### 9.2 Model

- The vault maps `identifier → random SubjectRef (128 bits) + DEK`. Its index is
  `HMAC(vault_key, identifier)` and is never in the log.
- Only the `SubjectRef` appears in the log: as the `actor` and/or the owner of a
  sealed payload.
- `Shred(ref)` deletes the DEK **and** the index entry.
- After a shred, `Resolve(identifier)` creates a **new incarnation** (new ref, new DEK).

### 9.3 API

Signatures are in [`docs/architecture.md`](docs/architecture.md). Sealing runs on the
caller's goroutine, before `Append`, without contending for the writer.

### 9.4 Field classification

| Field | In clear? | Note |
| --- | --- | --- |
| `seq`, times, `action`, `outcome` | yes | security metadata |
| `actor` | yes, as `SubjectRef` or service name | never email, CPF or login (RS-14, RS-18) |
| `event_id` | yes | must be random or opaque, never derived from personal data |
| `resource` | yes | must hold no personal data (RS-18 is a partial guard) |
| details (IP, user agent, email, reason) | no | sealed payload |

### 9.5 Trust domain

The vault belongs outside the log's domain: another directory and credential,
preferably another host. A vault backup older than the shred undoes the shred, and
the runbook has to address it.

### 9.6 Limits

Stated rather than discovered later:

- A shredded ref still **links that subject's entries to each other**. Pattern and
  timing may re-identify a person, so the remaining metadata may still be personal
  data (T-20).
- Deleting a file on an SSD or journaling filesystem does not destroy it. A wrapped
  DEK recovered from the medium plus a later KEK compromise undoes a shred; KEK
  rotation narrows this and does not close it.
- Plaintext copies in memory, swap and GC are outside the library's control, and Go
  does not guarantee zeroisation.
- The library delivers a **mechanism**. LGPD conformance depends on the operator's
  process and must be validated with legal counsel.

---

## 10. Go architecture

Layout, signatures and flows are in [`docs/architecture.md`](docs/architecture.md).

### 10.3 Concurrency and `Append` semantics

- One **writer goroutine** assigns `seq`, computes `prev_hash`, builds the batch and
  calls `AppendBatch` (group commit, `MaxBatch`, `MaxDelay`).
- Validation and sealing run on the caller's goroutine.
- `ctx` cancelled **before** enqueueing returns `ctx.Err()`. Cancelled **after** returns
  `ErrOutcomeUnknown`: the entry may or may not be stored, and the caller retries with
  the same `EventID`.
- The library does not choose failing open or closed: `Append` always reports the real
  error and the application applies its policy.

### 10.4 Durability

- `AppendBatch` writes the batch, fsyncs the file, and fsyncs the directory on creation
  or rotation.
- **Any** write or fsync error poisons the log: every later `Append` returns
  `ErrPoisoned`, and recovery means closing and reopening, with the tail verified. There
  is no fsync retry.
- There is no interval durability mode: an acknowledged entry that is then lost would
  falsify the library's promise.
- **Residual (R-31):** after a failed fsync the page cache can show data that never
  reached the disk, and reopening in the same boot trusts it. After `ErrPoisoned`, treat
  the most recent data as suspect and verify after a restart (ADR-0009).

### 10.5 Recovery

On open: take the lock, validate header and CRC record by record in the last segment,
quarantine **only** a partial record at the tail of the last segment (RF-20), check the
tail's chain against the last local checkpoint, rebuild the idempotency window. Any
inconsistency mid-chain fails the open.

### 10.6 Anchor

- Checkpoints go through a bounded publication queue with retries (RF-19).
- `anchor.Dir` is a create-only spool that something **off the host pulls from** (RS-17).
  Mounting another machine's directory on the host is not an anchor: the host can rewrite
  it.
- The README carries recipes in which the host holds no destructive credential: a pull
  by `rsync` from another machine, a Git remote that refuses force pushes, a bucket with
  object lock.
- Remote destinations can wrap `Anchor` in bastion (RI-04); that lives in the application.

---

## 11. Ecosystem

### 11.1 Dependency rules

**RI-01** tally imports no ecosystem library, and:

1. Whoever owns the interface hosts the adapter: the interface lives with the consumer.
2. Wiring happens in applications (usher, task-api, beacon), in `main` or a wiring package.
3. A little copying beats a dependency: the ~30-line secret redaction type is
   reimplemented rather than importing moat's `secret`.
4. Rule of three for extracting shared code: the segment WAL does not become a library
   until a third real consumer exists.

### 11.2 usher

**RI-02** usher integrates through a port it owns and an adapter in its own repository,
with a new usher ADR superseding the relevant part of `usher/ADR-0017`.

**What exists today:** `audit.Emitter` has `Emit(ctx, e)`, with no error and a contract
that it must not block; `usher/RI-03` ships events to crier and drops on overflow;
`usher/ADR-0017` rejected failing closed, because it couples availability to a log
pipeline. `Event.Subject` is a canonical identifier in clear, and event types are
`token_issued`-style names. None of that survives the policy below unchanged, so **the
decision is usher's to make** (#51). Recommended shape: a second, synchronous,
error-returning port beside `Emitter`, which stays as the crier path.

Policy by direction of privilege:

| Action | Direction | If audit fails |
| --- | --- | --- |
| issue or renew a token, grant a role, create a client, consent, activate a key | grants | **deny** the action (fail closed) |
| revoke a token, log out, lock an account, remove a role | reduces | **execute**, alarm and retry with the same `EventID` |
| failed login, rate-limit block | informational | execute and alarm |

Residual: a revocation executed during an audit failure may go unrecorded if the process
dies before the retry. Accepted for the MVP; reopen if a spool is demanded by an audit
finding or a real loss.

`EventID` is generated **before** the action and reused in retries. tally's signing key
is never usher's token key (RS-06). Each usher replica has its own log and `origin`.

### 11.3 crier

**RI-03** crier is **not** an audit source: its buffer can drop (`crier/IR3`, `usher/RI-03`).
Applications may mirror events **already confirmed** by tally, with no payload, for
dashboards and alerts.

### 11.4 Other projects

- **RI-04** bastion wraps `Anchor.Publish` to a remote destination, in the application,
  and **never** `Append`: a poisoned log is not fixed by retrying.
- **RI-05** warden tampers with a lab service's log and checks the `verify` report; sapper
  measures `Append` latency under load through usher and asserts the p99 SLO. Authorised
  targets only.
- **RI-06** task-api is a secondary consumer (task changes and administrative actions).
  moat has no dependency either way. beacon and granary have no relation in the MVP.

---

## 12. Test strategy

1. **Attack suite:** one test per threat in the threat model; the README table is
   generated from the results. Partial threats assert their limit as well.
2. **Exhaustive mutation:** alter each byte of a small valid log, **recomputing the CRC**,
   and require a verification failure. Without recomputing, the CRC catches the change
   and the hash chain is never tested; an attacker recomputes CRC32C (R-28).
3. **Strictness:** non-minimal encodings, trailing bytes, invalid UTF-8, unknown version
   and type, over-limit sizes are all rejected.
4. **Property tests:** encoding is injective; decode after encode is the identity; `Verify`
   of any honest sequence of `Append` is intact.
5. **Native fuzzing:** record decoder, checkpoint parser, segment frame.
6. **Fault injection** with `tallytest.FaultyStore` and the injectable filesystem: failure
   and truncation at every offset, fsync error (must poison), disk full.
7. **Concurrency** with `-race` and `-shuffle=on`: `seq` unique and ordered, no goroutine
   left after `Close`.
8. **Context semantics:** cancellation before and after enqueueing, retry with the same
   `EventID`.
9. **Shredding:** a shred preserves `Verify`; `Open` after it returns `ErrShredded`; a
   changed AAD fails; a new incarnation has a different ref.
10. **Differential** in `interop`: checkpoints validated against `golang.org/x/mod/sumdb/note`.
11. **Fixed test vectors** for independent implementations.
12. **Benchmarks:** append by batch size, verify, recovery; on NVMe and a Raspberry Pi.
13. **End-to-end:** usher to tally to anchor to `tally verify`.

---

## 13. Engineering, release and supply chain

- **From the first commit:** `SECURITY.md`, private vulnerability reporting, rulesets,
  Dependabot, OpenSSF Scorecard.
- **CI:** build, vet, golangci-lint (which runs staticcheck), gosec, govulncheck, tests with
  `-race -shuffle=on`, short fuzz on pull requests and a long scheduled campaign, coverage
  reported, benchmarks compared.
- **CLI release:** reproducible build (`-trimpath`, embedded version), signed checksums,
  SBOM, provenance attestation. The verifier is the auditor's root of trust.
- **Release checklist** (lessons from moat): `go install` and `go get` in a clean room from
  the tag, `go.mod` checked before tagging, signed tags, CHANGELOG from a real API diff, a
  documented `retract` plan.
- **Clean-session audit** before v0.1.0 (RS-16).

---

## 14. Milestones

Issues are on the [project board](https://github.com/users/JonasBorgesLM/projects/9).

| Milestone | Delivers | Acceptance |
| --- | --- | --- |
| M0 Foundations | Repository, CI, repository security, SPEC v1, threat model, architecture, ADRs | Spec independently reviewed; pipeline green |
| M1 Wire format | `internal/wire`, entry, genesis, leaf hash, vectors | Mutation, strictness, property tests green |
| M2 Log core | `Log` over `MemStore`: writer, group commit, validation, idempotency, poisoning, `ctx` | §12 items 7 and 8 green |
| M3 Checkpoints and Verify | `internal/note`, checkpoints, heartbeat, `Verify`, `interop` | T-05 to T-08, T-10, T-15 green; differential passes |
| M4 filestore | Segments, `flock`, directory fsync, recovery, `Prune` | Fault injection at every offset; fsync error poisons |
| M5 Anchor and CLI | Publish queue, `anchor.Dir`, CLI | T-17, T-21 green; exit codes stable |
| M6 seal | `FileVault`, sealing, shred, incarnations | §12 item 9 green; T-19, T-20 green |
| M7 Attack suite | Attack suite, fuzz campaigns, benchmarks, RUNBOOK, README table | T-01 to T-22 in CI; RNF-03 measured |
| M8 Integration | usher ADR, port, adapter; crier mirror; sapper and warden scenarios | Runnable end-to-end example |
| M9 Audit | Clean-session audit | Findings fixed or accepted with a reason |
| M10 v0.1.0 | Release through §13's checklist | Signed tag; verifiable binaries |
| M11 v0.2 | Merkle tree, tlog-checkpoint, proofs, witness | Consistency verified; T-09 addressed |
| Later | Forward-secure MAC chain, RFC 3161, post-quantum signatures, `sqlstore` | To be defined |

---

## 15. Decisions

Recorded in [`docs/adr/`](docs/adr/README.md).

---

## 16. Questions from v0.2, answered

| # | Question | Answer | Owner if open |
| --- | --- | --- | --- |
| 1 | Default checkpoint and heartbeat interval | 1,000 entries or 60 s (RF-06) | — |
| 2 | Demo anchor | A second Raspberry Pi pulling over `rsync`; it also proves the host holds no destructive credential | #55 |
| 3 | Signer in a separate process in the MVP | No; in process, behind the interface (ADR-0015) | — |
| 4 | Private key file format | The signed-note key encoding, file at `0600` (ADR-0005) | — |
| 5 | usher's initial action catalogue | Reviewed against the real repository in usher's ADR | #51 |
| 6 | Reducing events when the process dies before the retry | Accept and document for the MVP (§11.2) | #51 |
| 7 | Default limits | RF-02 and RF-04 | — |
| 8 | Name availability | Resolved (R-38) | — |

---

## 17. References

- C2SP signed-note and tlog-checkpoint (c2sp.org).
- RFC 6962 / RFC 9162 (Certificate Transparency).
- `golang.org/x/mod/sumdb/note` and `tlog`.
- Trillian, Sigstore Rekor, the transparency-dev witness network.
- Crosby & Wallach, *Efficient Data Structures for Tamper-Evident Logging*.
- Schneier & Kelsey, *Secure Audit Logs to Support Computer Forensics*.
- PostgreSQL "fsyncgate" (fsync behaviour after an error on Linux).
- Go issue #26650 (`File.Sync` on macOS with `F_FULLFSYNC`).
- RFC 3161; LGPD documentation (validate the interpretation with legal counsel).
