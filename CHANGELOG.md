# Changelog

Notable changes to tally. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). In v0.x a minor version may break the API, and
every such break is listed under **Changed** with a ⚠️ marker.

The release workflow will refuse to publish a tag with no section here.

## [Unreleased]

### Added

- README, "End to end": usher's one-command demo of the log, an anchor that pulls off the host, and a rollback the
  host's own spool accepts and the anchor detects (#55). The anchor there shares the machine; a second one is not
  yet run.
- README, "Mirroring to crier", and `Example_mirrorToCrier`: mirror only what `Append` confirmed, with no
  payload, and a lost mirror event loses no audit record (RI-03).
- `tally.NewSigner`, which loads the signer key `tally keygen` writes, so a consumer needs no `golang.org/x/mod`
  to sign a log. The key is held only in a closure and printed by no error or format verb (RS-07).
- The RUNBOOK, complete: monitoring off the host, host compromise, a poisoned log, disk full, prune, shredding a
  subject and vault backups, beside key rotation. Each procedure was executed by a drill in
  `cmd/tally/runbook_test.go`, through the CLI where it has a command, and says what it was executed against;
  the disk-full drill runs on a real 2 MB tmpfs in CI. A shred is now recorded by ref, so a restored vault
  backup can have every recorded shred applied again.
- README: usage, and the status of a pre-release instead of a design.

- Benchmarks for RNF-03 (`filestore/bench_test.go`): durable append by number of callers, reopening after a crash, and
  verifying a stored log, with the results recorded in `docs/BENCHMARKS.md` beside the hardware and Go version. CI
  compares base and head on every pull request in the job summary, without gating on the numbers. RNF-03 is amended:
  the batched-append and verify targets are met; `Append`'s p99 is stated as what it is made of, since one fsync on
  macOS already exceeds the provisional 5 ms.

- Fuzz targets for the checkpoint parser (`FuzzCheckpoint`, `FuzzCheckpointBody`) and the segment frame (`FuzzFrame`),
  beside the record decoder's, and a nightly workflow that fuzzes every target found, 30 minutes each, preserving
  any failing input as an artifact. The first run found a checkpoint `recorded_at` outside the range of int64
  nanoseconds accepted, and judged as another time; it is now malformed (SPEC §5.2).

- The attack suite (`attack/`): one test per threat, T-01 to T-23, each asserting the detection it must meet or,
  for a partial threat, the limit it documents. CI fails when a threat of the threat model has no test or a named
  test is missing, and the README's attack table is generated from the suite and checked current.
- T-23 in the threat model: deleting leading segments down to a checkpointed boundary is indistinguishable from a
  prune (ADR-0016); only the anchor and the operator's records tell them apart.

- README, "Personal data and crypto-shredding": what every stored field may hold and which are in clear, and each
  limit of a shred, without a claim of LGPD compliance. RUNBOOK: a draft procedure for shredding a subject, vault
  backups, and narrowing what the medium keeps.

- `FileVault.Shred`, now part of `seal.Vault`: destroys a subject's DEK, durably, and is idempotent. Payloads sealed
  under it then return `tally.ErrShredded`, the log still verifies, and a later `Resolve` makes a new, unlinked ref
  (RF-11, RF-12). Removing a file does not destroy its bytes on an SSD, and a vault backup undoes a shred.

- `seal.Vault`, `FileVault.Seal` and `Open`, and `seal.Payload`: AES-256-GCM under a subject's DEK, a random 96-bit
  nonce, and SPEC §4's length-prefixed AAD binding `log_id`, `event_id` and `subject_ref` (RS-12, RS-19). A shredded
  ref is `tally.ErrShredded`; any other mismatch is `seal.ErrOpen`. `seal.AAD` rebuilds the AAD to open a stored
  payload. The sealing vector `testdata/vectors/seal.json`.

- `seal.FileVault` (ADR-0020, SPEC §4.1): `Resolve` maps an identifier to a random 128-bit `SubjectRef` and a
  per-subject DEK, indexed by an HMAC under a vault key, the identifier stored nowhere; `RotateKEK` rewraps every
  DEK under a new KEK, resumably. `seal.KEK` is an interface, for a KMS; `seal.NewLocalKEK` is AES-256-GCM in
  process. No key reaches `fmt` or an error (RS-07).

- Requirements v0.3, threat model, format specification, architecture and ADR-0001 to ADR-0015. No library code.
- `filestore`: a `tally.Store` on the local filesystem, with segments, a checkpoints file, an exclusive lock
  (`tally.ErrLocked`), and fsync of file and directory before each write returns. A directory accessible
  to group or others is refused (`ErrLoosePermissions`) unless `WithLoosePermissions` is given. Segments
  rotate only at a checkpoint (ADR-0019), so `WithSegmentSize` is a target, not a bound.
- `filestore` recovers a torn tail on `Open`: the bytes after the last good frame of the last segment or
  the checkpoints file, or a last file shorter than its header, go durably to a quarantine file before
  anything is removed, and never below the last stored checkpoint (RF-20). `tally.Open` reports the count
  through `Observer.Recovered` for any `Store` implementing the new `tally.RecoveryReporter`.
- `tally.CheckpointSize`, which reads a stored checkpoint's size without verifying it.
- `filestore.WithFreeSpaceThreshold`: below it, `tally.Open`'s Log calls `Observer.DiskSpace` after every batch and
  checkpoint, through the new `tally.SpaceReporter`, so the warning comes before writes fail (RNF-10, T-16).
  `filestore.WithPreallocation` reserves each new segment's blocks on Linux, and fails `Open` with
  `ErrPreallocationUnsupported` on macOS, where it would need `unsafe`.
- A draft RUNBOOK entry for a full disk.
- `tally.MalformedError`: a `Source` reports stored bytes that break the format, and `Verify` turns it into a
  `MalformedRecord` violation at the first leaf not verified instead of its error (RS-04). `filestore` reports
  every format fault of a segment or the checkpoints file this way.
- `tally.WithAnchors`, `WithAnchorQueue` and `WithAnchorFlushTimeout`: every stored checkpoint is published to each
  `Anchor` from its own goroutine and bounded queue, so publication never blocks `Append` (RF-07). A full queue
  drops the oldest checkpoint but the newest, counts it, and reports `ErrAnchorQueueFull`; a failure is reported
  and retried with backoff; `Close` flushes up to a deadline and returns `ErrAnchorUnflushed` for what is left
  (RF-19). The `Observer` is never called concurrently, now that `AnchorPublish` can come from an anchor's goroutine.
- The `tally` command: `verify`, `head` and `checkpoint`, all read-only, with exit statuses 0 intact, 1 violation,
  2 usage or IO error (RF-13). `verify` prints the attested size and the unattested count and takes `--anchor`,
  `--require-fully-attested`, `--from` and `--heartbeat`. Every log-derived value printed is escaped, so control
  characters, ANSI sequences and newlines cannot reach the terminal or forge a line (RS-13, T-17).
- `tally.VerifyCheckpoint`, SPEC §5.4 applied to one checkpoint.
- `tally export`: JSONL of the stored records, decoded, with every text field escaped and opaque bytes in base64
  or hex (RS-13), or an audit bundle: a tar of the log directory, the anchor, the verifier keys and quarantine
  files, with a MANIFEST of SHA-256 hashes that says `quarantine none` when there is none (RF-15). `tally
  bundle-check` reports a bundle changed after export. The MANIFEST is not signed.
- `tally.DecodeRecord` and `RecordView`, a stored record's fields; `Outcome.String`.
- `tally prune`: prunes only at a checkpoint that verifies and that the anchor holds byte for byte (RS-20), and
  only with the log closed. `filestore.ErrPruneRefused` tells a refusal from an IO error.
- `tally keygen`: a signing key in SPEC §5.3's encodings, the private key at 0600 and printed nowhere, never
  overwriting an existing key.
- `anchor.Dir`, a create-only spool of checkpoints: each one is written once under a name derived from its bytes,
  linked into place so an existing file is never overwritten, and a republished identical checkpoint is success
  (RS-10, RS-17). It is the host's half of an anchor; the README gives recipes for the other half, and says
  what each one leaves the host unable to do.
- `filestore.OpenReader`, a read-only `Source` that never takes the lock, recovers or writes, for verifying a
  directory as it is, damage included.
- `filestore.Store.Prune` removes the segments wholly below a checkpoint that verifies and agrees with the
  log, after writing it to the prune marker `pruned.tlc` (SPEC §3.5, ADR-0012). It cannot tell whether the
  checkpoint was anchored (RS-20). `tally.Open` opens a pruned store, starting at its first record.
- `tally.LeafHash`, `tally.RecordLogID`, `tally.MaxRecordLen`, `tally.MaxCheckpointLen` and `tally.ErrLocked`,
  for a `Store` writing segment headers and checking lengths before allocating.
- SPEC §3.4, the checkpoints file, and the segment vector `testdata/vectors/segments.json`.

### Changed

- RI-05: tampering with a lab log is a script in usher's "Audit log" workflow, not warden, which tests
  over HTTP only; sapper's `/token` scenario is the load half (#54).

### Fixed

- `tally.Open` reopened a log its own last stored checkpoint contradicted, and its next checkpoint signed the
  rewritten history with the real key. It now compares the leaf at that checkpoint's size with its head, and the
  checkpoint's signature under the signer's key with the signer's own, and refuses with
  `ErrStoredCheckpointMismatch`. T-06 is now partial: a rewrite that deletes the checkpoints after it is still signed
  and verifies without an anchor, and the attack suite asserts it. Found by the clean-session audit (A-01, #126).
- `Verify` with a heartbeat could report a clean close as a crash, `HeartbeatGap`, when the closing checkpoint
  shared its size and its `recorded_at` with the last open one, as a clock regression makes it: the two were left
  in the anchor's order. They are now ordered open before closed (SPEC §7 step 6). Found by the RUNBOOK's
  monitoring drill, which failed 87 times in 200.
