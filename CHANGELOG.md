# Changelog

Notable changes to tally. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). In v0.x a minor version may break the API, and
every such break is listed under **Changed** with a ⚠️ marker.

The release workflow will refuse to publish a tag with no section here.

## [Unreleased]

### Added

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
