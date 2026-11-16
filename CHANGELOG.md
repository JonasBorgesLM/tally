# Changelog

Notable changes to tally. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). In v0.x a minor version may break the API, and
every such break is listed under **Changed** with a ⚠️ marker.

The release workflow will refuse to publish a tag with no section here.

## [Unreleased]

### Added

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
- `filestore.Store.Prune` removes the segments wholly below a checkpoint that verifies and agrees with the
  log, after writing it to the prune marker `pruned.tlc` (SPEC §3.5, ADR-0012). It cannot tell whether the
  checkpoint was anchored (RS-20). `tally.Open` opens a pruned store, starting at its first record.
- `tally.LeafHash`, `tally.RecordLogID`, `tally.MaxRecordLen`, `tally.MaxCheckpointLen` and `tally.ErrLocked`,
  for a `Store` writing segment headers and checking lengths before allocating.
- SPEC §3.4, the checkpoints file, and the segment vector `testdata/vectors/segments.json`.
