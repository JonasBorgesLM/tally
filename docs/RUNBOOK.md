# tally runbook

Operating procedures, each executed once and each saying what it was executed against. The executions are
tests, so they run again on every pull request: `TestAKeyRotation` and the drills in
`cmd/tally/runbook_test.go`, which drive the `tally` CLI where it has a command and the library where it
does not, against real directories. A step outside software, such as isolating a host or telling an auditor,
is marked as not exercised.

Exit statuses of `tally verify`, `prune` and `bundle-check`: **0** intact, **1** violation, **2** could not
check (usage, IO, untrusted input). A monitor treats 2 as an alert too: a check that cannot run is not a
check that passed.

## Upgrading from v0.1

v0.2 signs each checkpoint as a pair of notes of one size (ADR-0006's amendment, SPEC §5.2): a
`tlog-checkpoint` (origin, size, Merkle root), which a witness cosigns, and a `tally-heartbeat/v1` note, which
carries the head, the time and the state as v0.1's checkpoint did, plus the root. Nothing stored is rewritten,
and a v0.2 verifier accepts v0.1's `tally-chain/v1` checkpoints beside the new pairs, in the log and in the
anchor. What an operator sees change:

- **Upgrade the verifier first.** A v0.1 `tally verify` reports every new note as `MalformedRecord` ("the body
  is not six lines") and exits 1, an alarm, though the log is intact; checked by running the v0.1.0 release on
  a v0.2 log. So every auditor and monitor moves to v0.2 before the writer does. A v0.2 verifier reads a v0.1
  log unchanged.
- **The anchor holds two files per checkpoint**, the `tlog-checkpoint` only when the size has grown:
  heartbeats at one size share one. Arrival monitoring (below) still sees a file every heartbeat.
- **The anchor queue counts notes.** `WithAnchorQueue`'s default of 64 now holds 32 checkpoints; size it for
  twice as many notes as before.
- **Prune and incremental verification start from a heartbeat note.** A `tlog-checkpoint` names no head, so
  `tally prune` refuses one and says so; take the `.note` file of the same size that says `tally-heartbeat/v1`
  on its second line. `tally checkpoint` prints the newest heartbeat note, and `--tlog` the newest
  `tlog-checkpoint`, for a witness.
- **`tally head` prints the root**, from leaf 0 or from the pruned range (SPEC §3.6). A log pruned by v0.1 has
  no range: its root is unknown, its writer keeps signing `tally-chain/v1` checkpoints, and its verifier
  compares heads only. Nothing about such a log gets weaker; it just gains no root.

### Executed against

`TestDrillUpgradeFromV01`: the bytes of a log a v0.1 writer wrote (`testdata/vectors/segments.json`), its
`tally-chain/v1` checkpoint in the anchor. The v0.2 writer reopened it, appended and closed, publishing one new
pair; segment 0 was the same bytes after, and `tally verify --anchor --require-fully-attested` reported all 8
leaves attested. `tally checkpoint --tlog` printed the new `tlog-checkpoint`. The order of the upgrade, verifiers
first, is a deployment step, not exercised.

## Key rotation

A log's checkpoints are signed with one key at a time (RS-06). Rotating replaces that key, for a
routine change or after a compromise. Two facts constrain every rotation:

- **The key's name is the log's origin, for the log's whole life** (SPEC §5.3, ADR-0005). A new key
  keeps the name; it changes only the key id. A log cannot move to another origin.
- **A checkpoint is worth something only under a key its verifier trusts** (RF-10). A checkpoint signed
  by a key the verifier does not have is `UnknownKey`, a failure, never a pass. So a verifier must keep
  every key that signed a checkpoint it still reads, from the store or from the anchor.

Keys are generated with `tally keygen --name ORIGIN --out PREFIX`, which writes `PREFIX.key` at mode
0600 and `PREFIX.pub`, refuses to overwrite either, and prints only the verifier key. For a rotation,
`ORIGIN` is the log's existing origin. `tally.NewSigner` loads the `.key` file's contents.
`golang.org/x/mod/sumdb/note`'s `GenerateKey` produces the same encodings (SPEC §5.3), and its `NewSigner`
also satisfies `tally.Signer`.

### Planned rotation

1. **Generate the new key under the same name**, the log's origin. Keep the private key at mode 0600,
   and never share it with another system's keys (RS-06).
2. **Publish the new verifier key to every verifier first**: auditors, and the side that pulls from
   the anchor. A checkpoint signed before they have the key is `UnknownKey` for them.
3. **Close the log.** `Close` signs a checkpoint with state `closed` under the old key, so the pause
   while you switch is not a `HeartbeatGap` (ADR-0006).
4. **Reopen the log with the new signer.** `tally.Open` checks the name against the stored origin;
   from here on, checkpoints carry the new key id.
5. **Verify with both keys**, `tally.NewVerifiers(old, new)`. The log verifies, fully attested.
   Keep the old key in every verifier set for as long as any checkpoint it signed is still read.

### After a key compromise

Whoever holds the old key can sign a fully consistent false history (T-07). Rotate at once, as
above, and then establish **when** the key was compromised. Of the checkpoints the old key signed,
only those an anchor received before that time are evidence, because the host could not alter
them (RS-17). Everything signed with the old key after it is worth nothing.

**What tally does not do for you here.** A verifier set has no time window per key. Keeping the old
key trusts every checkpoint it signed, the forged ones included; removing it turns every honest one
into `UnknownKey`. Telling them apart is the operator's job, using the anchor's own record of what
arrived when, until tally can bound a key's validity in time.

### Executed against

`TestAKeyRotation` (`rotation_test.go`). It runs steps 3 to 5 for real against a `tallytest.MemStore`:
two entries and their checkpoints under the old key, then two more under a new key with the same name.
It then verifies that:

- with both keys, the log is OK and fully attested;
- without the old key, the checkpoints it signed are `UnknownKey`;
- without the new key, the checkpoints after the rotation are `UnknownKey`.

Steps 1 and 2 are outside the library and were not exercised.

## Monitoring off the host

**Nobody notices a silent log from the host itself.** A host that stops signing, or whose attacker stops it,
reports nothing; whatever runs on that host to watch the log stops with it, or lies. Watching has to happen
where the anchor is, on the machine the host cannot reach (README, "Anchoring off the host").

The host signs a heartbeat checkpoint every period even with no entries (RF-06):
`tally.WithCheckpointEvery(n, period)`, a minute by default. A clean `Close` signs a `closed` checkpoint,
so a planned stop is not an alarm (ADR-0006). On the anchor machine, run two checks on a schedule, and alert
on either:

1. **Arrival.** A checkpoint file arrived within the period plus the pull interval plus some slack. Since
   v0.2, every heartbeat is a new heartbeat note, even when the size has not changed; only the
   `tlog-checkpoint` beside it waits for the size to grow:

   ```bash
   find /srv/anchor -name '*.note' -mmin -5 | grep -q . || alert "no checkpoint has arrived in 5 minutes"
   ```

   This reads the time each file *arrived* on the anchor side, which the host cannot set. It holds only if
   the pull does not copy the host's modification times: `rsync --ignore-existing` without `-t` or `-a`. For
   the Git and bucket recipes, use the server's own record of when each push or upload arrived.
2. **Heartbeat and integrity.** Verify a read-only copy of the log against the anchor:

   ```bash
   tally verify --dir /srv/log-copy --key-file trusted.keys --anchor /srv/anchor --heartbeat 1m --tolerance 30s
   ```

   A status other than 0 is an alert. `HeartbeatGap` means the anchored checkpoints stopped while the log was
   open: a crash, a stop, or checkpoints that did not reach the anchor. It never shows which events are
   missing, and its absence never shows the log is complete: a host can keep signing heartbeats over a log it
   drops entries from (T-15). The times compared are the signer's own claims, which is why check 1 exists.

### Executed against

`TestDrillMonitoringOffTheHost`: a log whose anchor never received the closing checkpoint, as when a host
dies or loses its link, and the same log with an anchor that did. Check 1 ran as written, through `find`,
on a spool written just then (found) and on the same spool aged an hour (alert). Check 2 ran as written
through the CLI: `HeartbeatGap` and status 1 for the host that died, status 0 for the clean close. Running
it found a bug, fixed in the same change: a closing checkpoint signed at the same instant as the last open
one was ordered by the anchor's file names, and a clean close read as a crash about half the time (SPEC §7
step 6). The schedule and the alerting are the deployment's, not exercised.

## Host compromise

Assume the attacker holds the host and the signing key. With the key they can sign a consistent false
history (T-07), and with the host they can rewrite every anchor spool on it (T-21). What still holds is what
left the host before the compromise: the copy on the anchor machine.

1. **Isolate the host** from the network, without powering it off if memory matters to the investigation.
2. **Preserve the evidence first**, before any repair:

   ```bash
   tally export --dir LOG --format bundle --out evidence.tar --key "$VERIFIER_KEY" --anchor /srv/anchor
   tally bundle-check evidence.tar
   ```

   The bundle carries the segments, the checkpoints, the quarantine files, the anchor copy and the
   verifier keys, with a MANIFEST of hashes. The MANIFEST is not signed: it shows that the bundle changed
   after it was made, not who made it. Keep the bundle off the host, and record its hash where the host
   cannot reach. `--key` is repeatable, one per trusted key.
3. **Verify against the off-host copy, never against the host's spool.** The host's spool says what the
   attacker left in it, and a forgery verifies against it.

   ```bash
   tally verify --dir LOG --key-file trusted.keys --anchor /srv/anchor
   ```

   `ForkDetected` says the log disagrees with a checkpoint that left the host, at the size printed. Entries
   below the newest anchored checkpoint that still matches are what the evidence supports; everything above
   it is the attacker's word.
4. **Establish when the key was compromised**, and rotate it ("After a key compromise", above).
5. **Do not append to the compromised log.** Rebuild the host, start a new log in a new directory under the
   new key, and keep the old directory and the bundle as evidence.

### Executed against

`TestDrillHostCompromise`: a log anchored through a spool, the spool pulled to an off-host copy, then the
attacker's moves with the key: the log rolled back to an earlier copy, another history written over it, and
the spool rewritten to match. Steps 2 and 3 ran through the CLI: the bundle was written and checked; the log
verified **intact against the host's spool**, the limit this procedure exists for, and reported
`ForkDetected`, status 1, against the off-host copy. Steps 1, 4 and 5 are outside the library, and step 4's
rotation is exercised by `TestAKeyRotation`.

## A poisoned log

Any write or fsync error poisons the log: the failing `Append` returns the store's error, every later one
returns `ErrPoisoned`, and the Observer hears `Poisoned` once (ADR-0009). There is no retry inside the
library, by design: after a failed fsync, a retry can report success with the data gone.

1. **Close the Log.** A poisoned log signs no closing checkpoint, so a `HeartbeatGap` follows on the anchor
   side; that is correct, and expected.
2. **Find the cause** in the error: a full disk ("Disk full", below) or an IO error from the device.
3. **Restart, preferably the host.** After a failed fsync the page cache can show data that never reached
   the disk, and a reopen in the same boot trusts it (R-31). Reopening the Log recovers a torn tail into a
   quarantine file, and the Observer hears `Recovered`.
4. **Retry the Appends that failed, with the same `EventID`.** No receipt was returned for them, so the
   application still has them. One stored after all is answered as a duplicate with its original receipt;
   one that was not is recorded once.
5. **Verify against the anchor** before relying on the log again. After an fsync error, treat the entries
   past the last anchored checkpoint as suspect (R-31), even when the log verifies.

### Executed against

`TestDrillPoisonedLog`: a file store behind `tallytest.FaultyStore`, which refuses the fifth write, as a disk
would refuse it. The failing
`Append` returned the store's error, the next one `ErrPoisoned`, and the Observer heard `Poisoned` once.
After the close and a reopen, the failed `Append` retried with its `EventID` was recorded once, a retry of an
entry stored before the failure came back as its duplicate, and `tally verify --require-fully-attested`
reported the log intact. The refusal was injected above the file store; real write and fsync failures at
every offset are `filestore`'s `TestAWriteFaultAtEveryByte` and `TestAnFsyncErrorAtEverySync`. The host
restart of step 3 was not exercised.

## Disk full

**A full disk stops the log, on purpose.** Every write fails, the log is poisoned (ADR-0009), and every
action that fails closed on `Append` stops with it (T-16). The library mitigates this and does not prevent
it.

### Before it happens

1. **Set a threshold.** `filestore.WithFreeSpaceThreshold(n)` makes the Log call
   `Observer.DiskSpace(free)` after every batch and every checkpoint while free space is below `n`.
   Choose `n` as your write rate times the time it takes someone to react, plus one segment. The
   warning is worth something only if it arrives while there is still room.
2. **Alert on `DiskSpace`.** The Observer is the only signal before writes fail, and it repeats on
   every write while space is low. Deduplicate it in the alert, not by ignoring it.
3. **On Linux, consider `filestore.WithPreallocation()`.** It reserves each new segment's blocks up to
   the segment size, so another process filling the disk does not stop the log before the segment
   is full. It is unavailable on macOS. A failed preallocation is reported as low space; it does not
   stop the log.
4. **Keep the log on its own volume** where you can. Nothing else then competes for its space.

### When `DiskSpace` fires

Free space: grow the volume, or move other data off it. **Do not delete segments by hand**: that
breaks verification from genesis, and an auditor cannot tell it from tampering (R-10). Old segments
go only through a prune ("Prune", below). Never delete quarantine files (`quarantine-*.bin`) to make
room: they are evidence (RF-20).

### When writes have failed

The log is poisoned: follow "A poisoned log", above, freeing space at step 2. A recovery that would cut
below the last stored checkpoint refuses to open instead; stop and investigate, because a full disk does not
produce that.

A disk-full failure is a failed write, which loses nothing acknowledged: no receipt was returned for the
entry that did not fit.

### Executed against

`TestDrillDiskFull`, on a real 2 MB tmpfs volume (Linux, in CI's job "runbook drill on a small volume", and
locally in a container; the command is in the test). A filler file took half the volume; the log, with a
256 KiB threshold, appended until the volume was full. The Observer heard `DiskSpace` before `Poisoned`, and
the failing `Append` returned the device's `ENOSPC` ("no space left on device"), after 8,363 entries in the
local run. The filler was removed, the log reopened and appended again, and `tally verify
--require-fully-attested` against the anchor, kept on another volume, reported it intact. Preallocation
and a production volume were not exercised; `filestore`'s `space_test.go` covers the threshold logic.

## Prune

A prune removes the leading segments below a checkpoint, for retention (RF-14, ADR-0012). It destroys
evidence, so it is refused unless the log verifies from that checkpoint, and the CLI also requires the
checkpoint to be one the anchor holds (RS-20): a valid checkpoint that never left the host proves nothing
to an auditor who reads the pruned log.

1. **Archive what will be removed**, and check the archive:

   ```bash
   tally export --dir LOG --format bundle --out archive-2026-11.tar --key "$VERIFIER_KEY" --anchor /srv/anchor
   tally bundle-check archive-2026-11.tar
   ```

2. **Choose the checkpoint from the off-host anchor copy**, one of its `.note` files at the size you prune
   to, and **close the Log**: the prune takes the directory's lock. Since v0.2, take the heartbeat note of that
   size (`tally-heartbeat/v1` on its second line), not the `tlog-checkpoint` beside it, which names no head and
   is refused.
3. **Prune:**

   ```bash
   tally prune --dir LOG --key-file trusted.keys --anchor /srv/anchor --checkpoint /srv/anchor/<file>.note
   ```

   The log still starts at or below the checkpoint's size. At a segment boundary, the next segment's header
   carries the checkpoint's head, which is what a verifier matches.
4. **Verify against the anchor**, and reopen the Log. From now on every verifier needs a trusted checkpoint
   at or above the new first segment, or reports `PrunedWithoutTrustedCheckpoint` (SPEC §7 step 7).

Deleting leading segments by hand down to a checkpointed boundary looks exactly like a prune (T-23). Only
the anchor and your record of prunes tell them apart: keep the archive and its date.

### Executed against

`TestDrillPrune`: a log written partly before its anchor existed, so some of its checkpoints never left
the host. Steps 1 to 4 ran through the CLI: the archive was written and checked, the prune at an anchored
checkpoint removed segments, the log verified against the anchor after it, and the archive still checked.
The refusals (an unanchored checkpoint, a forged one, another log's) are `TestPruneRefuses`.

## Shredding a subject

A shred destroys a subject's key, so the payloads sealed under it no longer open (`tally.ErrShredded`), and
the log still verifies. It erases the details; it does not erase that the subject acted. The limits are in
the README's ["Personal data and crypto-shredding"](../README.md#personal-data-and-crypto-shredding), and
none of this is legal advice: whether a request is satisfied is for the operator and counsel to decide.

### Before the first request

1. **Keep the vault apart from the log:** another directory and credential, preferably another host. A
   reader of the log must not also read the vault.
2. **Decide how long vault backups live.** Every backup taken before a shred undoes it, for as long as the
   backup exists. A shred is only effective once the last backup that predates it is gone, so the
   retention period is part of the answer to a person who asks.
3. **Keep the KEK out of the backups,** so that a stolen backup is ciphertext.

### Shredding

1. **Find the ref:** `vault.Resolve(ctx, identifier)`, with the identifier normalized exactly as the
   application normalizes it when it seals. `Resolve` creates a ref for an identifier it has not seen;
   shredding that new ref is harmless.
2. **Shred it:** `vault.Shred(ctx, ref)`. It is durable when it returns, and safe to repeat.
3. **Record that it happened, by ref,** without the identifier: an entry whose actor is the system or the
   service that shredded, action `subject.shred`, and resource `subject/<ref in hex>`. The ref is already
   in clear in the subject's own entries, so the record links nothing new, and it is what lets a restored
   vault be shredded again ("Vault backups", below).
4. **Verify the log.** It must still verify: a shred changes no stored byte.
5. **Note the date.** The shred is complete once the last vault backup older than this date is gone.

### Narrowing what the medium keeps

A removed file can survive on an SSD or under a journaling filesystem, and a wrapped key recovered from it
opens with the KEK that wrapped it. After a shred, or a batch of them:

1. Rotate the KEK: `vault.RotateKEK(ctx, next)`. Every key still in the vault is rewrapped under `next`.
2. Destroy the old KEK, and every copy of it, once the rotation has completed and no backup you keep needs
   it. A key recovered from the medium is then wrapped under a KEK that no longer exists.

This narrows the window to the time between the shred and the destruction of the old KEK. It does not
close it: whoever copied the medium and the old KEK before then still holds both.

## Vault backups

**A vault backup from before a shred undoes the shred** for as long as the backup exists: it still holds the
subject's key, wrapped under a KEK you still have. So a restore is never just a copy.

1. **Restore the vault directory** from the backup, with the application stopped.
2. **Apply again every shred the log records**, before the vault serves anything. `Shred` is idempotent, so
   applying them all is safe:

   ```bash
   tally export --dir LOG | jq -r 'select(.action == "subject.shred") | .resource | ltrimstr("subject/")'
   ```

   and call `vault.Shred` for each ref, from the application or a small program: the CLI has no vault
   command, since it never holds a KEK.
3. **Rotate the KEK, and destroy the old one** once nothing you keep needs it ("Narrowing what the medium
   keeps", above). A backup taken before the rotation then opens under no KEK that exists.

### Executed against

`TestDrillShredAndVaultBackups`: a file vault and a file-store log with two subjects' sealed payloads. A
vault backup was taken, one subject shredded and the shred recorded by ref; the log verified through the
CLI, and that subject's payload returned `ErrShredded`. The backup, opened with the same KEK, still opened
the payload: the limit is real. The backup was restored, the shreds were read from `tally export` and
applied again, and the payload returned `ErrShredded` while the other subject's still opened. After a KEK
rotation, the old backup no longer opened under the new KEK. The `jq` line was not run; the drill parses
the same JSON lines in Go. Media sanitization and the destruction of a KEK held in a KMS are outside the
library.
