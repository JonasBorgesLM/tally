# tally runbook

Operating procedures, each written once it could be exercised rather than guessed, and each saying
what it was executed against. **This is a draft:** key rotation, and a draft of disk full (#37), are here. Host compromise, a
poisoned log, shredding and vault backups, and prune come with #50.

## Key rotation

A log's checkpoints are signed with one key at a time (RS-06). Rotating replaces that key, for a
routine change or after a compromise. Two facts constrain every rotation:

- **The key's name is the log's origin, for the log's whole life** (SPEC §5.3, ADR-0005). A new key
  keeps the name; it changes only the key id. A log cannot move to another origin.
- **A checkpoint is worth something only under a key its verifier trusts** (RF-10). A checkpoint signed
  by a key the verifier does not have is `UnknownKey`, a failure, never a pass. So a verifier must keep
  every key that signed a checkpoint it still reads, from the store or from the anchor.

Until `tally keygen` exists (#41), keys are generated with `golang.org/x/mod/sumdb/note`'s
`GenerateKey`, whose encodings tally reads (SPEC §5.3). That package's `NewSigner` also returns a
value that satisfies `tally.Signer`.

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

## Disk full (draft, #37)

**A full disk stops the log, on purpose.** Every write fails, the log is poisoned (ADR-0009), and
every action that fails closed on `Append` stops with it (T-16). The library mitigates this and does
not prevent it. Exercised against `filestore`'s tests (`space_test.go`, `fault_test.go`), not yet
against a production volume; #50 finishes it.

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
go only through `Store.Prune`, below a checkpoint that verifies and that the anchor holds (ADR-0012).
Never delete quarantine files (`quarantine-*.bin`) to make room: they are evidence (RF-20).

### When writes have failed

`Append` returns `ErrPoisoned`, and the Observer has had `Poisoned`. Then:

1. **Close the Log.** No retry happens inside it, and none should happen outside it either.
2. **Free space**, as above.
3. **Reopen.** `filestore.Open` recovers a torn tail: the bytes after the last complete frame go to a
   quarantine file, and `Observer.Recovered` reports how many. A recovery that would cut below the
   last stored checkpoint refuses to open instead; stop and investigate, because a full disk does not
   produce that.
4. **Verify** the log, with the anchor, before relying on it again.

A disk-full failure is a failed write, which loses nothing acknowledged: no receipt was returned for
the entry that did not fit. If the failure was an fsync error rather than `ENOSPC`, R-31 applies:
treat the most recent entries as suspect.
