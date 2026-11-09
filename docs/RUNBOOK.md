# tally runbook

Operating procedures, each written once it could be exercised rather than guessed, and each saying
what it was executed against. **This is a draft:** only key rotation is here. Host compromise, disk
full, a poisoned log, shredding and vault backups, and prune come with #50.

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
