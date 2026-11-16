# ADR-0020: The file vault keeps one file per subject, behind a KEK interface, and rotates by rewrapping each file

## Status
Accepted — 2026-11-16

## Context
ADR-0011 chose a vault of random refs and per-subject DEKs. It left the on-disk format and KEK
rotation to the implementation (#43). Neither can be left implicit: the format decides what a shred
destroys, and rotation decides what a KEK compromise exposes.

Three questions had to be settled:
- what holds the KEK;
- how DEKs sit on disk;
- what rotating the KEK rewrites.

## Decision
**The KEK is an interface**, `seal.KEK`, with `ID`, `Wrap` and `Unwrap`, so it can be a KMS or an HSM,
as `tally.Signer` can (ADR-0015). `seal.NewLocalKEK` is the in-process implementation, AES-256-GCM.
Its key lives only inside a closure, as `note.Signer`'s does, so no `fmt` verb prints it (RS-07).

**One file per subject**, in a directory at mode 0700, each file at 0600 and written atomically
(RS-10):
- `VAULT` holds the vault key, wrapped by the KEK. The vault key is 32 random bytes that key the
  index.
- `idx/<hex HMAC-SHA256(vault key, identifier)>` holds the subject's ref. The identifier itself is
  stored nowhere.
- `refs/<hex ref>` holds the subject's DEK wrapped by the KEK, the id of that KEK, and the index name,
  so that a shred can remove both files.

A ref is 128 random bits. Every wrapped blob is bound by its AAD to what it protects: the vault key
to a fixed tag, a DEK to its ref. A wrapped DEK therefore cannot be moved to another ref's file.
SPEC §4.1 gives the exact encoding.

**Rotation rewraps each file.** `RotateKEK(next)` unwraps every `refs/` file and the vault key that
are not already under `next`, with whichever KEK wrapped them, and rewraps them under `next`, one
atomic write per file. `VAULT` comes last. Each blob records its KEK's id, so an interrupted rotation
is resumed by calling `RotateKEK(next)` again with both KEKs available. The DEKs do not change, so no
sealed payload in the log is re-encrypted.

## The alternative that was rejected
**A single vault file, rewritten on every change.** One file to back up, and an index that reads in
one go. Rejected because every `Resolve` of a new subject and every `Shred` rewrites everything. A
shredded DEK also survives in every earlier version of that one file that the medium still holds,
which is more copies than a deleted small file leaves.

**A single intermediate key under the KEK**, so rotating the KEK rewrites one file. Rejected because
that key then unwraps every DEK at once. Replacing it, which is what a compromise demands, brings back
the cost of rewrapping everything.

**The KEK as a bare 32-byte key.** Simpler, and it rules out a KMS or an HSM without a new API.

## Consequences
- **Deleting a file on an SSD or a journaling filesystem does not destroy it** (R-34). A wrapped DEK
  recovered from the medium, plus a later compromise of the KEK that wrapped it, undoes a shred.
  Rotating the KEK narrows that window: a DEK wrapped only under a KEK that is itself destroyed stays
  unreadable. It does not close it, and the docs say so.
- Many small files, which a backup must copy whole. An old backup undoes a shred (ADR-0011).
- During a rotation the vault needs both KEKs, and each blob names the one it is under, so a missing
  KEK fails loudly on the subjects it wrapped instead of silently.
- A crash between writing a subject's `refs/` file and its `idx/` file leaves a DEK no ref was ever
  returned for, so nothing was sealed with it. It is unreachable, not a leak of anything sealed.

## Reopening criterion
When a deployment needs a vault backed by a database or a KMS's own key store, or a measured
subject count makes per-file storage too slow to back up.
