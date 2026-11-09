# tally format specification — v1

**Status:** draft, revised after the independent review (#10). Nothing here is implemented yet, so it
may change until M1 fixes the wire format in code; after that, a change is a new format version.

The test of this document: someone with no access to the Go code can write a verifier from it.
Key words MUST, MUST NOT and SHOULD are as in RFC 2119. A requirement marked **(writer)** binds an
implementation that writes logs; a verifier cannot observe it.

## 1. Encoding

All records use this encoding, and only it.

| Type | Encoding |
| --- | --- |
| `uint8`, `uint32`, `uint64`, `int64` | Fixed width, big-endian (`int64` two's complement) |
| `[n]byte` | Exactly `n` bytes |
| `bytes` | `uint32` length, then that many bytes |
| `string` | As `bytes`; MUST be valid UTF-8; not normalised |

Fields appear in the listed order. There are no optional fields: empty is length zero. Whether a
field may be empty is a validity rule of its record (§2), not of the encoding. Varints do not exist
in this format, because they admit several encodings of one value.

A decoder MUST:

1. check a length against the limits in §6 **before** allocating or reading it;
2. reject trailing bytes after the last field;
3. reject an unknown `version`, an unknown `type`, an unknown enum value, and invalid UTF-8. The known
   enum values are exactly those listed in §2, and the seal format byte in §4;
4. re-encode the decoded value and reject the record unless it is byte-identical.

### 1.1 Forbidden code points

Several fields below MUST NOT contain a **forbidden code point**. The set is listed explicitly, so
that it does not depend on the Unicode version an implementation ships:

| Code points | What they are |
| --- | --- |
| U+0000–U+001F, U+007F–U+009F | Controls (general category Cc) |
| U+0020, U+0085, U+00A0, U+1680, U+2000–U+200A, U+2028, U+2029, U+202F, U+205F, U+3000 | Spaces (the White_Space property, beyond Cc) |
| U+180E, U+200B–U+200F, U+202A–U+202E, U+2060–U+2064, U+2066–U+206F, U+FEFF | Invisible and bidirectional formatting |

Go's `unicode.IsSpace` matches the second row plus U+0009–U+000D, which the first row already holds.
The third row exists because an invisible or reordering character makes two different identifiers
print the same.

## 2. Records

Every record begins with `version uint8 = 1` and `type uint8`.

| `type` | Record |
| --- | --- |
| `0x01` | GENESIS |
| `0x02` | ENTRY |

### 2.1 GENESIS

```
version     uint8    = 1
type        uint8    = 0x01
log_id      [16]byte   random (writer)
seq         uint64   = 0
created_at  int64      nanoseconds since the Unix epoch, UTC
origin      string
```

`origin` MUST be non-empty, MUST contain no forbidden code point (§1.1) and no `+`, and is the
signed-note key name the log signs with (§5). Every valid `origin` is therefore a valid key name for
`golang.org/x/mod/sumdb/note`, which forbids only spaces and `+`.

A log has exactly one genesis, and it is leaf 0. In a segment set that starts at `seq` 0, the first
record MUST be a genesis; anywhere else a genesis is a violation. `created_at` has no constraint of its
own.

### 2.2 ENTRY

```
version       uint8    = 1
type          uint8    = 0x02
log_id        [16]byte
seq           uint64
recorded_at   int64      nanoseconds since the Unix epoch, UTC
occurred_at   int64      nanoseconds since the Unix epoch, UTC
event_id      bytes
actor_kind    uint8      0x01 subject · 0x02 service · 0x03 system
actor_id      bytes      SubjectRef (16 bytes), service name, or empty for system
action        string
resource      string
outcome       uint8      0x01 success · 0x02 failure · 0x03 denied · 0x04 error
payload_kind  uint8      0x00 none · 0x01 plain · 0x02 sealed
subject_ref   bytes      16 bytes if payload_kind is sealed, otherwise empty
payload       bytes      empty if payload_kind is none
prev_hash     [32]byte
```

Validity, beyond the encoding, checked in the order listed. The first rule that fails names the
violation (§7.2):

- `log_id` equals the log's (genesis's, or the first segment header's when genesis was not read, §7).
- `seq` is exactly one more than the previous record's.
- `recorded_at` is not less than the previous entry's; the first entry compares with genesis's
  `created_at`. An entry whose predecessor was not read (§7) has no lower bound.
- `prev_hash` equals the leaf hash of the previous record.
- `event_id` is non-empty. It is opaque bytes, not necessarily UTF-8. A verifier MUST NOT check that
  event ids are unique: idempotency is a writer's window (RF-04), not a property of the log.
- `actor_id` is, by `actor_kind`:
  - subject: exactly 16 bytes, any value;
  - service: non-empty valid UTF-8 with no `@` and no forbidden code point (§1.1);
  - system: empty.
- `action` matches `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`.
- `resource` contains no `@` and no forbidden code point. It MAY be empty.
- `payload`, by `payload_kind`:
  - none: empty;
  - plain: non-empty, any bytes. An empty plain payload is invalid, so that "no payload" has one encoding;
  - sealed: as in §4, and at least 29 bytes.
- `subject_ref` has no required relation to `actor_id`: the actor and the person whose data is sealed are
  often different people.

`occurred_at` is caller-supplied and untrusted; a verifier MUST NOT fail on its value.

### 2.3 Leaf hash

```
leaf_hash(record) = SHA-256(0x00 || record_bytes)
```

`record_bytes` is exactly the stored record body, as framed in §3. A verifier MUST hash the stored
bytes and MUST NOT hash a re-encoding. This is the RFC 6962 leaf form; `0x01` is reserved for
interior nodes.

### 2.4 Size and indices

A log's **leaves** are genesis (index 0) and every entry (index `seq`). Therefore
`size = head_seq + 1`. A log holding only genesis has size 1. There is no record for size 0.

The leaf hash is not stored in the record that it hashes. It is computable, and it is compared as the
next record's `prev_hash`, as a segment header's `prev_hash`, or as a checkpoint's head.

## 3. Segment files

A log is a directory of segments named `NNNNNNNNNNNNNNNN.tlog`: the first `seq` in the segment, as
exactly 16 lowercase hex digits. Segments are contiguous and ordered by that number.

- A verifier reads only files whose names match that pattern exactly. Other files in the directory
  (checkpoints, quarantine files, the prune marker) are not segments.
- A file whose name matches the pattern except for uppercase hex digits is a violation, not a foreign
  file, so that renaming cannot hide a segment.
- The name MUST equal the header's `first_seq`.
- A segment holding a header and no frames is valid only as the last segment; a writer that has just
  rotated produces one.

### 3.1 Header

```
magic      [8]byte  = "TALLYLOG"
version    uint8    = 1
log_id     [16]byte
first_seq  uint64
prev_hash  [32]byte   all zero if first_seq is 0, otherwise the leaf hash of first_seq - 1
```

The header is 65 bytes. A segment shorter than that, or with the wrong `magic` or `version`, is a
violation, including when it is the last segment.

### 3.2 Frame

Each record is framed as:

```
len    uint32    length of body
body   [len]byte the record
crc    uint32    CRC-32C (Castagnoli) of body
```

`len` is checked against the frame ceiling (§6) before the body is read.

**The CRC is not a security mechanism.** It detects partial writes and accidental corruption, and
anyone rewriting a file recomputes it. A verifier MUST treat a CRC mismatch as a violation, but MUST
NOT treat a matching CRC as evidence of anything.

### 3.3 Tail states, on opening

For the last segment, reading frames from the start, the tail ends in exactly one of these states.

| State | Bytes after the last good frame | Writer's recovery | Verifier |
| --- | --- | --- | --- |
| Clean | none | none | ok |
| Short | fewer than a full frame: fewer than 4 bytes, or fewer than `len + 8` bytes, so the body or the CRC is cut off | quarantine and truncate | `MalformedRecord` |
| Bad tail | a complete frame failing its CRC, with nothing after it | quarantine and truncate, reporting it | `MalformedRecord` |
| Bad middle | a frame failing its CRC with bytes after it, or `len` over the limit | **refuse to open** | `MalformedRecord` |

In a segment that is not the last, every frame MUST be complete and good: any of the states other than
Clean is `MalformedRecord`.

**(writer)** A writer MUST NOT truncate below the last local checkpoint: if the tail states above would
remove a record that checkpoint covers, opening fails.

**(writer)** Quarantine: the removed bytes are written durably to
`quarantine-<segment>-<offset>.bin` before truncating, where `<segment>` is the segment's 16-digit name
and `<offset>` is the byte offset of the first removed byte, as 16 lowercase hex digits. Quarantined
bytes are part of an audit bundle. A short or bad tail and a flipped bit in the last acknowledged entry
can be indistinguishable; quarantine preserves the evidence without settling it.

## 4. Sealing

```
ciphertext = AES-256-GCM(DEK, nonce, plaintext, aad)
payload    = 0x01 || nonce (12 bytes, random) || ciphertext (with its 16-byte tag)
```

The leading byte is the seal format, and `0x01` is its only known value. The AAD is the §1 encoding of:

```
tag          string = "tally/v1/seal"
log_id       [16]byte
event_id     bytes
subject_ref  bytes
```

It is length-prefixed so that no boundary between `event_id` and `subject_ref` can shift. `seq` is
deliberately absent: sealing happens on the caller's goroutine, before `seq` exists.

Verifying a log needs no DEK. A verifier checks the shape only: the format byte is `0x01` and the
payload is at least 29 bytes (1 + 12 + 16; the plaintext may be empty). Otherwise the payload is opaque
bytes, hashed as stored. After a shred the entry still verifies. The nonce's randomness and the AAD's
correctness are writer requirements a verifier cannot check.

The vault's on-disk format is specified with its implementation in M6 (#43), and will be added here.

## 5. Checkpoints

A checkpoint is a [C2SP signed note](https://c2sp.org/signed-note). The parts of that specification a
verifier needs are restated here; where they differ, this document is stricter, never looser.

### 5.1 Envelope

```
<text>                 the body of §5.2; every line ends in "\n"
"\n"                   one empty line
<signature line>...    one or more
```

A signature line is `— <name> <signature>\n`: U+2014 EM DASH, a space, the key name, a space, and the
standard, padded, canonical base64 of `key_id (4 bytes) || Ed25519 signature (64 bytes)`.

- The whole note MUST be valid UTF-8 and MUST NOT contain U+0000–U+001F other than `\n`.
- The text and the signatures are split at the **last** `\n\n`. The signed message is the text,
  including its final `\n` and excluding the empty line.
- `key_id = SHA-256(name || 0x0A || 0x01 || public_key)[:4]`, where `0x01` is the Ed25519 algorithm byte.
- A note over 64 KiB, or with more than 16 signature lines from any key, is rejected. Lines are counted
  as they appear, before any repeated line is set aside (§5.4).

### 5.2 Body

The text is exactly these six lines, each ending in `\n`. Nothing follows the sixth line.

```
<origin>
tally-chain/v1
<size>
<base64(head leaf hash)>
<recorded_at>
<state>
```

- `origin` equals the signing key's name (ADR-0005).
- `size` is an ASCII decimal with no leading zeros, at least `1`, and fits in a `uint64` (§2.4).
- The hash is standard, padded, canonical base64 of 32 bytes. Decoders MUST reject non-canonical base64.
- `recorded_at` is RFC 3339 in UTC in exactly one layout, `YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ`: nine
  fractional digits always, and the letter `Z`. In Go that is the layout
  `2006-01-02T15:04:05.000000000Z` on a UTC time; `time.RFC3339Nano` is **not** it, because it drops
  trailing zeros. The value is the head leaf's `recorded_at` (genesis's `created_at` at size 1) or a later
  log clock reading. It is the signer's claim, not evidence of real time.
- `state` is `open`, or `closed` on the checkpoint written by a clean `Close`. It is the signer's claim as
  well: it lets an honest restart produce no false alarm, and an attacker holding the key can write it too
  (T-15).
- Line 2 means a `tlog-checkpoint` parser fails on the size line, so this chain head cannot be read as
  a Merkle root. That is intended.

At v0.2 the body changes to `tlog-checkpoint`. That format has no time line (ADR-0006).

### 5.3 Keys

A verifier's trusted keys are signed-note verifier keys, one per string:

```
<name>+<key_id as 8 lowercase hex digits>+<base64(0x01 || 32-byte Ed25519 public key)>
```

The `key_id` in the string MUST equal the one computed from the name and key. The private key file uses
the matching signer encoding, `PRIVATE+KEY+<name>+<key_id hex>+<base64(0x01 || 32-byte seed)>`, at
mode 0600. Both are the encodings `golang.org/x/mod/sumdb/note` reads and writes.

Reading a checkpoint (§5.4) does not depend on the log: a trusted key for another log can produce an
accepted checkpoint, and §7 step 5 then reports that it names another `origin`. This keeps §5.4 usable
before the log's `origin` is known, which, when genesis was not read, comes from the checkpoints
themselves.

### 5.4 Reading a checkpoint

Each checkpoint is read in this order, and the first matching outcome applies:

1. The envelope does not parse (§5.1), or exceeds a limit: `MalformedRecord`. A signature line whose
   base64 decodes but is not canonical: `NonCanonicalEncoding`. Both are decided here, before any key is
   looked up.
2. A signature line names a trusted key (by name and `key_id`) and does not verify: `BadSignature`. One
   bad signature from a trusted key fails the checkpoint even if another trusted key's signature is good;
   this is `golang.org/x/mod/sumdb/note`'s behaviour. Repeated identical lines from one key count once.
3. No signature line verifies under a trusted key: `UnknownKey`. Signatures from unknown keys are
   otherwise ignored.
4. The body does not parse (§5.2), or its `origin` differs from the name of any trusted key whose signature
   verified: `MalformedRecord`. Non-canonical base64 in the body's hash line is `NonCanonicalEncoding`.
5. Otherwise the checkpoint is **accepted**, and only an accepted checkpoint takes part in §7.

## 6. Limits

| Field | Default | Hard ceiling |
| --- | --- | --- |
| `event_id` | 128 bytes | 128 bytes |
| `actor_id` | 256 bytes | 256 bytes |
| `action` | 128 bytes | 128 bytes |
| `resource` | 256 bytes | 256 bytes |
| `origin` | 256 bytes | 256 bytes |
| `subject_ref` | 16 bytes | 16 bytes |
| `payload` | 64 KiB | 16 MiB |
| frame `len` | derived from the above | 16 MiB + 2 KiB |
| checkpoint note | 64 KiB | 64 KiB |
| signature lines per note | 16 | 16 |

A verifier MUST accept the hard ceiling and MUST reject above it. A deployment's smaller limit applies
to its writers, not to verifiers. The largest valid ENTRY body is under the frame ceiling.

## 7. Verification algorithm

ADR-0016 records why the algorithm stops at the first broken record and how pruned and incremental
starts are judged.

**Input:**

- a segment set (§3);
- a set of trusted keys (§5.3);
- optionally, a start checkpoint, for incremental verification (RF-08);
- optionally, checkpoints read from an anchor, and other checkpoints, each marked as from an anchor or not;
- optionally, a heartbeat interval `T`, a `tolerance` and the current time, all supplied by the caller.
  The format sets no default for any of them;
- optionally, a requirement that the whole log be attested (RF-18, ADR-0018).

**Error, not violation.** The result is an `error`, never a report, when verification is not possible:
an IO error, no segment file, a start checkpoint that is not accepted (§5.4), or, with genesis not read,
accepted checkpoints naming more than one `origin` (step 3).

**Steps:**

1. **Checkpoints.** Read every checkpoint (§5.4). Report each one that is not accepted, and set it aside.
2. **Segments.** Select the segment files and order them (§3). With a start checkpoint of size `s`, start at
   the last segment whose `first_seq ≤ s - 1`; earlier segments are not read. Otherwise start at the first.
3. **The log's identity.** Let `f` be the `first_seq` of the first segment read.
   - `f = 0`: `log_id`, `origin` and `created_at` come from genesis, which step 4 reads first. If genesis
     itself is a violation, the log has no verified identity: step 4 stops there, steps 5 to 8 are skipped,
     and the result is that violation with `Size = 0`.
   - `f > 0`: `log_id` is that segment header's. `origin` is the start checkpoint's, or, without one, the
     `origin` shared by every accepted checkpoint. If they name more than one, that is an error. With no
     accepted checkpoint, `origin` is unknown and nothing needs it: step 7 then reports
     `PrunedWithoutTrustedCheckpoint`.
4. **Records.** For each segment, validate its header in this order: length, `magic` and `version` (§3.1),
   the name (§3), then `log_id`, `first_seq` and `prev_hash`. For every segment after the first one read,
   `log_id` equals the log's, `first_seq` is one more than the previous segment's last `seq`, and `prev_hash`
   equals the previous leaf hash. In every segment the header stands in for the previous record: the first
   frame's `seq` MUST equal `first_seq` and, for an entry, its `prev_hash` MUST equal the header's. For each
   frame, in this order: check the length limit, read the body, check the CRC, decode strictly (§1 rules 1
   to 4, in order), and apply the validity rules of §2 in their listed order.

   **Stop at the first violation.** Exactly one record-level violation is reported, named by the first
   check that fails. The **verified prefix** is the leaves read before it, and `Size = f + the number of
   leaves verified`: with no violation, one more than the last leaf's index. Nothing is asserted about any
   byte after the violation.
5. **Checkpoints against the log.** Every accepted checkpoint whose `origin` is not the log's is
   `CheckpointMismatch`, and takes no further part. From here on, "accepted checkpoints" means the rest.
   For each of them:
   - `size < f`: below what was read; it is not compared, and takes part only in steps 6 and 8.
   - `size = f > 0`: `head` MUST equal that segment header's `prev_hash`.
   - `f < size ≤ Size`: `head` MUST equal the leaf hash at `size - 1`, and `recorded_at` MUST NOT be less
     than that leaf's `recorded_at` (genesis's `created_at`), else `TimeRegression`.
   - `size > Size`: `TruncatedBelowCheckpoint` if step 4 found no violation. After a violation it is not
     evaluated: the log has already failed, and a broken record is not a truncation.

   A `head` that differs is `ForkDetected` for an anchor checkpoint and `CheckpointMismatch` otherwise. A
   checkpoint whose comparison succeeds is **matched**.
6. **Checkpoint order.** Sort accepted checkpoints by `size`, then by `recorded_at`, the start checkpoint
   included. `recorded_at` MUST NOT decrease along that order, else `TimeRegression`: equivalently, no
   checkpoint has a later `recorded_at` than one of larger `size`. Heartbeats produce many checkpoints of
   one `size`, so the secondary key is what makes the order unique. Two with the same `size` and different heads
   are `ForkDetected`, whether or not either was compared with the log.
7. **A start above leaf 0.** If `f > 0`, some accepted checkpoint with `size ≥ f` MUST be matched, else
   `PrunedWithoutTrustedCheckpoint`. This holds for a pruned log and for an incremental start alike. A
   matched start checkpoint satisfies it. The prune marker is not an input: a verifier relies on the
   checkpoint, which is signed, rather than on a file the host wrote.
8. **Heartbeat.** If `T` is given, take the accepted anchor checkpoints in step 6's order. A gap between
   consecutive `recorded_at` values, or between the last one and the current time, above `T + tolerance` is
   `HeartbeatGap`, unless the earlier checkpoint's `state` is `closed`. Times are compared as instants. With
   `T` given and no accepted anchor checkpoint, the gap is unbounded: `HeartbeatGap`. These times are the
   signer's own claims (ADR-0006).
9. **Result.** `AttestedSize` is the largest `size` among matched checkpoints, or 0 if none matched. It never
   exceeds `Size`. `UnattestedEntries = Size - AttestedSize`, counted in leaves: with nothing attested,
   genesis is among them.
10. **Full attestation, if required.** If the caller required the whole log to be attested and
    `UnattestedEntries > 0`, that is `UnattestedTail`. Without the requirement, an unattested tail is not a
    violation: it is reported in `UnattestedEntries`, and §7.1 says what it means.

### 7.1 What a result asserts

`OK() == true` exactly when no violation of any kind in §7.2 was reported, including `HeartbeatGap`,
checkpoint order, `PrunedWithoutTrustedCheckpoint`, and `UnattestedTail` when full attestation was
required. It means: every record read was well-formed, the
chain is unbroken, and every accepted checkpoint agrees with it. **It asserts nothing about entries past
`AttestedSize`,** and a trust that comes only from checkpoints read off the host being verified is worth
no more than that host.

An IO error or misuse is the `error` return, never `OK()`. A verifier MUST NOT report success on a partial
read.

### 7.2 Violation kinds

The kinds are those of REQUIREMENTS §5.1. For the format, this table governs; if the two ever diverge,
REQUIREMENTS is the one corrected. Every check in this document reports exactly one:

| Kind | Reported when |
| --- | --- |
| `MalformedRecord` | A frame's `len` is over the ceiling, its CRC fails, or it is incomplete (§3.3). A header or segment name is invalid (§3, §3.1). A record fails strict decoding (§1 rules 1–3: a field over its limit, trailing bytes, an unknown version, type, enum or seal format, invalid UTF-8). A record breaks a §2 rule not listed below, including a missing or misplaced genesis and a `log_id` that differs from the log's. A checkpoint's envelope or body does not parse (§5.4). |
| `NonCanonicalEncoding` | A record does not re-encode to the same bytes (§1 rule 4). With a fixed-width encoding a correct strict decoder never reaches this; the check exists to catch a decoder bug. A checkpoint holds non-canonical base64. |
| `PrevHashMismatch` | An entry's or a segment header's `prev_hash` differs from the previous leaf hash. |
| `SeqGap` | A `seq` or header `first_seq` is greater than expected. |
| `SeqRegression` | A `seq` or header `first_seq` is less than expected. |
| `TimeRegression` | An entry's `recorded_at` decreases. A checkpoint's `recorded_at` is less than its head leaf's. `recorded_at` decreases across checkpoints (§7 step 6). |
| `BadSignature` | A signature from a trusted key does not verify. |
| `UnknownKey` | A checkpoint has no signature from a trusted key (RF-10). |
| `CheckpointMismatch` | A checkpoint not from an anchor disagrees with the log, or names another `origin`. |
| `ForkDetected` | An anchor checkpoint disagrees with the log. Two accepted checkpoints of one `size` have different heads. |
| `TruncatedBelowCheckpoint` | A checkpoint's `size` exceeds a log read without violation. |
| `HeartbeatGap` | §7 step 8. |
| `PrunedWithoutTrustedCheckpoint` | §7 step 7. |
| `UnattestedTail` | §7 step 10: full attestation was required, and `UnattestedEntries > 0`. |

## 8. Test vectors

[`testdata/vectors/`](../testdata/vectors/README.md) holds the published vectors.
[`records.json`](../testdata/vectors/records.json) is a genesis and four entries forming one chain,
covering every `actor_kind`, `payload_kind` and `outcome`, each given as fields, stored bytes and leaf
hash. [`keys.json`](../testdata/vectors/keys.json) is a public test key in both §5.3 encodings, with
its seed and key id, and a note it signed (§5.1).
[`checkpoints.json`](../testdata/vectors/checkpoints.json) is a §5.2 checkpoint over the head of
`records.json`, signed with that key; the records and it verify (§7) with the whole log attested.
Segment files are added with the file store (#33). Sealing vectors need a fixed DEK and nonce as
inputs, and are added with #44. Conformance to §5 is tested
against `golang.org/x/mod/sumdb/note` (#30). That package accepts up to 100 signatures and no size limit,
so the differential test expects tally to reject notes it accepts above §6's limits, and never the
reverse.
