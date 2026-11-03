# tally format specification — v1

**Status:** draft, pending independent review (#10). Nothing here is implemented yet, so it
may change until M1 fixes the wire format in code; after that, a change is a new format version.

The test of this document: someone with no access to the Go code can write a verifier from it.
Key words MUST, MUST NOT and SHOULD are as in RFC 2119.

## 1. Encoding

All records use this encoding, and only it.

| Type | Encoding |
| --- | --- |
| `uint8`, `uint32`, `uint64`, `int64` | Fixed width, big-endian (`int64` two's complement) |
| `[n]byte` | Exactly `n` bytes |
| `bytes` | `uint32` length, then that many bytes |
| `string` | As `bytes`; MUST be valid UTF-8; not normalised |

Fields appear in the listed order. There are no optional fields: empty is length zero. Varints
do not exist in this format, because they admit several encodings of one value.

A decoder MUST:

1. check a length against the limits in §6 **before** allocating or reading it;
2. reject trailing bytes after the last field;
3. reject an unknown `version`, an unknown `type`, an unknown enum value, and invalid UTF-8;
4. re-encode the decoded value and reject the record unless it is byte-identical.

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
log_id      [16]byte   random
seq         uint64   = 0
created_at  int64      nanoseconds since the Unix epoch, UTC
origin      string
```

`origin` MUST be non-empty, MUST contain no Unicode space and no `+`, and is the signed-note key
name the log signs with (§5). A log has exactly one genesis, and it is leaf 0.

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

Validity, beyond the encoding:

- `log_id` equals genesis's.
- `seq` of the first entry is 1, and each following entry's is exactly one more.
- `recorded_at` is not less than the previous entry's (the first compares with `created_at`).
- `prev_hash` equals the leaf hash of the previous record.
- `actor_id` is 16 bytes for a subject, non-empty for a service, with no `@`, whitespace or control characters, and
  empty for the system.
- `action` matches `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`.
- `resource` and a service name contain no `@`, whitespace or control characters.

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

The leaf hash is not stored anywhere in the record. It is computable, and it is compared only as
the next record's `prev_hash` or a checkpoint's head.

## 3. Segment files

A log is a directory of segments named `NNNNNNNNNNNNNNNN.tlog`: the first `seq` in the segment, as
16 lowercase hex digits. Segments are contiguous and ordered by that number.

### 3.1 Header

```
magic      [8]byte  = "TALLYLOG"
version    uint8    = 1
log_id     [16]byte
first_seq  uint64
prev_hash  [32]byte   all zero if first_seq is 0, otherwise the leaf hash of first_seq - 1
```

### 3.2 Frame

Each record is framed as:

```
len    uint32    length of body
body   [len]byte the record
crc    uint32    CRC-32C (Castagnoli) of body
```

**The CRC is not a security mechanism.** It detects partial writes and accidental corruption, and
anyone rewriting a file recomputes it. A verifier MUST treat a CRC mismatch as a violation, but MUST
NOT treat a matching CRC as evidence of anything.

### 3.3 Tail states, on opening

For the last segment, reading frames from the start, the tail ends in exactly one of these states.

| State | Bytes after the last good frame | Writer's recovery | Verifier |
| --- | --- | --- | --- |
| Clean | none | none | ok |
| Short | fewer than a full frame (`len` runs past EOF, or fewer than 4 bytes) | quarantine and truncate | `MalformedRecord` |
| Bad tail | a complete frame failing its CRC, with nothing after it | quarantine and truncate, reporting it | `MalformedRecord` |
| Bad middle | a frame failing its CRC with bytes after it, or `len` over the limit | **refuse to open** | `MalformedRecord` |

A writer MUST NOT truncate below the last local checkpoint: if the tail states above would remove a
record that checkpoint covers, opening fails.

Quarantine: the removed bytes are written durably to `quarantine-<first_removed_offset>.bin` before
truncating, and are part of an audit bundle. A short or bad tail and a flipped bit in the last
acknowledged entry can be indistinguishable; quarantine preserves the evidence without settling it.

## 4. Sealing

```
ciphertext = AES-256-GCM(DEK, nonce, plaintext, aad)
payload    = 0x01 || nonce (12 bytes, random) || ciphertext (with its 16-byte tag)
```

The leading byte is the seal format. The AAD is the §1 encoding of:

```
tag          string = "tally/v1/seal"
log_id       [16]byte
event_id     bytes
subject_ref  bytes
```

It is length-prefixed so that no boundary between `event_id` and `subject_ref` can shift. `seq` is
deliberately absent: sealing happens on the caller's goroutine, before `seq` exists.

Verifying a log needs no DEK: a sealed payload is opaque bytes, hashed as stored. After a shred the
entry still verifies.

The vault's on-disk format is specified with its implementation in M6 (#43), and will be added here.

## 5. Checkpoints

A checkpoint is a [C2SP signed note](https://c2sp.org/signed-note) with this text:

```
<origin>
tally-chain/v1
<size>
<base64(head leaf hash)>
<recorded_at>
<state>
```

- `size` is an ASCII decimal with no leading zeros, per §2.4.
- The hash is standard, padded, canonical base64 of 32 bytes. Decoders MUST reject non-canonical base64.
- `recorded_at` is RFC 3339 in UTC, with nanoseconds, and is the head entry's `recorded_at` or a later
  log clock reading. It is the signer's claim, not evidence of real time.
- `state` is `open`, or `closed` on the checkpoint written by a clean `Close`. It is the signer's claim as
  well: it lets an honest restart produce no false alarm, and an attacker holding the key can write it too
  (T-15).
- Line 2 means a `tlog-checkpoint` parser fails on the size line, so this chain head cannot be read as
  a Merkle root. That is intended.

Signatures are Ed25519 as the spec defines (algorithm byte `0x01`, key id
`SHA-256(name || 0x0A || 0x01 || public_key)[:4]`). The key name MUST equal `origin`, and additional
signatures from unknown keys MUST be ignored. A checkpoint with no signature from a trusted key has
**no value** and MUST NOT be read.

Limits: a note over 64 KiB or with more than 16 signatures is rejected.

At v0.2 the body changes to `tlog-checkpoint`. That format has no time line (ADR-0006).

## 6. Limits

| Field | Default | Hard ceiling |
| --- | --- | --- |
| `event_id` | 128 bytes | 128 bytes |
| `actor_id` | 256 bytes | 256 bytes |
| `action` | 128 bytes | 128 bytes |
| `resource` | 256 bytes | 256 bytes |
| `origin` | 256 bytes | 256 bytes |
| `payload` | 64 KiB | 16 MiB |
| frame `len` | derived from the above | 16 MiB + 2 KiB |

A verifier MUST accept the hard ceiling and MUST reject above it. A deployment's smaller limit applies
to its writers, not to verifiers.

## 7. Verification algorithm

Input: records in order from a segment set; a set of trusted public keys; optionally a trusted
checkpoint to start from; optionally checkpoints read from an anchor, with the current time supplied by
the caller.

1. Read and validate each segment header; `log_id`, `first_seq` and `prev_hash` MUST agree with what came
   before. Segments MUST be contiguous.
2. For each frame: check the length limit, read the body, check the CRC, decode strictly (§1), and apply the
   validity rules in §2. Keep `previous_leaf = leaf_hash(body)`.
3. For each checkpoint available, with a trusted signature, that matches `origin`: if its `size` is at most
   the log's, compare `head` with the leaf at index `size - 1`. A mismatch is `CheckpointMismatch`, or
   `ForkDetected` when the checkpoint came from an anchor. If its `size` is larger, the log was cut:
   `TruncatedBelowCheckpoint`.
4. **Checkpoint order:** across checkpoints, `size` and `recorded_at` MUST not decrease.
5. If anchor checkpoints are given and a heartbeat interval `T` is configured, any gap between consecutive
   checkpoints' times, or between the last one and the supplied time, above `T + tolerance` is
   `HeartbeatGap`, unless the earlier checkpoint's `state` is `closed`.
6. If the log starts above leaf 0, a prune marker is present, and a trusted checkpoint MUST cover the
   boundary, with `head` equal to the first segment's `prev_hash`; otherwise
   `PrunedWithoutTrustedCheckpoint`.
7. `AttestedSize` is the largest `size` matched by a trusted checkpoint.
   `UnattestedEntries = size - AttestedSize`.

### 7.1 What a result asserts

`OK() == true` means: every record read was well-formed, the chain is unbroken, every trusted checkpoint
given agrees with it. **It asserts nothing about entries past `AttestedSize`,** and a trust that comes only
from checkpoints read off the host being verified is worth no more than that host.

An IO error or misuse is the `error` return, never `OK()`. A verifier MUST NOT report success on a partial
read.

## 8. Test vectors

`testdata/vectors/` will hold keys, records, leaf hashes and checkpoints (#15). Conformance to §5 is tested
against `golang.org/x/mod/sumdb/note` (#30).
