# Test vectors

Fixed inputs and outputs for [SPEC v1](../../docs/SPEC.md), so that an independent implementation can
check itself without reading tally's Go code.

## `records.json`

A genesis and four entries forming one valid chain, leaves 0 to 4. Together they cover every
`actor_kind`, every `payload_kind` and every `outcome`. Each record is given three ways:

| Key | What it is |
| --- | --- |
| `genesis` or `entry` | The fields, named as in SPEC §2. Byte fields are hex (`*_hex`), and an empty one is `""`. 64-bit integers are decimal strings, so that a JSON reader using float64 does not round them. |
| `body_hex` | The exact stored record bytes (SPEC §1, §2). |
| `leaf_hash_hex` | `SHA-256(0x00 \|\| body)` (SPEC §2.3). |

To check an implementation against them:

1. Encode the fields and compare with `body_hex`, byte for byte.
2. Decode `body_hex` and compare with the fields.
3. Hash `body_hex` as a leaf and compare with `leaf_hash_hex`.
4. Check that each entry's `prev_hash_hex` is the previous record's `leaf_hash_hex`, and that the five
   records verify as a chain from leaf 0 (SPEC §7 step 4).

Points that are easy to get wrong, which these vectors exercise:

- **Empty fields.** An empty field is a length of zero, not an absent field (`resource`, `actor_id` of
  the system, `subject_ref` and `payload` when there is no payload).
- **`event_id` is opaque bytes.** It is not text, and one vector holds `0x00` and `0xff`.
- **`resource` is UTF-8 and is not normalised.** One vector holds multi-byte characters.
- **`occurred_at` is untrusted.** Any `int64` is valid, including before the epoch; one vector holds `-1`.
- **The sealed payload is opaque to a verifier.** Its bytes are the format byte `0x01`, a nonce and
  bytes standing for ciphertext and tag. They are **not** real AES-GCM output; `seal.json` is.

## `keys.json`

A **public test key**, named `example.com/log` (the origin of the genesis in `records.json`) and made
from the seed `00 01 … 1f`. Anyone can sign with it: it is for checking implementations, never for a
real log. `tallytest.TestSignerKey` and `tallytest.TestVerifierKey` are the same pair.

| Key | What it is |
| --- | --- |
| `seed_hex` | The 32-byte Ed25519 seed. |
| `key_id_hex` | `SHA-256(name ‖ 0x0A ‖ 0x01 ‖ public_key)[:4]` (SPEC §5.1). |
| `verifier_key`, `signer_key` | The key in SPEC §5.3's two encodings. |
| `notes[].note` | A whole signed note (SPEC §5.1) over `notes[].text`. Ed25519 is deterministic, so signing the same text with the same key gives these exact bytes. |

Points that are easy to get wrong, which this key exercises:

- **The public key's base64 contains `+`**, which is also the separator in a key string. Only the
  separators before the key split it. A parser that splits on every `+` rejects this key, and
  tally's own first one did.
- **The signed message is the text including its final newline**, and excluding the blank line.

The key id was also recomputed outside Go, and `golang.org/x/mod/sumdb/note` parses both keys,
opens the note, and produces the same note bytes when signing the same text.

## `checkpoints.json`

One checkpoint (SPEC §5.2) over the head of `records.json`: `size` 5, `head_hex` the last record's
`leaf_hash_hex`, `recorded_at` the head entry's, and `state` `closed`. It is signed with the test key of
`keys.json`, and `note` is the whole signed note.

To check an implementation: open `note` under the verifier key (SPEC §5.4), parse `text` (§5.2), and
verify `records.json` with this checkpoint (§7). The result is a valid log of size 5, all of it
attested. `golang.org/x/mod/sumdb/note` also opens this note under the published key.

Points that are easy to get wrong:

- **`recorded_at` always has nine fractional digits**, and ends in `Z` (§5.2). Here the digits happen to
  end in a non-zero, but a formatter that trims trailing zeros, such as Go's `time.RFC3339Nano`, is
  still wrong.
- **The size counts leaves, genesis included.** Four entries make a size of 5 (§2.4).

## `segments.json`

`records.json` and the checkpoint of `checkpoints.json` as a writer stores them on disk (SPEC §3), each
file as `hex` under its `name`:

| File | What it holds |
| --- | --- |
| `0000000000000000.tlog` | The header (§3.1: `first_seq` 0, `prev_hash` all zero) and the five records, framed (§3.2). |
| `checkpoints.tlc` | The header (§3.4) and the one checkpoint, framed. |
| `0000000000000005.tlog` | A header and no frame: `first_seq` 5 and `prev_hash` the last record's `leaf_hash_hex`. A writer starts it right after storing the checkpoint of size 5 (ADR-0019). |

To check an implementation: read the records and the checkpoint out of these files and verify them as
`checkpoints.json` says. A writer given the same records and checkpoint, and rotating at it, produces
these bytes.
Every frame's CRC was also recomputed outside Go, with a bitwise CRC-32C checked against the
standard check value `0xE3069283` for `"123456789"`.

Points that are easy to get wrong:

- **A frame's CRC is CRC-32C (Castagnoli)**, not the IEEE CRC-32 most libraries default to.
- **The header-only segment is valid only as the last one** (§3), and its `prev_hash` is what the
  checkpoint of size 5 is matched against (§7 step 5).

## `merkle.json`

The RFC 6962 tree over the five leaves of `records.json` (SPEC §3.6), every hash as hex:

| Key | What it is |
| --- | --- |
| `leaf_hashes_hex` | The leaves, which are `records.json`'s `leaf_hash_hex` in order. |
| `roots` | The root of every size from 1 to 5. |
| `inclusion` | The inclusion proof of every leaf in the tree of 5. |
| `consistency` | The consistency proof from every size from 1 to 5, to 5. An equal size has an empty proof. |
| `compact_ranges` | The compact range below every start from 1 to 5, largest subtree first. |

To check an implementation: build the tree from the leaves and compare. Every entry was also checked
against `golang.org/x/mod/sumdb/tlog` (`interop/merkle_test.go`), an independent implementation.

Points that are easy to get wrong:

- **The interior prefix is `0x01`**, and leaves keep their `0x00` (§2.3).
- **The split is the largest power of two strictly below the size**, so a tree of 5 is `[0, 4)` and `[4, 5)`.
- **A consistency proof from a power of two omits that size's root**, which the checker supplies (RFC 6962).
- **Genesis is leaf 0**, so a range below 3 covers genesis and the first two entries.

## `pruned-range.json`

The `pruned.range` file (SPEC §3.6) a prune writes when it keeps records from 3 on and from 5 on, as `text`,
for the compact ranges of `merkle.json` with the same `start`. A writer produces these bytes, and a reader
accepts nothing else.

## `seal.json`

SPEC §4's sealing with every random input fixed: a DEK of `0x42` repeated and a nonce of `00 01 … 0b`, over
the `log_id`, `event_id` and `subject_ref` of `records.json`'s sealed entry. `aad_hex` is the §4 AAD and
`payload_hex` the payload, format byte and nonce included. **A real DEK and nonce are random;** these are
fixed only so that the output can be checked.

To check an implementation: build the AAD from the three fields and compare with `aad_hex`, then seal
`plaintext_hex` under `dek_hex` and `nonce_hex` and compare with `payload_hex`.

Points that are easy to get wrong:

- **The AAD is length-prefixed, field by field** (§1), not concatenated: `event_id` and `subject_ref`
  each carry a 4-byte length, so no boundary between them can shift.
- **The tag string comes first,** with its own length prefix, and `log_id` is fixed-width with none.

The AAD and the payload were also recomputed outside Go, with Python's `cryptography` (OpenSSL's
AES-GCM) and the AAD assembled by hand from §1.

## How they are made

`TestRecordVectors`, `TestKeyVectors`, `TestCheckpointVectors`, `filestore`'s `TestSegmentVectors` and
`seal`'s `TestSealVector` compare these
files with the implementation on every run, and never rewrite them. A suite that regenerated vectors
would update them silently on a format break, which is the one change they exist to catch. To
regenerate them after a deliberate format change:

```bash
go test -run 'TestRecordVectors|TestKeyVectors|TestCheckpointVectors' -write-vectors .
go test ./filestore -run TestSegmentVectors -write-vectors
go test ./seal -run TestSealVector -write-vectors
```

Then review the diff. A format change updates `docs/SPEC.md` and these vectors in the same pull request.

The genesis vector is the record that `record_test.go` assembles by hand from the spec. Its leaf
hash, and the leaf hash of every vector here, were also recomputed outside Go:

```bash
printf '00%s' "<body_hex>" | xxd -r -p | shasum -a 256
```
