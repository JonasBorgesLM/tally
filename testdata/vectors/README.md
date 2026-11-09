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
  bytes standing for ciphertext and tag. They are **not** real AES-GCM output. Sealing vectors with
  a fixed DEK and nonce come with #44.

## Not here yet

- **Keys and checkpoints** (SPEC §5) come with the signed-note implementation (#25, #26).
- **Segment files** (SPEC §3) come with the file store (#33).

## How they are made

`TestRecordVectors` in `vectors_test.go` compares these files with the encoder on every run, and never
rewrites them. A suite that regenerated vectors would update them silently on a format break, which is
the one change they exist to catch. To regenerate them after a deliberate format change:

```bash
go test -run TestRecordVectors -write-vectors .
```

Then review the diff. A format change updates `docs/SPEC.md` and these vectors in the same pull request.

The genesis vector is the record that `record_test.go` assembles by hand from the spec. Its leaf
hash, and the leaf hash of every vector here, were also recomputed outside Go:

```bash
printf '00%s' "<body_hex>" | xxd -r -p | shasum -a 256
```
