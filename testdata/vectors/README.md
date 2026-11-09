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

## Not here yet

- **Segment files** (SPEC §3) come with the file store (#33).

## How they are made

`TestRecordVectors`, `TestKeyVectors` and `TestCheckpointVectors` (in the `*vectors_test.go` files) compare these
files with the implementation on every run, and never rewrite them. A suite that regenerated vectors
would update them silently on a format break, which is the one change they exist to catch. To
regenerate them after a deliberate format change:

```bash
go test -run 'TestRecordVectors|TestKeyVectors|TestCheckpointVectors' -write-vectors .
```

Then review the diff. A format change updates `docs/SPEC.md` and these vectors in the same pull request.

The genesis vector is the record that `record_test.go` assembles by hand from the spec. Its leaf
hash, and the leaf hash of every vector here, were also recomputed outside Go:

```bash
printf '00%s' "<body_hex>" | xxd -r -p | shasum -a 256
```
