# ADR-0003: Records use a strict fixed-width binary encoding, and stored bytes are hashed bytes

## Status
Accepted — 2026-11-03

## Context
A hash chain authenticates bytes. If one value has several encodings, a verifier can pass
something a reader understands differently. Go's `binary.Uvarint` accepts `0x80 0x00` as
`0` (R-06).

## Decision
Fixed-width big-endian integers and length-prefixed bytes, with no varint. The decoder
rejects trailing bytes, unknown version and type and invalid UTF-8, and every decoded
record is re-encoded and compared (RS-02). The verifier hashes bytes as stored, never a
reconstruction (RS-03). JSON exists only in `export`.

## The alternative that was rejected
**Canonical JSON or CBOR.** Readable and self-describing, with existing tooling. Rejected
because each needs a canonicalisation rule that a second implementation will get subtly
different, and the point of this format is that it has only one valid form. **Protobuf**
does not guarantee canonical bytes at all.

## Consequences
A log cannot be read with `cat`, which `export` exists to soften. Fixed-width integers
cost a few bytes per record over varint, which is irrelevant here.
