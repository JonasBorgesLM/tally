# ADR-0011: A vault holds random refs, with incarnations, and Principal is typed

## Status
Accepted — 2026-11-03

## Context
The log is immutable and LGPD requires erasure. v0.1 used an HMAC under a global secret,
with `actor` in clear: the CPF space is ~10⁹, so a leaked secret reverses every pseudonym,
and shredding the payload left who-did-what intact (R-03).

## Decision
The vault maps an identifier to a random 128-bit `SubjectRef` and a DEK, indexed by
`HMAC(vault_key, identifier)`. Only the ref enters the log. `Shred` destroys the DEK and
the index entry, and a later `Resolve` makes a new incarnation. `Principal` has no
constructor for a human identifier (RS-14), `Service` and `Resource` reject `@` and
whitespace (RS-18), and the AAD is length-prefixed (RS-19). The vault's format and KEK
rotation are specified with the implementation in M6.

## The alternative that was rejected
**Deterministic pseudonyms with no stored mapping.** No vault to run or lose. Rejected
because anything derived from the identifier can be recomputed from it, so erasure means
destroying a key shared with everyone else. **Redacting entries** breaks the chain by
definition.

## Consequences
A vault to operate, back up and keep elsewhere: an old backup undoes a shred. Losing it
loses every sealed payload. **Limits (R-34):** a shredded ref still links its entries, so
pattern and timing may re-identify. Deleting on SSD does not destroy. The charset does not
catch digits. Compliance needs counsel (T-20).
