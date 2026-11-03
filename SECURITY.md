# Security

## Reporting

Report privately through GitHub: **Security → Report a vulnerability** on this repository. Do not open a
public issue. Expect an answer within a week; this is a one-maintainer project.

**There is no released version yet,** so nothing is supported in production. Reports against the design are
still welcome, and useful.

## What counts

tally claims one thing: tampering with entries covered by a trusted checkpoint is detectable. In scope:

- A way to alter, remove, insert or reorder covered entries and get `OK() == true`.
- A record with two valid encodings, or bytes the verifier hashes differently from how they are stored.
- A crafted log, frame or checkpoint causing a panic, an unbounded allocation or a hang in a verifier.
- An acknowledged entry lost without a failure being reported.
- A key, DEK or KEK reaching an error, a log or formatted output.
- A payload readable without its DEK, or a shredded subject re-linked to a person through tally's data.
- Output from the CLI that a log field can forge or hide.

Out of scope, because the threat model already says so ([`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) §7):
anything past the last anchored checkpoint against whoever holds the host and key; events never submitted;
a deployment whose anchor the host can alter; split view before v0.2.

## Verifying a release

Once releases exist (#57, #58), tags are signed with a key listed in
[`.github/allowed_signers`](.github/allowed_signers), and every attached file has build provenance:

```bash
git -c gpg.ssh.allowedSignersFile=.github/allowed_signers tag -v vX.Y.Z
gh attestation verify tally_vX.Y.Z_linux_arm64 --repo JonasBorgesLM/tally
```
