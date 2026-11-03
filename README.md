# tally

**A tamper-evident audit log library for Go:** a hash chain, signed checkpoints anchored off the
host, offline verification, and crypto-shredding for LGPD.

> **Status: design stage. There is no library code yet, and nothing here can be installed.**
> The requirements, threat model, format specification and decisions are written and enforced by
> CI, and they are what the implementation is checked against. Progress is on the
> [project board](https://github.com/users/JonasBorgesLM/projects/9).

## What it will do

Someone who compromises a host, or an insider with privileged access, tries to erase the trace of what
they did. An ordinary log cannot prove its history is intact. tally records events in an append-only
chain, signs checkpoints, publishes them where the host cannot change them, and verifies offline,
pointing at exactly where and how the chain was violated. Personal data is sealed so it can be erased
without breaking the chain.

## The guarantee, stated honestly

> **tally detects tampering; it does not prevent it.** Given a trusted checkpoint obtained from outside
> the compromised host, any alteration, removal, insertion or reordering of entries covered by that
> checkpoint is detectable.

What that does not cover, in the terms you would otherwise assume:

- **Anything past the last anchored checkpoint**, against whoever holds the host and the key.
- **An event that was never submitted.** A heartbeat proves the signer ran, not that the log is complete.
- **A host-writable "anchor".** An anchor must be something the host holds no credential to alter. A
  directory mounted on the host runs fine, reports intact, and protects nothing.
- **Real time,** split view (until v0.2), and legal compliance. Crypto-shredding is a mechanism, and LGPD
  conformance depends on the operator's process and counsel.

The full list, with a residual for each threat, is in [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).

## Documents

| | |
| --- | --- |
| [`REQUIREMENTS.md`](REQUIREMENTS.md) | What it must do, with the ids everything else cites, and the review record |
| [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) | Threats, mitigations and residuals |
| [`docs/SPEC.md`](docs/SPEC.md) | The format, enough to write an independent verifier |
| [`docs/architecture.md`](docs/architecture.md) | Packages, real signatures, flows |
| [`docs/adr/`](docs/adr/README.md) | Decisions, with the alternatives they rejected |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Git flow and commit format, checked by CI |
| [`SECURITY.md`](SECURITY.md) | Private vulnerability reporting |

## Part of an ecosystem, depending on none of it

tally imports no other library from this ecosystem, and that is enforced against the Go resolver.
Applications wire things together: [usher](https://github.com/JonasBorgesLM/usher) is the first
intended consumer, through an integration that still needs a decision on its side.

## License

[MIT](LICENSE).
