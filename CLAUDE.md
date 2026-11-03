# CLAUDE.md

Guidance for Claude Code in this repository. The general engineering rules are in
`~/.claude/CLAUDE.md`; this file carries only what is true of tally.

**Status: design stage.** No library code exists. `REQUIREMENTS.md`, `docs/SPEC.md`,
`docs/THREAT-MODEL.md` and `docs/architecture.md` are the plan the code is checked against.
Work is tracked on the [project board](https://github.com/users/JonasBorgesLM/projects/9).

## Project Overview

tally is a Go library and CLI for tamper-evident audit logging: a hash chain, signed checkpoints
anchored off the host, offline verification and crypto-shredding. First consumer: usher.

**The guarantee is conditional, and every claim must stay conditional:** given a trusted
checkpoint from outside the compromised host, tampering with entries it covers is detectable. It
detects; it does not prevent. Nothing past the last trusted checkpoint is covered.

**Not responsible for**, each a deliberate boundary:

- Choosing between failing open and closed: `Append` reports the real error, and the application
  decides (ADR-0010).
- Querying, dashboards, observability (crier). Consensus, servers, split-view before v0.2.
- Knowing about any ecosystem project. tally imports none of them (RI-01).
- LGPD compliance. It provides a mechanism; the docs must never claim more.

## Architecture

```
cmd/tally ──▶ tally, filestore, anchor
filestore, anchor, seal, tallytest ──▶ tally ──▶ internal/wire, internal/note
filestore ──▶ internal/fsx
```

- The root imports only `internal/*`. `internal/*` imports nothing above it.
- The module is stdlib only (RNF-01). `interop/` (from #30) has its own `go.mod`.
- A new package gets added to `KNOWN` in `check-boundaries.sh`, or it fails.

## Commands

```bash
go build ./... && go vet ./... && go test -race -shuffle=on ./...
golangci-lint run
gosec -tests -exclude-generated ./...
./.github/scripts/check-boundaries.sh
./.github/scripts/check-docs.sh
```

`interop/` will need its own commands: `go test ./...` at the root does not descend into it.

## Conventions

- English in code, comments, docs, ADRs, issues and commits.
- Git flow and commit format are in `CONTRIBUTING.md` and checked by CI: `<type>/<issue>-<name>`
  branches squash into `develop`; only `release/*` and `hotfix/*` reach `main`, by merge commit;
  tags are signed and never moved.
- Requirement ids are `RF-`, `RS-`, `RNF-`, `RI-`; threats are `T-nn`; review findings are `R-nn`;
  milestones are `Mn`. Cross-project citations are qualified (`usher/RI-03`), since an unqualified
  one is checked against this project's numbering. Threat ids have no such exemption: do not cite
  another project's `T-nn` at all.
- ADRs are never rewritten: amend or supersede. CI enforces "may gain lines, never lose them".
- A format change updates `docs/SPEC.md` and `testdata/vectors/` in the same pull request.

## Testing

- **Mutation tests recompute the CRC** (R-28). Otherwise the CRC catches the change, the hash chain
  is never reached, and the test passes while proving nothing.
- Each threat has a test in the attack suite. Partial threats also assert their limit.
- Every protection has a test seen failing with the protection removed, noted above the test.
- A loop over offsets asserts how many it ran: zero iterations must fail.

## Known Constraints

- **The anchor's security is a property of the deployment that the library cannot check** (RS-17). A
  host-writable directory runs and reports intact, and protects nothing.
- A heartbeat proves the signer ran, not that the log is complete (T-15). Do not write otherwise.
- NFS and SMB are unsupported: `flock` and `fsync` are unreliable there. Windows is out of scope.
- `usher/ADR-0017` rejected failing closed. tally's integration needs a new usher ADR (#51).

## Non-negotiable Invariants

1. **No `Receipt` before the entry is durable** (RF-01). A receipt for a lost entry falsifies the only
   promise this library makes.
2. **Any store error poisons the log; never retry an fsync** (ADR-0009). After a failed fsync, a retry
   can report success with the data gone (PostgreSQL's fsyncgate).
3. **The verifier hashes stored bytes, never a re-encoding** (RS-03), and every decoded record must
   re-encode to the same bytes (RS-02).
4. **`Verify`'s `error` means could not verify; a violation is in `Report`** (§5.1). Any parse failure is
   a violation (RS-04). A partial read never reports success.
5. **Sizes are checked before allocating** (RS-05). A decoder that trusts a length is a denial of service.
6. **No human identifier in clear** (RS-14), no secret in an error, log or `%v` (RS-07), no payload to the
   `Observer` (RF-16).
7. **Never truncate below the last local checkpoint, and quarantine rather than delete** (RF-20).
8. **No dependency in the core, no `unsafe`, no reflection on the encoding path** (RNF-01, RS-11). No global
   state, no `init()` registration, no panic in a normal path.
