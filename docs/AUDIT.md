# Clean-session audits

Two audits so far: [v0.2.0's](#v020-the-tree-the-checkpoints-and-the-witness), of what M11 added, and v0.1.0's,
below it.

## v0.2.0: the tree, the checkpoints and the witness

### How it was run

- **Audited:** the `v0.2.0` tag, 2026-11-19, as a copy with no git history and no `CHANGELOG.md`.
- **Auditor:** an agent of a **different model** (Claude Sonnet 5.5) from the one that wrote the code (Claude Opus
  5.5), with none of the design conversation in its context. That answers this file's own recommendation after
  v0.1.0 halfway: independent of context and of model, not of vendor or of a person.
- **Scope:** `internal/merkle`; the pruned range; the checkpoint pair and the writer; `Verify`'s bodies, roots,
  forks, heartbeat and witness options; `internal/note`'s cosignatures; the `witness` package and
  `tally witness serve | push`. Every finding needed a file, a line, a path and a reproduction.
- **Each reproduction was run again before its fix**, and each fix has a test seen failing without it.

### Findings

| | Severity | Finding | Outcome |
| --- | --- | --- | --- |
| A2-01 | MEDIUM | A quorum above 1 could not be met by the documented flow: each push publishes one witness's cosignature per note, and `Verify` counted per note, so two witnesses at quorum 2 left an honest log `UnwitnessedTail`. Fail-closed, but THREAT-MODEL and ADR-0021 presented the quorum as a mitigation | **Fixed**, #154: counted across notes of one size and root |
| A2-02 | LOW | With the log's key, the witness can be made to cosign an invented size (2^40, with a proof of invented hashes), after which no honest push is accepted. Inherent to add-checkpoint: a witness cannot know the leaves | **Accepted and documented**: T-09's residual, the RUNBOOK's recovery, ADR-0021's amendment |
| A2-03 | LOW | On a log v0.1 pruned, a `pruned.range` the host planted was adopted on reopen, and the log's own key signed a root over a prefix nothing had checked; `Verify` then reported the log intact | **Fixed**, #155: a range is used only once a signed root at or above its start has checked it |
| A2-04 | LOW | Two refusals had no test that removing them would fail: the writer refusing a tampered range on reopen, and a prune refusing a range below the first segment | **Fixed**, #155: both tested, each seen failing |
| A2-05 | LOW | Nothing enforced "prune only at a checkpoint the witness cosigned"; a prune above it stranded the witness until a manual reset | **Fixed**, #156: `tally prune --witness-key` refuses it |
| A2-06 | LOW | Documentation against the code: SPEC said a verifier never reads the range (it does, to compare signed roots); ADR-0021 said `AttestedSize` counts only witnessed checkpoints (it does not); "a false range never makes a comparison pass" held only given a signed root; nothing said an incremental verify cannot see the witness | **Fixed**, docs: SPEC §3.6 and §7 step 5, the RUNBOOK, ADR-0021's amendment |
| A2-07 | info | A crash between the pair's two notes leaves a `tlog-checkpoint` last, whose missing time drops the "never earlier than the last checkpoint" floor for the next one; and `Prune` and `witness push` hold 32 bytes per leaf | **Open**, unreproduced: the first needs a faulting store and a regressing clock; the second is memory in operator commands, not a bound on untrusted input |

### What held

Checked by the auditor, with what it did:

- **The proofs.** `VerifyInclusion` and `VerifyConsistency` against RFC 9162's text step by step, and 33,620
  consistency cases by brute force: every fork point and every pair of sizes up to 40. A proof verified exactly
  when the two trees share the prefix.
- **The witness.** The old-size, size, consistency, same-size root and durable-write checks each failed a test
  when removed. Requests and state files are bounded before reading. A rollback is answered 400 or 409 with no
  state change.
- **The cosignatures.** One alone never accepts a note. A bad one from a trusted witness is `BadSignature`.
  The origin is in the signed text, so a cosignature cannot move between logs.
- **The three bodies.** None parses as another, extension lines are refused, and only timed notes feed the
  heartbeat and time order.
- **The pruned range against a host without the key.** No panic or allocation from a malformed one. A garbled
  one drops the tree, never invents a root.
- **The CLI.** Verdict last, values sanitized. `--require-witnessed` without a witness is an error. The push
  checks the cosignature before publishing.

### What was not covered

- **Fuzzing:** none beyond the existing targets and the brute-force proof test.
- **Packages:** `anchor/`, `seal/`, `tallytest`, `internal/fsx` and `internal/wire` were not reviewed, except where
  v0.2 uses them.
- **The witness as a real process:** two processes on one state directory (there is no file lock), TLS, slow
  clients, and real crashes and fsync failures in `Prune` and the witness.
- **Very large logs:** memory and time were not measured.
- **The Raspberry Pi procedures** were not repeated.

## v0.1.0

RS-16 asks for a final audit **in a clean session, by someone who did not write the code** (#56). This is its
record: what was audited and how, what it found and what became of each finding, what held, and what was not
covered.

### How it was run

- **Audited:** `develop` at `f2e5707`, 2026-11-18.
- **Auditor:** a fresh agent with none of the design conversation in its context. Its inputs were
  `REQUIREMENTS.md`, `docs/THREAT-MODEL.md`, `docs/SPEC.md`, `docs/architecture.md`, `docs/adr/`,
  `docs/RUNBOOK.md`, `README.md` and the code. `CHANGELOG.md` and the git history were withheld, since they
  record the authors' reasoning.
- **What it was asked to test:** every threat's mitigation, and whether its residual is complete and honest; the
  invariants; the verifier against SPEC §7; `filestore`, `seal` and the CLI. Every finding needed a file, a line,
  a path to the problem and a reproduction, or was to be marked unreproduced. It worked in a copy and changed
  nothing in the repository.
- **The independence is of context, not of author.** The auditor is the same model that wrote the code. It had
  no access to the reasons the code was written the way it was, which is what RS-16 is after, but it shares the
  author's training, and a defect both are blind to the same way would pass. An audit by a person, or by a
  different model, remains worth doing.
- **The findings were reproduced again before they were fixed**, by running the auditor's tests.

### Findings

| | Severity | Finding | Outcome |
| --- | --- | --- | --- |
| A-01 | HIGH | `tally.Open` reopened a log its own last stored checkpoint contradicted, and the writer's next checkpoint signed the rewritten history with the real key. Records are not signed, so this needed no key | **Fixed**, #129 (#126). Open compares the leaf at the checkpoint's size with its head, and the checkpoint's signature under the signer's key with the signer's own. A rewrite that also deletes the checkpoints after it is still signed: **T-06 is now partial**, and the attack suite asserts that limit |
| A-02 | MEDIUM | One length field changed to run past the end of a segment was recovered as a torn write, and every acknowledged entry after it was dropped | **Fixed**, #130 (#127). A cut-off frame with a complete frame after it is a bad middle, and Open refuses |
| A-03 | LOW | The verifier accepted a segment header naming another `log_id`, or a `prev_hash` its first record does not chain to | **Fixed**, #131 (#128) |
| A-04 | LOW | Truncation below a start or anchored checkpoint, and a broken genesis with two origins, came back as errors (exit 2) rather than violations | **Fixed**, #131 (#128) |
| A-05 | LOW | Prune's documentation said the segment holding record `size - 1` is kept; at a segment boundary it is not | **Fixed**, docs, #131 (#128). The behaviour was right |
| A-06 | LOW | An anchored checkpoint dated after now hid every heartbeat gap | **Fixed**, #131 (#128) |
| A-07 | LOW | A sealed payload's length is in clear (the plaintext's plus 29 bytes) and survives a shred, and nothing said so | **Accepted and documented**, #131 (#128): README, T-20, `Seal`. Padding to buckets is a later option |
| A-08 | LOW | `tally verify` read `--from` and `--key-file` without a bound | **Fixed**, #131 (#128) |

#### Found while fixing them

- **Zeros past the last frame read as frames**, found while checking A-02's fix against preallocated tails. A
  length of 0 has the CRC of nothing, which is also 0, so 4096 zeros read as 512 empty frames. Nothing was
  recovered, and the store returned empty records. **Fixed** in #130: a frame of length 0 is not a frame.
- **A-01's limit is wider than the audit stated.** It said deleting the checkpoints file. Deleting only the
  checkpoints after the rewritten point is enough, so that no stored checkpoint contradicts the rewrite. T-06
  says so.
- **`TestASignerNeverPrintsItsKey` in `internal/note` is flaky.** It looks for the decimal of one key byte,
  `171`, and a pointer address printed by `%d` can contain it. It failed once in this work, and passed 60 times in
  a row since. **Fixed** in #136: the bare pattern is gone, and the seed as `%v` and `%d` print it is still
  checked.

### What held

Checked by the auditor, with what it did:

- **Build and tests.** `go build`, `go vet` and `go test -race -shuffle=on`, interop included, all pass.
- **No `unsafe`, `reflect`, `init()` or `panic` in non-test code.** By search.
- **The wire codec** checks limits before allocating, rejects trailing bytes and invalid UTF-8, and re-encodes
  every decoded record. Each fuzz target ran 25 s with no failure.
- **The leaf hash is over stored bytes.**
- **Every byte of every record and checkpoint, flipped with the CRC recomputed, is detected.** The only
  exception was the segment 0 header, A-03, now detected too.
- **Truncation and rollback against an anchor** are `TruncatedBelowCheckpoint`. A keyless rewrite against the
  old checkpoints is `CheckpointMismatch`.
- **No receipt before durability.** Any store error poisons the log, there is no fsync retry, and files and
  directories are fsynced (RF-01, ADR-0009).
- **Quarantine** is durable before any truncation and never overwrites; a bad middle is refused; the
  checkpoint floor is enforced (RF-20).
- **No key** reaches any `fmt` verb on a KEK, a vault or a signer, or a struct holding one (RS-07).
- **Locking, permissions and atomic writes** (RS-09, RS-10, RS-15).
- **The CLI sanitizes every log-derived string** it prints (RS-13). Its exit codes hold, and its files are
  created exclusively, never overwritten.
- **`anchor.Dir`** is create-only.
- **`seal`:**
  - the AAD is length-prefixed;
  - wrapped keys are bound to their ref;
  - shred removes the ref, then the index, each fsynced;
  - KEK rotation rewraps without changing the data keys.

### What was not covered

- **Supply chain (T-18):** the release, the SBOM and reproducible builds. These are M10's.
- **Linux-only behaviour,** preallocation and free space included. The audit ran on macOS. CI runs Linux, but
  nobody reviewed the Linux code paths.
- **`golangci-lint`, `gosec`, and the boundary and doc checks.** The auditor did not run them; CI does.
- **Long fuzzing campaigns.** Only 25 s per target was run, and there is no fuzz target for `Verify` over whole
  directories. The byte-flip test stood in for one.
- **A live log read while it is written,** and `Close` and `Checkpoint` interleavings beyond the existing `-race`
  suite.
- **The usher integration and the end-to-end demo, and the RUNBOOK drills.** The drills pass as tests and were
  not reviewed. NFS and SMB are unsupported and untested.
- **Crashes inside `Shred` and `RotateKEK`.** Checked by reading the code, with no fault injection.
