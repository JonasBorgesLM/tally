# Clean-session audit before v0.1.0

RS-16 asks for a final audit **in a clean session, by someone who did not write the code** (#56). This is its
record: what was audited and how, what it found and what became of each finding, what held, and what was not
covered.

## How it was run

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

## Findings

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

### Found while fixing them

- **Zeros past the last frame read as frames**, found while checking A-02's fix against preallocated tails. A
  length of 0 has the CRC of nothing, which is also 0, so 4096 zeros read as 512 empty frames. Nothing was
  recovered, and the store returned empty records. **Fixed** in #130: a frame of length 0 is not a frame.
- **A-01's limit is wider than the audit stated.** It said deleting the checkpoints file. Deleting only the
  checkpoints after the rewritten point is enough, so that no stored checkpoint contradicts the rewrite. T-06
  says so.
- **`TestASignerNeverPrintsItsKey` in `internal/note` is flaky.** It looks for the decimal of one key byte,
  `171`, and a pointer address printed by `%d` can contain it. It failed once in this work, and passed 60 times in
  a row since. Not yet fixed.

## What held

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

## What was not covered

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
