# tally — Threat Model

**Scope:** the integrity and completeness of an audit log, the confidentiality of the
personal data in it, and the trust an auditor places in the verdict.
**Companion to:** [`REQUIREMENTS.md`](../REQUIREMENTS.md) — every mitigation names the
requirement that discharges it, and every security requirement appears at least once.

> A threat model that lists only the threats it defeats is marketing. §7 is what makes this
> one honest.

**Status of every claim here: designed, not implemented.** A threat counts as mitigated
when its test in the attack suite (#47) has been seen failing with the protection removed.

---

## 1. What is being protected

| Asset | Why it matters | Exposure |
| --- | --- | --- |
| Integrity and completeness of the history | It is the reason the log exists | Host, insider |
| Confidentiality of personal payloads | LGPD; a log outlives its purpose | Disk, backups |
| Signing key | Whoever holds it can write a consistent false history | Host (by default) |
| Vault of DEKs | Opens every payload | Vault host, backups |
| Anchored checkpoints | The only trust that survives a host compromise | Anchor destination |
| Verifier binary | The auditor's root of trust | Supply chain |

**The asymmetry that drives the design:** everything on the host can be rewritten by whoever
takes the host, including the key. Only what left the host, to somewhere the host cannot
change, survives. So the anchor's real property (T-21) carries most of the guarantee, and
everything written after the last anchored checkpoint carries none against that attacker.

## 2. Actors and capabilities

| Actor | Assumed capability | Assumed *not* to have |
| --- | --- | --- |
| Outsider with a file read or write bug | Reads or alters files, not the key in memory | Code execution, key material |
| Host attacker | Root: log, signing key, clock, process, any mounted directory | Credentials to alter the anchor's history, the vault if it is elsewhere |
| Insider operator | As host attacker, with legitimate access | As host attacker, assuming duties are separated; **if one person runs host and anchor, the anchor protects nothing against them** |
| Caller application bug | Reuses `EventID`, passes identifiers in fields | Malice |
| Malicious log content | Controls `resource`, `event_id`, payload text | Anything on the auditor's machine except its terminal |
| Supply-chain attacker | Publishes an altered verifier | The release signing key and the build provenance |

Victim, not attacker: the **auditor**, who acts on the verdict, and the **data subject**, who
cannot inspect any of this.

## 3. Trust boundaries

```
 application host                    │  off the host, host cannot alter
 ┌───────────────────────────────┐   │   ┌──────────────┐     ┌──────────────┐
 │ app ─▶ tally.Log ─▶ segments  │   │   │   anchor     │────▶│   auditor    │
 │          │ signer (key)       │ ──┼──▶│ pull or WORM │     │ pubkeys, bin │
 │          └▶ anchor spool      │   │   └──────────────┘     └──────────────┘
 └───────────────┬───────────────┘   │
                 ▼                   │   ┌──────────────┐
          vault (other directory; ───┼──▶│ vault, ideally another host
          preferably other host)     │   └──────────────┘
```

- **Host to anchor:** nothing on the far side trusts the host. The near side may assume
  nothing it already published can be withdrawn, *if* RS-17 holds in the deployment.
- **Log to auditor's terminal:** every log field is untrusted text (T-17).
- **Log to vault:** the log holds only opaque refs; the mapping to people stays in the vault.

## 4. Threats

### T-01 — Alter an entry's content
**Actor:** host attacker, outsider. **Impact:** a false record of what happened.
**Mitigation:** RS-03, RS-04, RF-08, RF-18: the successor's `prev_hash` or the checkpoint head no longer matches.
**Residual:** **detected only if covered.** The leaf hash is not stored, so changing an entry past the last checkpoint, with no following entry, is undetectable even without the key. `Report` shows `UnattestedEntries`, and `WithRequireFullyAttested` fails on it.

### T-02 — Remove an entry from the middle
**Actor:** host attacker. **Impact:** a hidden action.
**Mitigation:** RF-08: `prev_hash` and the `seq` gap.
**Residual:** none within the attested range; tail as T-01.

### T-03 — Insert a forged entry in the middle
**Actor:** host attacker. **Impact:** a framed action.
**Mitigation:** RF-08: `prev_hash` of the next entry.
**Residual:** a key holder can rewrite everything after the insertion, which is T-07.

### T-04 — Reorder entries
**Actor:** host attacker. **Impact:** a false sequence of events.
**Mitigation:** RF-08: `seq` and `prev_hash`.
**Residual:** none within the attested range; tail as T-01.

### T-05 — Truncate the end
**Actor:** host attacker. **Impact:** the most recent actions vanish.
**Mitigation:** RF-09, RS-17: an anchored checkpoint has a larger `size`.
**Residual:** entries past the last anchored checkpoint vanish undetected. The checkpoint interval (RF-06) sets the exposure window.

### T-06 — Rewrite from a point, without the key
**Actor:** outsider with file write. **Impact:** a consistent false suffix.
**Mitigation:** RF-06, RF-10: existing checkpoint signatures fail. RS-06 keeps the key separate.
**Residual:** if the rewrite leaves all checkpoints intact it can only touch the tail, as T-01.

### T-07 — Rewrite with the key, host compromised
**Actor:** host attacker. **Impact:** a fully consistent, correctly signed false history.
**Mitigation:** RF-09, RS-17: a fork against any anchored checkpoint.
**Residual:** **no guarantee past the last anchored checkpoint.** An attacker holding the key and the host writes anything from there. ADR-0015 records why the signer is in process in the MVP.

### T-08 — Roll back to an older checkpoint
**Actor:** host attacker. **Impact:** the log appears earlier than it is.
**Mitigation:** RF-09, RS-17: the anchor holds a newer checkpoint.
**Residual:** requires the auditor to read the anchor rather than anything on the host.

### T-09 — Split view
**Actor:** host attacker. **Impact:** different auditors see different histories.
**Mitigation:** none in v0.1. Witnesses in M11.
**Residual:** **not detected in v0.1,** unless auditors compare notes or all read one anchor that cannot itself equivocate.

### T-10 — Splice across logs
**Actor:** host attacker. **Impact:** one log's entries pass as another's.
**Mitigation:** RF-05, RF-08: `log_id` in every entry, `origin` in every checkpoint.
**Residual:** none known, conditional on `origin` being unique per log, which is the operator's job.

### T-11 — Duplicate an entry
**Actor:** host attacker, caller bug. **Impact:** an action seems to have happened twice.
**Mitigation:** RF-04, RF-17, RF-08: monotonic `seq`, idempotency window, conflict refused.
**Residual:** past the window, a retried `EventID` is a new entry. A verifier sees two entries, not a corrupt log.

### T-12 — Corruption by crash
**Actor:** none (failure). **Impact:** a torn tail.
**Mitigation:** RF-20, RS-10: CRC per record, recovery of the tail, directory fsync.
**Residual:** after a failed fsync, the page cache can show data that never reached disk; a reopen in the same boot trusts it (R-31, ADR-0009).

### T-13 — Non-canonical bytes with the same meaning
**Actor:** host attacker. **Impact:** one record with two valid forms, which breaks reasoning over hashes.
**Mitigation:** RS-02, RS-03, RS-05, RS-11.
**Residual:** none known; asserted by fuzzing's round-trip property.

### T-14 — Backdating by the caller
**Actor:** caller, host attacker. **Impact:** a false time of occurrence.
**Mitigation:** RF-03: `occurred_at` is untrusted by definition, `recorded_at` is monotonic.
**Residual:** **partial.** The host clock is not trusted; `recorded_at` is not proof of real time, and a key holder chooses it. RFC 3161 is deferred.

### T-15 — Suppression
**Actor:** host attacker, insider. **Impact:** actions are never recorded.
**Mitigation:** RF-06, RF-09: a gap between anchored checkpoints beyond `T + tolerance`.
**Residual:** **partial, and this is the weakest claim here.** A heartbeat proves the signer ran, not that the log is complete: whoever controls the application drops selected events and keeps emitting heartbeats, and no local mechanism can see an event that was never submitted. Only comparison with another record of the same actions can. Checkpoint times are self-asserted, so a gap is credible only when the off-host side observes when things arrived. A crash and an attack look alike. And `tlog-checkpoint` has no time line, so this changes at v0.2 (#60).

### T-16 — Fill the disk
**Actor:** host attacker, runaway process. **Impact:** every fail-closed action stops.
**Mitigation:** RNF-10, RF-16: preallocation, thresholds, runbook.
**Residual:** **mitigated, not prevented.** A disk full is still an outage, by design: failing closed is what was asked for.

### T-17 — ANSI injection in the auditor's terminal
**Actor:** malicious log content. **Impact:** a forged `OK` line, a hidden failure.
**Mitigation:** RS-13.
**Residual:** none for the CLI's own output. A tool reading `export` output must treat it as untrusted.

### T-18 — A tampered verifier binary
**Actor:** supply-chain attacker. **Impact:** "intact" for anything.
**Mitigation:** ADR-0014, §13 of the requirements: reproducible build, signed checksums, SBOM, provenance.
**Residual:** a compromised build environment or auditor machine; and the auditor must actually run the check. The SPEC allows an independent verifier for that reason.

### T-19 — Read personal payloads on disk or in a backup
**Actor:** outsider with file read. **Impact:** a personal data leak.
**Mitigation:** RS-12, RS-19, RF-11, RS-07.
**Residual:** an attacker on the host sees plaintext as it is sealed, and metadata stays in clear by design. The vault in the same domain as the log removes this protection.

### T-20 — Link old entries to a person after a shred
**Actor:** anyone holding the log. **Impact:** erasure undone in practice.
**Mitigation:** RS-14, RS-18, RF-11, RF-12: random ref, mapping destroyed in the shred.
**Residual:** **partial.** The ref still links that subject's entries to each other, so timing and pattern may re-identify. `resource` and `event_id` are free of people only as far as RS-18's charset reaches. An older vault backup restores the mapping. Deleting on SSD or a journaling filesystem does not destroy, so a recovered wrapped DEK plus a later KEK leak reopens the payload. Conformance needs legal counsel.

### T-21 — Rewrite the anchor from the host
**Actor:** host attacker. **Impact:** T-05, T-07, T-08 and T-15 all stop being detectable, and everything still looks healthy.
**Mitigation:** RS-17: the host holds no credential that can alter or delete; `anchor.Dir` is a create-only spool that something off-host pulls.
**Residual:** **the library cannot verify this property of a deployment.** A mounted directory type-checks and works. Between publication and pull, a spool on the host is still host-controlled, so the pull interval adds to the exposure window. If the same person controls both sides, this protects nothing against them.

### T-22 — Tampering disguised as a crash
**Actor:** host attacker. **Impact:** a damaged tail is accepted as an ordinary recovery.
**Mitigation:** RF-20: nothing below the last local checkpoint is truncated, truncated bytes are quarantined and reported, and RF-09 catches anything below an anchored checkpoint.
**Residual:** a torn write and a flipped bit in the last acknowledged entry can look identical, so one acknowledged entry past the last checkpoint can be lost without proof it was malicious. Quarantine preserves the evidence; it does not settle the question.

## 5. Coverage matrix

| Threat | Requirements |
| --- | --- |
| T-01 | RS-03, RS-04, RF-08, RF-18 |
| T-02 | RF-08, RS-04 |
| T-03 | RF-08, RS-04 |
| T-04 | RF-08, RS-04 |
| T-05 | RF-07, RF-09, RF-19, RS-17, RS-20 |
| T-06 | RF-06, RF-10, RS-01, RS-06, RS-07 |
| T-07 | RF-09, RS-06, RS-17 |
| T-08 | RF-09, RS-17 |
| T-09 | — (M11) |
| T-10 | RF-05, RF-08 |
| T-11 | RF-04, RF-08, RF-17 |
| T-12 | RF-20, RS-09, RS-10, RS-15 |
| T-13 | RS-02, RS-03, RS-05, RS-11 |
| T-14 | RF-03 |
| T-15 | RF-06, RF-09 |
| T-16 | RF-16, RNF-10 |
| T-17 | RS-13 |
| T-18 | RS-16 (audit reaches the release path), §13 of the requirements |
| T-19 | RF-11, RS-07, RS-08, RS-12, RS-19 |
| T-20 | RF-11, RF-12, RS-14, RS-18 |
| T-21 | RS-17 |
| T-22 | RF-20, RF-09 |

Every `RS-` id appears above. RS-08 and RS-09 are hardening: RS-08 keeps a secret comparison
from leaking, and RS-09 prevents an accident rather than an attack.

## 6. Verification

Each `T-nn` becomes a named test in the attack suite (#47), and each partial threat also
asserts its limit, so that the README cannot overclaim. Each security requirement gets a test
validated by a negative control. The clean-session audit (RS-16) tests the claims in this
document, residuals included.

## 7. What this does not protect against

Stated plainly, since these are what someone would assume otherwise:

- **Anything past the last anchored checkpoint**, against whoever holds the host and the key.
- **An event never submitted.** tally records what it is given. The application is in the
  trusted computing base for completeness.
- **A dishonest application at write time:** it can record a false event, correctly signed.
  The log proves what was recorded, never that it was true.
- **One person controlling both the host and the anchor.** Separation of duties is
  operational; no library provides it.
- **A deployment that ignores RS-17.** It will run, and report "intact", and mean much less.
- **Split view in v0.1** (T-09).
- **Real time.** No proof a checkpoint existed at the moment it claims (T-14).
- **Availability.** Failing closed turns an audit failure into an outage, on purpose, for
  privilege-granting actions.
- **Legal compliance.** Crypto-shredding is a mechanism.
