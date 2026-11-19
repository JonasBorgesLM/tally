# ADR-0021: A c2sp tlog-witness on another machine cosigns consistent checkpoints, and verifiers can require it

## Status
Accepted — 2026-11-18

## Context
Split view (T-09) is undetected: a host holding the log's key can show one auditor one history and another
auditor a different one, each internally consistent and each signed. An anchor narrows it only if every
auditor reads the same anchor and the anchor cannot itself serve different copies. #61 asks for a witness on
a second machine that cosigns only checkpoints consistent with everything it has cosigned before.

v0.2 already has what a witness needs: an RFC 6962 tree over the leaves (#59), a plain `tlog-checkpoint` per
checkpoint that a witness can cosign as it is (#60, ADR-0006's amendment), consistency proofs, and a Raspberry
Pi that is not the log's host (#125). c2sp.org/tlog-witness and c2sp.org/tlog-cosignature define the protocol
and the signature, and other logs' witnesses speak them.

## Decision

1. **The protocol is c2sp.org/tlog-witness's `add-checkpoint`**, as published: `POST /add-checkpoint` with
   `old <size>`, at most 63 consistency proof lines, a blank line and the checkpoint note. Its statuses:
   - `200`: the cosignature lines;
   - `400`: an old size above the checkpoint's;
   - `403`: no valid signature from the log's key;
   - `404`: an unknown origin;
   - `409`: the old size is not the witness's, with that size in `text/x.tlog.size`;
   - `422`: a proof that fails, or two roots at one size.

   The witness tracks, per origin, only the latest checkpoint it cosigned, and **persists it before it
   answers**, the size check and the write atomic under one lock, so two requests can never roll it back.
2. **The cosignature is `cosignature/v1` over Ed25519** (signed-note type `0x04`):
   - **signed message:** `cosignature/v1`, `time <unix seconds>`, then the checkpoint body;
   - **signature line:** the key id, 8 bytes of big-endian time, then the 64-byte signature.

   It is stdlib only (RNF-01) and checkable against another implementation in `interop`.
3. **The witness is `tally witness serve`**, a stdlib `net/http` server on the second machine.
   - **User:** it runs as a dedicated `witness` user, apart from the `anchor` user of #125.
   - **Key:** generated there and never copied off.
   - **State:** one file per origin, in a 0700 directory, written atomically (RS-10).
   - **Configuration:** the logs it serves, as `origin` plus the log's verifier key. It cosigns only checkpoints
     that key signed, and ignores every other signature.
4. **The host pushes, the witness never connects.** `tally witness push`, run on the host by cron or beside the
   application, does the push:
   1. it reads the log directory read-only, and builds the consistency proof from the stored leaves and the
      pruned range (#59);
   2. it learns the witness's size from a `409`;
   3. it posts the newest `tlog-checkpoint`;
   4. it writes the cosigned note into the anchor spool, a new file beside the uncosigned one, which the anchor
      pulls as it pulls everything else (#125).

   **The witness holds no credential on the log's host**, which is #61's third done-when. **The host holds
   nothing that changes the witness's state** except a checkpoint the log's key signed and that is consistent
   with what the witness already holds.
5. **Verifiers can require it.** `Verify` gains a witness option, with trusted witness keys and a quorum:
   - **counted:** a checkpoint whose cosignatures verify, from at least the quorum of trusted witnesses;
   - **a bad cosignature** from a trusted witness key is a violation, as a bad log signature is;
   - **required (`--require-witnessed`):** `AttestedSize` counts only witnessed checkpoints, and a matched
     checkpoint without the quorum is reported, as an unattested tail is (ADR-0018).
6. **Pruning respects the witness.** A consistency proof from the witness's size needs that size at or above
   the first record kept (SPEC §3.6). So `tally witness push` refuses, saying why, when the witness's size is
   below the log's first record. The RUNBOOK prunes only at a checkpoint the witness has cosigned, which keeps
   the witness's size at or above it.

## The alternative that was rejected

- **ML-DSA-44, which c2sp.org/tlog-witness recommends.** It is post-quantum, and it is where witnesses are
  heading. `crypto/mldsa` is in the standard library from Go 1.27, and the module's floor is Go 1.26 (RNF-01):
  using it means raising the floor while 1.26 still receives security fixes, or a dependency in the core.
  Ed25519 `cosignature/v1` is in the same specification, and it is what the log's own key already uses.
- **The witness pulls from the spool, as the anchor does.** It would keep every connection outbound from the
  second machine. It was rejected because the witness needs a consistency proof for each new size, so the host
  would publish proof files into the spool beside the checkpoints. That is a second format of our own, where
  `add-checkpoint` is one other witnesses already accept. It would also leave a witness unable to say `409` to a
  host that has moved on without it.
- **The witness inside the log process, or on the host.** It needs no network, but it shares fate with the
  host. Root there forges the witness's cosignatures with the log's, which is the split view it was meant to
  catch.

## Consequences

- **One witness is one party to trust.** A witness that colludes with the host, or whose key leaks with the
  log's, cosigns a fork. The quorum exists for more witnesses than one. The demo has one, and T-09's residual
  says so.
- **Split view is caught only by a verifier that requires the cosignature.** An auditor who accepts
  uncosigned checkpoints can still be shown a fork. T-09 becomes partial, conditional on `--require-witnessed`
  and on an honest witness.
- **A witness that falls behind blocks proofs after a prune.** Hence the push refusal and the RUNBOOK rule
  (decision 6). A witness whose state is lost has to be reset by hand to accept the log again. It then
  witnesses only from that point: what it saw before is gone, and nothing can show the gap.
- **The witness is a network service on the second machine**, the first tally runs. It is plain HTTP on the
  LAN at first. Every body is signed in both directions, so a man in the middle can delay, drop or replay, and
  cannot forge. A replayed checkpoint gets `409`. TLS comes when the witness leaves the LAN.
- **The cosignature's time is the witness's claim**, which is a third party's. ADR-0006 left this as further
  heartbeat evidence once a witness exists. It is not wired here.

## Reopening criterion

- **ML-DSA-44:** when the module's floor reaches Go 1.27, which RNF-01 allows once Go 1.28 is released and
  Go 1.26 stops receiving security fixes.
- **A second witness:** when the demo gains a third machine.
