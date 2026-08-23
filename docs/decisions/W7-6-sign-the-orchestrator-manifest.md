# W7-6 — Sign the orchestrator MANIFEST.json

Issue: [#464](https://github.com/thuram-nana/vigil-sovereign/issues/464) ·
Milestone: W7 — BACKUP / DISASTER RECOVERY.
Feeds [W7-4](https://github.com/thuram-nana/vigil-sovereign/issues/462) (destination verification checks a
signed manifest). Key handling + rotation per [W9-1](https://github.com/thuram-nana/vigil-sovereign/issues/434).

## The defect

The two-plane `vigil backup` orchestrator writes a **plaintext, unsigned `MANIFEST.json`** alongside the two
encrypted plane parts. That file is the *index* of what a backup contains — which encrypted file is which
plane, and each part's `sha256` — and `vigil restore` reads those values to **locate and integrity-check every
part before it invokes any leg**. Unsigned, the index could be edited by anyone who can reach the backup at
rest:

- redirect a part's `file` to a different blob;
- **downgrade a `sha256`** so an OLD legitimate part is accepted in place of the current one — a
  rollback/substitution to a pre-revocation state (the passphrase and the part's *own* inner governance
  signature both still check out, because it is a genuine older backup);
- tamper the retention hint or host/metadata.

Each encrypted part already carries its own inner governance signature sealed inside the AEAD body, but that
protects **the part**, not the orchestrator's **index of parts**. So the index itself was unprotected: the old
`_cmd_restore` performed no signature check at all (observed directly on `origin/main` — an unsigned,
attacker-substituted manifest restored with exit 0 and the offense leg invoked).

## The claim (register in the claims registry, [W0-3] #398)

<!-- CLAIM:W7-6 -->
> **Registered claim (W0-3 #398):** The orchestrator `MANIFEST.json` is signed with the offense governance key, and `vigil restore` verifies that signature over the exact manifest bytes before trusting the index — refusing an unsigned, tampered, or wrong-key manifest (fail-closed); the same `--expect-governance-pubkey` out-of-band pin authenticates it.

This claim is TRUE of the code as of W7-6:

- **What is signed, and where.** `vigil backup` (`_cmd_backup`) writes the exact `MANIFEST.json` bytes with
  `write_bytes` (no newline translation) and then `vigil_integration.backup.sign_orchestrator_manifest` signs
  **those exact raw bytes** with the stable offense-governance keypair (`live.governance_identity` — the same
  key that signs the inner offense manifest), emitting a self-describing `MANIFEST.sig.json` sidecar
  (`algo=ed25519`, `signs="MANIFEST.json (raw bytes)"`, the signer `pubkey`, the `sig`, and the
  `manifest_sha256`). The sidecar carries no secrets.
- **Where it is verified (fail-closed).** `vigil restore` (`_cmd_restore`) reads the manifest bytes and, via
  `vigil_integration.backup.verify_orchestrator_manifest`, **refuses before touching any plane part** when the
  sidecar is missing (an unsigned manifest is never trusted), when the signature does not verify over the
  manifest bytes (tamper), when the envelope lacks its pubkey/sig, or when an `--expect-governance-pubkey` pin
  is supplied and the signer does not match it (wrong key). Each refusal is a non-zero exit; the offense/
  sovereign legs are never invoked on a bad index.
- **Determinism.** The signature is Ed25519 over fixed bytes with a persisted key — no wallclock or randomness
  enters the signed envelope, so `sign_orchestrator_manifest` is byte-reproducible and the signature
  re-verifies offline.
- **Off-host replication carries the signature.** `vigil backup --push` transports `MANIFEST.sig.json`
  alongside `MANIFEST.json` and the encrypted parts, so a pushed copy is itself a signature-verifying
  `vigil restore` source (an off-host copy that dropped the signature would be refused as unsigned).

## FATAL-2 boundary

The orchestrator runs in the **offense** venv and signs with the **offense governance key only**. The
sovereign owner key never enters this process (the two-env boundary), so — exactly as for the inner offense
manifest — the index is **governance-signed, not owner-signed**. This is honest and intentional: a keyless
offense plane cannot owner-sign.

## Authenticity residual (tracked by [W9-1] #434)

Without the out-of-band `--expect-governance-pubkey` pin, the self-describing signature proves **integrity**
(no edit by anyone lacking the offense governance private key) but not full **authenticity** against a
re-mint: an attacker who can reach the index — but who cannot decrypt the parts — could re-sign a tampered
manifest under a key they generated, and an unpinned verify would accept that self-signed envelope (it could
only enable a rollback to a genuine older part, since forging a *new* part still needs the passphrase). The
pin closes this: it names the true governance key out of band, and a re-minted envelope is then refused. The
**operator-owned signing key and its rotation story** that make the pin the default posture are
[W9-1] #434; W7-6 ships the mechanism and the pin, and marks the operator-key provisioning as that residual.

## Tests + negative controls

`integration/tests/test_backup_manifest_signature.py` (runs in the required `integration two-env boundary
(P5)` job):

- **Unit:** sign→verify round-trip; determinism (identical bytes on repeat); refuse tampered bytes; refuse a
  missing/empty/incomplete envelope (unsigned); refuse a wrong-key pin; and the residual made explicit — an
  attacker re-mint verifies *without* the pin but is refused *with* it.
- **CLI (fails without the fix):** a clean signed manifest restores; a **tampered** manifest (part swapped +
  its `sha256` rewritten so the old per-part check would pass) is refused before the leg runs; an **unsigned**
  manifest (sidecar removed) is refused; a **wrong pin** is refused while the correct pin restores. On a tree
  without the fix these controls fail — the pre-fix restore accepts the unsigned/tampered index and calls the
  leg (observed, not assumed).
