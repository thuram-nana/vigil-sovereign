# W9-2 — Rotate the spine DEK, the WARDEN kernel key and the TPM KEK; seal the WARDEN key

Issue: [#434](https://github.com/thuram-nana/vigil-sovereign/issues/435) (W9-2) ·
Milestone: W9 — KEY LIFECYCLE & PRODUCTION POSTURE. Sibling of [W9-1] #434; feeds [W9-4] #437.

## The claim (register in the claims registry, [W0-3] #398)

> Each of the three at-rest keys can be ROTATED with re-encryption of everything it protects, without
> data loss, VERIFY-THEN-SWAP and FAIL-CLOSED (a leg that cannot be proven leaves every key untouched):
> the **TPM KEK** (re-wrap every vault-sealed file under a fresh KEK), the **spine DEK** (re-encrypt the
> sealed content fields under a fresh DEK), and the **WARDEN kernel key** (fresh keypair + cross-signed
> succession). After a rotation the OLD key no longer decrypts and material sealed before rotation still
> reads under the new key. The **WARDEN key is sealed to the TPM** when a vault is provisioned (it was
> left plaintext-0600 even on a TPM host). `vigil doctor` reports the sealing state PER key.

This claim is TRUE of the code as of W9-2, with the honestly-scoped live/infra boundary below.

## Where it lives

- **Pure re-encryption engine** — `vigil_core/rotation.py` (`rewrap` / `rewrap_or_seal` /
  `verify_opens_to`). `rewrap` moves a sealed blob from old-key to new-key custody and PROVES both
  controls before returning: the new blob opens under the new key to the exact original (positive) AND
  no longer opens under the old key (negative). Any failure raises `RotationError` and returns nothing.
- **TPM KEK rotation** — `Vault.rotate_kek` (`vigil_core/vault.py`): re-wraps every listed vault-sealed
  FILE in memory, seals a fresh KEK to STAGED TPM blobs and verifies it unseals back, stages every
  re-wrapped file and re-verifies it from disk, then COMMITS (snapshot old KEK → `.prev` crash-window
  anchor → swap KEK → swap files → drop `.prev`). A read during the swap window falls back to the
  `.prev` KEK (`Vault._open`) so an interrupted commit never orphans a secret. `vigil_core/kek.py` gains
  `reseal_kek` / `load_kek_from` (seal/unseal a KEK under staged blob names).
- **WARDEN key sealing + rotation** — `apps/sigil/sigil/warden_key.py`. `seal_warden_key` seals the
  plaintext-0600 kernel key at rest via `Vault.seal_file` (binary-secret sealing added to the vault:
  `read_bytes_secret` / `write_bytes_secret` / `seal_file`). `rotate_warden_key` mints a fresh Ed25519
  keypair, records a CROSS-SIGNED SUCCESSION (the outgoing key signs the incoming pub into an
  append-only `warden.succession.jsonl`), swaps the key files verify-then-swap with rollback, and seals
  the fresh key. `verify_warden_succession` walks old→new so action-log entries under a prior key stay
  authenticable — the same succession design as owner-key rotation (W9-1).
- **Spine DEK rotation** — `apps/sigil/sigil/spine/dek_rotation.py` (`reencrypt_payload` /
  `reencrypt_records` / `rotate_spine_dek`): re-encrypt every sealed content field under a fresh DEK,
  rebuild the hash-chain, and PROVE it (chain verifies; every field opens under the new DEK to the exact
  original; the old DEK no longer opens a re-keyed field), then verify-then-swap the spine + DEK file
  with rollback.
- **doctor** — `integration/vigil_integration/doctor.py` `_posture_key_sealing` reports the at-rest
  sealing state PER key (owner.priv / spine.dek / warden.key), read from the AEAD magic on disk WITHOUT
  importing sigil (FATAL-2). Rendered as the `key-sealing` posture control.
- **CLI** — `sigil key status | seal-warden | rotate-warden | rotate-dek | rotate-kek`.

## Tests (all in required CI jobs)

- `packages/core/vigil_core/tests/test_rotation.py`, `..._vault_rotate_kek.py` — required `vigil_core`
  job. New key reads / old key no longer decrypts; a re-wrap that cannot be proven rolls the WHOLE
  rotation back (originals untouched); crash-window `.prev` fallback; binary WARDEN key sealing.
- `apps/sigil/tests/test_dek_rotation.py`, `..._warden_key_rotation.py` — required `SIGIL governor
  gates` job (whole-dir). Re-encrypt + verify + rollback; forged/tampered succession refused (negative
  control); segmented/anchored/unprovisioned refusals.
- `integration/tests/test_doctor_key_sealing.py` — required two-env boundary (sovereign leg). Per-key
  SEALED/PLAINTEXT/ABSENT reporting. None of these use `pytest.importorskip("framework…")`.

Each suite includes a test that FAILS on a tree without the change (the rotation/seal functions do not
exist) and a negative control asserted in the same run.

## Honest live/infra boundary (composes with the deferred legs)

- **TPM seal/unseal is live-only** — the KEK is sealed/unsealed through `vigil_core.kek`'s injectable
  argv-runner seam; tests drive a fake keyring stub. The real `tpm2-tools` path activates on a
  provisioned host. No LIVE hardware result is faked.
- **KEK-blob two-file commit window** — the fresh KEK is two sealed blobs (pub + priv); a power loss
  BETWEEN the two `os.replace`s is the residual window. The `.prev` + `.rot` artifacts make it
  recoverable; a resume/`--resume` reconciliation is the live-hardening leg.
- **Secrets sealed DIRECTLY under the KEK and embedded in the immutable owner-signed spine** (e.g.
  account TOTP shared secrets via `Vault.seal_secret`) are NOT files and are NOT re-wrapped by
  `rotate_kek`; re-keying them composes with the W9-1 re-genesis path.
- **DEK rotation of a SEGMENTED or ANCHORED spine** (a manifest, a signed head, or a durable floor) is
  REFUSED fail-closed by `rotate_spine_dek`: re-encryption changes every `cert_digest` and thus the
  signed head_hash, so it must re-sign the head / re-anchor the floor / re-checkpoint transparency —
  that is exactly the W9-1 re-genesis path (#434). The pure engine has no such restriction and is what
  the re-genesis path calls.
- **The Rust kernel consuming a sealed WARDEN key at boot** — the kernel (`kernel/src/crypto.rs`) reads
  `warden.key` as 32 raw bytes. The Python side seals/unseals it (`seal_warden_key` /
  `materialize_warden_key`); the boot step that materialises the plaintext just-in-time for the kernel
  (or a Rust-side unseal) is the live wiring leg.
- **Claims-registry registration** — the registry itself lands with [W0-3] #398; this doc is the
  truthful claim to register there.
