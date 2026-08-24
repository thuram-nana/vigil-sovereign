# W9-6 — A pluggable hardware backend for the owner signing key

Issue: [#439](https://github.com/thuram-nana/vigil-sovereign/issues/439) ·
Milestone: W9 — KEY CUSTODY.

Before this, the owner Ed25519 key — the key that authorizes everything (per-action approval tokens, the
m-of-n destruction authorizations) — was **file-based only**: a base64 private key exported into the
signing process from a `0600` file owned by the same UID as the process. A process compromise, a core
dump, a `/proc/<pid>/environ` read, or a swap leak therefore exposes the root of authority. W9-6
introduces a pluggable backend so the same owner identity can instead live in a hardware token that signs
on the device, so the private scalar never enters the process.

## The claim (registered in the claims registry — [W0-3] #398, id `W9-6`)

<!-- CLAIM:W9-6 -->
> The owner Ed25519 signing key can be held by a pluggable backend selected with `VIGIL_OWNER_KEY_BACKEND`: a `file` backend (the default — a base64 private key loaded into the process, byte-identical to the prior owner-signing path) or a `pkcs11` hardware backend (a real HSM / YubiKey) that signs ON the token so the private key never enters the process. `select_owner_backend` is FAIL-CLOSED: when the hardware backend is selected but its token / PKCS#11 module is absent it raises `HardwareKeyUnavailable` and NEVER falls back to a file key, and an unknown backend name is refused rather than defaulted to file. `vigil doctor` reports the active backend as the `owner-key-backend` posture control. Driving a real PKCS#11 token end-to-end is the irreducible residual, exercised only by an env-gated live-token test and never in CI.

## Why this is TRUE of the code

- **Pluggable, file default unchanged.** `vigil_core.key_backend.select_owner_backend` returns a
  `FileBackend` when `VIGIL_OWNER_KEY_BACKEND` is unset or `file`. `FileBackend.sign` is
  `vigil_core.crypto.sign` over the same bytes, so a token minted through the backend is byte-identical to
  one minted before this abstraction existed (proved by
  `test_file_backend_is_byte_identical_to_the_legacy_owner_signing_path`). Nothing already deployed
  changes: the CLI signing path (`vigil approve sign`) still reads `VIGIL_APPROVAL_OWNER_KEY` and signs.
- **Hardware backend holds no private material.** `Pkcs11Backend` wraps an opened PKCS#11 token session
  (`TokenSigner`) and holds no private-key attribute; `sign()` delegates to the token and only the message
  crosses to it. `test_hardware_path_never_reads_private_material_into_the_process` forbids
  `vigil_core.crypto.sign` and `Ed25519PrivateKey.from_private_bytes` on the hardware path and still signs
  through the (faked) token, verifying the signature under the token's public key.
- **Fail-closed — the negative control.** With the hardware backend selected but the token/module absent,
  `select_owner_backend` raises `HardwareKeyUnavailable` even when a perfectly good file key is supplied —
  it never returns a `FileBackend`
  (`test_hardware_selected_but_token_absent_fails_closed_never_uses_file_key`). At the CLI, `vigil approve
  sign` then refuses and writes no signed token
  (`integration/tests/test_owner_key_backend.py::test_hardware_selected_but_absent_refuses_to_sign_and_never_falls_back`).
- **`vigil doctor` reports the active backend.** `doctor._posture_owner_key_backend` →
  `describe_owner_backend` adds the `owner-key-backend` posture line (FILE by default; a fail-closed
  PKCS11-* state when the hardware backend is selected but unusable). It reads env only — it never opens
  the token or uses the PIN.
- **Rotation (#434) is backend-agnostic.** Whatever backend holds the current owner key signs; rotating
  means provisioning a new backend (a fresh file key, or a fresh token key object). The pure re-encryption
  rotation primitives (`vigil_core.rotation`) are untouched.

## The irreducible residual (honestly labelled)

The real PKCS#11 path — `open_pkcs11_signer`, which loads a provider `.so`, opens a token session, and
uses the on-token Ed25519 key as a signing handle — needs a **physical token** (an HSM / YubiKey, or a
SoftHSM2 token for a dev exercise) and the `pkcs11` binding, neither present on a hosted CI runner. It is
marked `# pragma: no cover` and is exercised ONLY by the env-gated
`packages/core/vigil_core/tests/test_key_backend_live_token.py` (SKIPPED in CI, with a documented SoftHSM2
recipe). The falsifiable core — backend selection, the fail-closed negative control, the no-private-material
guarantee, and the doctor report — is fully tested with no hardware.

## Configuration

- `VIGIL_OWNER_KEY_BACKEND` — `file` (default) or `pkcs11` / `hardware` / `hsm` / `yubikey`.
- `VIGIL_PKCS11_MODULE` — path to the PKCS#11 provider `.so`.
- `VIGIL_PKCS11_TOKEN_LABEL` — which token/slot (optional → first token).
- `VIGIL_PKCS11_KEY_LABEL` — which key object on the token (default `owner`).
- `VIGIL_PKCS11_PIN` — the user PIN that AUTHORIZES USE of the token. It is not the private key and never
  yields the private scalar.
