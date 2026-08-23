# W9-5 — Secure per-host co-signer provisioning; multi-signer is the production default

Issue: [#438](https://github.com/thuram-nana/vigil-sovereign/issues/438) ·
Milestone: W9 — KEY LIFECYCLE & PRODUCTION POSTURE. Depends on [W9-1] #434; feeds [W9-4] #437.
Registered in the claims registry ([W0-3] #398, id `W9-5`).

## The defect

The m-of-n destruction quorum (VIGIL I4, `integration/vigil_integration/destruction_gate.py`) had two
holes that made its "quorum" a costume:

1. **The default was 1-of-1.** `vigil provision-destruction` defaulted to `--threshold 1 --signers 0` — a
   solo owner. A single keyholder authorized every destructive PR.
2. **Every private key was minted and printed on ONE box.** `generate_authority` called
   `generate_keypair()` for the owner AND every co-signer locally, then printed all of them. Even at
   `--threshold 3`, all three private keys originated on, and were displayed by, one host. A quorum whose
   members all live on one machine is not a quorum — one compromise of the minting box is a compromise of
   the whole "quorum".

## What W9-5 changes (add-only on the existing signing path)

### 1. Production posture makes MULTI-SIGNER the default and refuses an under-provisioned quorum

<!-- CLAIM:W9-5 -->
**Registered claim (W0-3 #398, id `W9-5`):** Under the production posture (`VIGIL_POSTURE=production`/`prod`,
the one shared parse in `vigil_core.posture`) the destruction authorization path REQUIRES a genuine
multi-signer quorum and refuses a 1-of-1 (or pubkey-collapsed) authority, fail-closed, where distinct signers
are counted by their DECODED 32-byte Ed25519 key (not the base64 string) and non-canonical base64 encodings are
rejected at the crypto core, at BOTH the immutable construction of a `DestructionAuthority` AND the
authorization decision (`authorize_destruction`); with the posture unset the behaviour is byte-identical to
before (a solo authority is still allowed — the change is strictly additive). "Genuine multi-signer" means
threshold >= 2 AND at least `threshold` signers whose DECODED public keys are pairwise distinct, so neither a
solo authority nor a pubkey-collapsed roster — N key_ids that decode to ONE key, which `verify_threshold`
counts by key_id — can satisfy the quorum with one keyholder. The decoded-key dedup is what
`production_multisigner_reason` enforces (at construction and at assemble); the crypto-core canonicalisation
(`vigil_core.crypto._b64decode_exact`) is the defense-in-depth that stops an alternate encoding entering a
roster at all. `verify_threshold` itself still counts by key_id (the witness subsystem relies on that), so
the roster-distinctness invariant is enforced at construction/assemble, never left to `verify_threshold`.

- The predicate is `destruction_gate.production_multisigner_reason(trust_root)` — pure over the trust root
  (it reads no env), returning `""` for a genuine multi-signer quorum or a DENY reason otherwise.
- `DestructionAuthority.__post_init__` calls it under `is_production_posture()`: an under-provisioned
  authority can never be **loaded** as deployment config (this is the chokepoint
  `live.trusted_finding.load_destruction_authority` and all provisioning flow through).
- `authorize_destruction(..., production=None)` re-checks it at the **decision** (defense in depth): even an
  authority object built before the posture was armed cannot slip a solo quorum past the live gate.
  `production` defaults to `is_production_posture()`; tests inject it explicitly for determinism.
- `generate_authority` (the all-keys-on-one-box mint) is **refused entirely** under the production posture,
  because it mints private material on the minting box regardless of threshold.

This is a production-posture-gated control, so — like its siblings [W9-4] #437 and [W10-8] — it is registered
`default: off` and `failure_class: opt-in-stated-as-default`: it is documented as holding *only when the
operator arms the production posture*, never as an always-on default.

### 2. Secure per-host provisioning (CSR-style enrolment; public material only)

Provisioning is split into two phases so no co-signer private key ever transits the minting box
(`integration/vigil_integration/live/destruction_provision.py`):

- **PHASE 1 — on each signer's OWN host** (`build_enrollment` / `vigil enroll-cosigner`): generate the
  Ed25519 keypair LOCALLY, write the PRIVATE key `0600` (`O_EXCL`) on that host, and emit a PUBLIC
  *enrolment request* = `{key_id, name, public_key_b64}` plus a **proof-of-possession** — the fresh private
  key's signature over the domain-separated canonical enrolment statement. The private key is never
  transmitted; only the enrolment request travels.
- **PHASE 2 — on the MINTING box** (`assemble_authority` / `vigil assemble-destruction`): consume only the
  PUBLIC enrolment requests, VERIFY every proof-of-possession (`verify_enrollment`), refuse duplicate
  key_ids AND duplicate public keys — compared by their DECODED 32-byte value, so re-encoding one key under a
  second key_id cannot slip past a base64-string comparison (and the non-canonical encoding is itself rejected
  by `verify_enrollment`'s `load_public_key`) — (quorum collapse), bind the owner as mandatory, and — under the
  production posture — refuse anything that is not a genuine multi-signer quorum. The returned authority
  carries **no private keys** (`GeneratedAuthority.private_keys == ()`).

A companion trio keeps keys apart at AUTHORIZE time too: `vigil request-destruction` (coordinator mints one
shared unsigned authorization), `vigil sign-destruction` (each host signs it DETACHED with its own key —
owner from `VIGIL_DESTRUCTION_OWNER_KEY`, a co-signer from a key file), `vigil combine-destruction`
(coordinator merges the detached signatures into the single-use `signed-authorization.json`). The signatures
are re-verified by the gate, not trusted at combine time.

### Negative control (AC3) — a key that never proved possession is refused

`verify_enrollment` refuses an enrolment whose public key was swapped for one the proof-of-possession does
NOT cover (a copy-pasted / forged pubkey), a tampered PoP signature, or a weak/non-canonical key
(`vigil_core.load_public_key` bars low-order / non-canonical points). So a quorum assembled from a pubkey
that never proved possession on its own host is rejected before it can enter the trust root.

## Determinism

Nothing signed or verifiable here reads the wallclock or an RNG on its decision path. The proof-of-possession
statement is the deterministic canonical JSON of `{key_id, name, public_key_b64}` under a fresh domain tag
(`vigil-destruction-cosigner-enrollment-v1`); `authorize_destruction` takes `now` and `production` as
explicit arguments. Key generation uses the OS RNG exactly as the pre-existing `generate_authority` did —
that is provisioning, not a signed artifact's decision path.

## Attestation of deletion (AC4 — the honest statement, registered in [W0-3] #398)

There is **no cryptographic attestation of private-key deletion**, and W9-5 does not pretend otherwise. A
proof-of-possession proves the enroller *controlled* the private key when the enrolment request was produced;
it cannot prove *which physical host* produced it, nor that any copy of the key was destroyed. What the
tooling provides instead is an **operational** separation-of-duties made the default and the easy path:

- `build_enrollment` writes the private key `0600` on the signer's own host and returns it to the caller to
  store there; it is never emitted in the enrolment request and never sent to the minting box.
- `assemble_authority` consumes public material only and returns an authority with `private_keys == ()`, so
  the minting box holds no co-signer private key to delete.
- The **operator step** — that each signer generated its key on hardware it controls and that any transient
  copy on the minting box (only relevant for the legacy `generate_authority` dev path) is destroyed — is an
  out-of-band operator attestation. Operators SHOULD record it in the deployment runbook. VIGIL cannot and
  does not certify it. This limitation is the registered honest residual for the maintainer's review.

## Operator key-material residual (honest boundary)

W9-5 implements the full mechanism; it does not fabricate key material. The actual owner and co-signer keys
are minted by the operators on their own hosts (`vigil enroll-cosigner`), and the owner private key is held
by the owner (`VIGIL_DESTRUCTION_OWNER_KEY`, or an HSM/YubiKey in the plan's §6 shape — a hardware signer is
a drop-in for the file-backed key at `sign-destruction` time and is the recommended production posture). No
test or tool ever generates a "real" operator key on the operator's behalf.

## Tests (required CI job: `integration two-env boundary (P5)`)

`integration/tests/test_cosigner_enrollment.py` (import-clean — vigil_core + the offense-local
provisioning/gate only, no framework/strix/sigil — so it runs in the required P5 sovereign leg). It covers:

- **the "fails without the fix" delta, observed not assumed**: under the production posture,
  `generate_authority(threshold=1)` and a 1-of-1 `DestructionAuthority` are refused — on a tree without W9-5
  both succeed, so `test_production_refuses_all_on_one_box_generate_authority` and
  `test_production_refuses_building_a_1of1_authority` fail there (verified against `origin/main`);
- **negative controls asserted in the same run**: a forged pubkey with no valid PoP, a tampered PoP, a weak
  key, a duplicate-pubkey collapse, an ENCODING-VARIANT collapse (one key enrolled under two key_ids with two
  different base64 encodings, each with a valid PoP — refused by `production_multisigner_reason`, by
  `__post_init__` under production, by `authorize_destruction`, and by `assemble_authority`), a mis-mapped
  enrolment file, and an owner-absent quorum are each refused;
- **positive controls (the gate is not a blanket no-op)**: a genuine 2-of-2 authority loads under production,
  the unset-posture 1-of-1 path is unchanged, and an end-to-end per-host detached-signature 2-of-3 quorum
  authorizes a PR through the same `build_destruction_quorum` the live path uses;
- the CLI verbs (`enroll-cosigner` writes a 0600 key + public enrolment and refuses to clobber a key;
  `assemble-destruction` builds the trust root from public enrolments; `provision-destruction` is refused in
  production).

## Where it lives

- `integration/vigil_integration/destruction_gate.py` — `production_multisigner_reason`,
  `PRODUCTION_MIN_THRESHOLD`, the `__post_init__` + `authorize_destruction`/`consume_authorization`
  production checks.
- `integration/vigil_integration/live/destruction_provision.py` — `build_enrollment`, `verify_enrollment`,
  `assemble_authority`, `write_cosigner_private_key`, the per-host `build_authorization_request` /
  `sign_request_detached` / `combine_authorization`, and the production refusal in `generate_authority`.
- `integration/vigil_integration/cli.py` — `enroll-cosigner`, `assemble-destruction`, `request-destruction`,
  `sign-destruction`, `combine-destruction`.
- `integration/tests/test_cosigner_enrollment.py` — the proving suite.
