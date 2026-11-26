# AEGIS TT-STG DONE records — trust root

This directory holds the **trust root** for AEGIS test-tenant (TT-STG) DONE records
(slice **AS-25**, decision **D33**). It is the out-of-band root an auditor pins to
re-verify a demonstration record offline.

## What a DONE record is

A DONE record is a **signed binding** (`vigil-aegis-tt-demonstration-v1`) over a
verification-manifest run (`tools/verification_manifest.py run` →
`vigil-verification-manifest/1`). The binding ties the run to the slice and the world it
ran in — slice and `claim_ids`; the commit; the manifest / JUnit / suite digests; the
signed build manifest (`artifacts VALID`); the IaC topology digest; the subject paths and
digest; the tenants; the UI legs exercised; the required case classes; and the
`no_skip_terms` that must never be skipped.

The model, signing and the **offline verifier** live in
`engine/crucible/framework/v2/evidence/aegis_tt.py` (`verify_demonstration`). The verifier
re-checks every bound field offline and deterministically, and **fails closed**: a flipped
byte anywhere in the bound manifest changes its digest and voids the binding; a flipped byte
in the signed record fails the signature.

Why a separate record rather than the claims registry: a required-check registry entry can
never point at a dispatched/scheduled TT-STG run (plan §13.2). See ADR
`engine/crucible/framework/v2/docs/aegis/adr/0005-EV-evidence.md`.

## The key

Signing is domain-tagged Ed25519 (`vigil-aegis-tt-demonstration-v1\0`) via the shared
`verify_threshold` substrate. The signer is a **dedicated TT evidence key held KMS-wrapped
in the staging control plane** — never a CI runner key, never the production root (plan
§13.3). Only the key's **public** half is ever committed, in `trust-root.json`.

`trust-root.json` is currently **`unprovisioned`** (empty `authorizers`): the staging key is
provisioned by the AS-26 key ceremony. Until then the verifier has no usable root and no
record can verify — the honest, fail-closed state. A `production` environment value is
refused by the verifier regardless of provisioning.

## Limits

A DONE record is **SIGIL attesting its own staging run**. It is not production behaviour
and not third-party assurance; every record says so in its `limits` field.
