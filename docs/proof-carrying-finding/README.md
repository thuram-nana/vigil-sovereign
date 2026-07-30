# Proof-Carrying Finding (PCF) — public schemas + standalone verifier

A VIGIL finding is designed to be **independently verifiable by a third party who does not trust or
run VIGIL**. This directory is the public, framework-independent half of that promise:

- **`schemas/`** — JSON Schema (draft 2020-12) for every public artifact in a proof bundle, derived
  from the real pydantic models / code (no invented fields):
  - `evidence-certificate.schema.json` — `EvidenceCertificate` (the actual serialized shape,
    including the additive members `report_claims` / `oracle_version` / `how_to_verify` that are
    **dropped when empty** so older certificates stay byte-identical), with `ArtifactRef` + `ReportClaim`.
  - `signed-evidence.schema.json` — `SignedEvidence` (certificate + m-of-n `Signature`s).
  - `chain.schema.json` — `ChainEntry` + `SignedChainHead` (v1 and v2 fields).
  - `trust-root.schema.json` — `TrustRoot` + `AuthorizerKey` (public keys + threshold).
  - `evidence-bundle.schema.json` — the top-level `evidence-bundle.json` object.
  - `pcf-certificate.schema.json` — the **PCF v0.1** wire format (`to_pcf` output).
- **`SPEC.md`** — the byte-level spec: canonical JSON, domain separation, the m-of-n Ed25519
  threshold + weak-key rejection, the hash chain / signed head / anti-rollback high-water, and the
  out-of-band trust-root fingerprint pin. The verifier is derived from this, not from VIGIL's code.
- **`verify_pcf.py`** — a **standalone reference verifier**. Standard library + one Ed25519 library
  (`cryptography`). **No `framework`, `vigil_core`, `vigil_integration`, or `strix` import.**

## How the standalone verifier stays VIGIL-free

`verify_pcf.py` imports only `argparse, base64, hashlib, json, pathlib, sys, importlib.util` and
`cryptography` (for Ed25519). It re-implements — from `SPEC.md`, not by importing VIGIL — the
canonical bytes (`canonical_json` = sorted keys, `(",",":")` separators, UTF-8), the
`crucible-evidence-v1\0` domain tag, `digest_payload` / `evidence_signing_bytes`, `verify_threshold`
(distinct-authoriser m-of-n with the non-canonical / small-order public-key blocklist), the chain
`entry_hash` and the version-conditional head signing payload, and `trust_root_fingerprint`.

You can *prove* the environment is clean: pass `--prove-standalone` and the verifier first asserts
that none of `framework / vigil_core / vigil_integration / strix / gateway` is imported **or even
importable** in the running interpreter, exiting non-zero otherwise. The conformance test runs the
verifier this way, in a subprocess launched with the system Python from a neutral working directory
and a `PYTHONPATH` that excludes `engine/crucible`, `integration`, and `packages/core`.

## What it proves — and what it does not

Run over a bundle:

```
python3 verify_pcf.py bundle --bundle <dir> --trust-root-fingerprint sha256:<hex>
```

Exit `0` iff **SOUND**. Standalone it checks, over stdlib + Ed25519 only:

| layer | checked standalone | how |
|-------|:---:|-----|
| fingerprint | yes | trust root matches the operator's out-of-band pin |
| authentic   | yes | m-of-n Ed25519 over `crucible-evidence-v1\0` + canonical certificate bytes |
| bound       | yes | `oracle_context_digest` == `digest_payload(oracle_context)` |
| artifacts   | yes | each raw file re-hashes to its recorded sha256 (path-confined) |
| chained     | yes | hash chain + signed head bind the cert set; anchored; anti-rollback high-water |
| **reproduced** | **no** | re-running the oracle over the retained context, the `oracle_version` staleness check, and claim-grounding are **framework-specific** |

**Reproduction requires the VIGIL verifier.** Re-executing the deterministic oracle to reconfirm the
verdict needs the oracle bodies, so it is done by:

```
python -m framework.v2 evidence verify \
    --report reverifiable.json --bundle . --trust-root trust-root.json --evidence-root evidence \
    --trust-root-fingerprint sha256:<hex>
```

Authenticity, binding, integrity, and chain are fully checkable **without** VIGIL — that is the
adoption lever: a third party can confirm that a signed, chained, byte-for-byte-intact finding really
was issued under the operator's governance key, before ever installing VIGIL to re-run the oracle. A
single flipped byte anywhere flips a standalone verify to NOT SOUND.

## The out-of-band pin is what makes it zero-trust

`trust-root.json` inside a bundle is only a convenience copy. Its authenticity is anchored by the
fingerprint the operator publishes through a channel **independent of the bundle**. Without the pin,
a successful verify proves internal consistency + binding + chain but **not** authenticity — whoever
handed you the bundle could have re-signed it under their own key. Always pass
`--trust-root-fingerprint`.

## Conformance test

`tests/test_standalone_verifier.py` (run under the offense venv) exports a **real** bundle from a
genuine oracle fire (`vigil_integration.proof.bundle.export_bundle`), then:

1. runs `verify_pcf.py bundle --prove-standalone` in a clean, VIGIL-unimportable subprocess and
   asserts it validates the genuine bundle (exit 0);
2. flips a signature byte, and separately a raw-evidence byte, and asserts the standalone verifier
   **rejects** each (exit 2);
3. asserts a **wrong** fingerprint pin is refused and the **right** pin passes;
4. proves **canonical-bytes parity** — the verifier's `digest_payload(certificate)` equals the
   framework's `cert_digest`, and its `trust_root_fingerprint` equals the framework's — so the
   re-implemented bytes are byte-identical to the real serializer;
5. validates a real certificate and the whole bundle against the JSON Schemas, and a real PCF cert
   against `pcf-certificate.schema.json`.
