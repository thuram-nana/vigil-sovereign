# Verifier supply-chain provenance (Lane C / C3)

The whole point of a proof-carrying finding is that a third party who trusts and runs **nothing** of
VIGIL can re-check it. Three **standalone, zero-VIGIL** verifiers make that possible:

| Verifier | Role |
|---|---|
| `docs/proof-carrying-finding/verify_pcf.py` | PCF v0.1 — authenticity (m-of-n Ed25519) + binding + faithful projection + out-of-band pin |
| `docs/proof-carrying-finding/verify_vf.py` | Verifiable-Fact lifecycle + zero-VIGIL **re-execution** of the pure oracle bodies |
| `engine/crucible/framework/v2/evidence/audit_offline_verifier.py` | External-audit-package re-verifier (shipped verbatim as `verify_offline.py`) |

Each imports only the Python standard library and one Ed25519 library (`cryptography`) — **no**
`framework` / `vigil_core` / `vigil_integration` / `vigil_gateway` / `strix`.

## The gap this closes

A reviewer who downloads those three files has, by itself, no way to confirm they are the **exact bytes**
the maintainers audited. A tampered verifier could silently pass a forged bundle. This directory closes
that gap with a **signed provenance** that pins each verifier's content hash, published out-of-band.

- `verifier-provenance.json` — an in-toto / SLSA-provenance statement whose `subject` list pins the
  `sha256` of each verifier. Deterministic: a pure function of the verifier bytes + committed spec
  references (no wallclock, no RNG), so minting is idempotent and byte-reproducible.
- `verifier-provenance.sig.json` — an m-of-n Ed25519 signature over the canonical bytes of the statement,
  with the trust root embedded.
- `verifier-provenance.fingerprint.txt` — the signing trust-root fingerprint.
- `verifier-transparency.jsonl` — the durable, committed transparency record: one append-only line per
  verifier binding its path + `sha256` to the trust-root fingerprint. A **second, independent** channel
  for the pins besides `SECURITY.md`.

The trust-root fingerprint is also published **out of band** in [`../../SECURITY.md`](../../SECURITY.md),
in a durable channel separate from the signature file — so an adversary who rewrites the repo and re-signs
with a fresh key cannot match the pin a reviewer holds.

## Re-verify it (zero dependencies)

Re-hash a verifier and compare to the pin in `SECURITY.md` or `verifier-transparency.jsonl`:

```
sha256sum docs/proof-carrying-finding/verify_pcf.py
```

Or run the full offline check (re-derives all three legs — the framework signature check, the zero-VIGIL
`verify_vf.verify_threshold` over the same canonical bytes, and the hash-pin drift check):

```
python3 -m framework.v2.eval.verifier_provenance verify
```

Re-mint after an intentional verifier change (updates every committed artifact in lock-step):

```
python3 -m framework.v2.eval.verifier_provenance mint
```

The drift test `docs/tests/test_verifier_provenance.py` keeps the provenance, the transparency record, the
`SECURITY.md` pins, and the shipped verifier bytes in lock-step: change any verifier without re-minting, or
update one pin and not another, and the build turns red.

## Honest boundary

This is a **certifiable-ready** artifact, not an external certification:

- The **default signing key is a deterministic fixture** derived at runtime from a committed public seed
  (no private key in the repo), so CI is byte-stable with nothing provisioned. It signs a *self-attestation*
  of the verifier bytes. A **published** provenance re-signs with the operator's governance key
  (`--signing-key`; FATAL-2 — keys are passed in, never provisioned here), yielding the same statement
  content under the operator's trust root.
- What this proves is **integrity + origin under the pinned trust root** of the verifier bytes. It does
  **not**, and structurally cannot, assert that an external accredited body certified them (see
  `docs/limitations` `LIMIT-external-audit-team`), nor anchor to a hardware root of trust (see
  `LIMIT-attest-tee-hardware`). Those boundaries are named in the statement's `irreducible_boundary` block,
  never hidden.
