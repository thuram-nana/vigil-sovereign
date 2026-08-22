# W16-STD-3b — the spine segment manifest supports owner-key signing (tamper-refused)

Issue: [#529](https://github.com/thuram-nana/vigil-sovereign/issues/529) ·
Milestone: W16 — DECLARED-LIMITATION BURNDOWN.

## The claim (registered in the claims registry — [W0-3] #398, id `W16-STD-3b`)

<!-- CLAIM:W16-STD-3b -->
> **Registered claim (W0-3 #398):** The spine segment manifest supports owner-key signing: when written with a signing key its `manifest_sig` is populated, and `read_manifest` refuses a manifest whose signature is missing or does not verify under the expected key.

## Why it is TRUE of the code

`manifest_sig` was reserved-but-unsigned. It is now a real, optional signed tier that reuses the shared
`vigil_core` Ed25519 signing (no new crypto): `write_manifest(..., private_key_b64=…)` sets `manifest_sig`
to a signature over the canonical manifest body with the signature field nulled, and `read_manifest(...,
public_key_b64=…)` verifies it, raising `ManifestSignatureError` for a missing or non-verifying signature —
so an edited manifest on disk is refused fail-closed at read.

This is defence-in-depth ON TOP of the unconditional byte-level floor (record order/count and every tamper
decision are re-derived from the segment bytes, so a doctored manifest already fails closed downstream);
signing catches it EARLIER, at read. Called without a key both paths are byte-identical to the historical
unsigned manifest, so retain-all stores are unchanged. Wiring a persisted per-store key so a running store
signs BY DEFAULT is tracked as W16 blocking-work.

Enforced by `apps/sigil/sigil/spine/manifest.py::read_manifest` (with `sign_manifest` / `verify_manifest`);
proved by `apps/sigil/tests/test_spine_manifest_signature.py` (sign→verify roundtrip, an edited manifest on
disk is refused, and an unsigned manifest is refused when a key is required — with the untampered read as
the negative control).
