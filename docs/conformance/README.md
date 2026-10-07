# VIGIL conformance run (Lane C / C2)

A **re-runnable, offline-verifiable conformance run** over a frozen corpus, with a governance-signed
scorecard that records exactly what was verified. This is the capstone over the C1 standalone
re-execution tier (`docs/proof-carrying-finding/verify_vf.py`).

## What it attests

The signed scorecard (`conformance-scorecard.json` + `.sig.json` + `.fingerprint.txt`) records three
legs, all in one deterministic pass:

1. **Frozen-corpus re-verification (zero-VIGIL).** For every fact-capable general oracle family, one
   **sound signed bundle** — a real PCF v0.1 certificate (`corpus/<family>.pcf.json`) minted by the
   real producer over a reproducing `oracle_context` — is re-checked with the two **standalone**
   verifiers (stdlib + the one Ed25519 lib, **no** framework/vigil import):
   - `verify_pcf.py` → authenticity (m-of-n over the embedded certificate) + binding (the retained
     `oracle_context` re-hashes to the signed digest) + faithful projection + the out-of-band
     trust-root pin;
   - `verify_vf.py` (`reexecute_general_oracle`) → the verdict is **re-derived** from the retained
     evidence (the pure oracle re-fires standalone).
   Then the **full tamper battery** (per bundle: flip a signed field, strip the signatures, tamper the
   retained context, flip a signature byte, forge the out-of-band pin, make the retained values benign)
   — **each must be refused**.

2. **Differential parity (the C1 check).** The standalone re-execution kernel equals the real
   framework oracle on both `fired` and `conclusive` over C1's representative case battery, and the
   standalone dispatch agrees with `OracleVerifier.confirm` over the frozen contexts.

3. **Zero-VIGIL proof.** Both standalone verifiers import no framework/vigil/crucible code (AST over
   the import graph).

## Re-run it

```
make conformance
# or:
python3 -m framework.v2.eval.conformance_run verify   # run + write + sign + offline-verify the scorecard
python3 -m framework.v2.eval.conformance_run mint     # (re)mint the frozen corpus (deterministic)
python3 -m framework.v2.eval.conformance_run check    # verify-only, no write (CI / determinism)
```

The run is **deterministic / byte-stable**: minting the corpus and building+signing the scorecard
reproduce the committed bytes exactly (Ed25519 is deterministic; no wall-clock enters the signed
artifacts). `engine/crucible/framework/v2/eval/tests/test_conformance_run.py` gates this.

The signature verifies **offline** three independent ways: the framework `verify_scorecard` (with the
pinned fingerprint and `expected_threshold`), the fingerprint-pin match, and — zero-VIGIL —
`verify_vf.verify_threshold` over the same canonical bytes.

## Honesty boundary (this builds a certifiable-READY artifact; it does NOT fake a certification)

- **Signing key.** The default key is a **deterministic conformance-fixture key** derived at runtime
  from a committed public seed (no private key sits in the repo). It makes the run byte-stable and
  re-runnable in CI with nothing provisioned, which is what a self-attestation needs. It is **not** a
  governance key, and the scorecard says so (`attestation_key`). A **published** attestation re-runs
  with the operator's real governance key passed in (`--signing-key`; FATAL-2 — keys are provided,
  never minted here), producing the **same scorecard content** under the operator's trust root.
- **Liveness.** Re-execution proves the verdict is the correct **function** of the retained evidence; it
  does **not** prove the evidence is live — that still needs an in-VIGIL live re-run (the
  producer-supplied honesty bound). Recorded on every family.
- **Irreducible families.** The oracle families whose body cannot be re-fired with stdlib +
  cryptography (`version_range` → packaging, `saml_forgery` → signxml/lxml, `oob_callback` → the
  framework collector-receipt crypto) are **named** in the scorecard's `irreducible_boundary`, never
  counted as reproduced. See `docs/limitations/inventory.json` (`LIMIT-audit-package-reproduction`).
