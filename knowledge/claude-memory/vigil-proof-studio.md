---
name: vigil-proof-studio
description: "VIGIL Proof Studio — Strix exploit → oracle-confirmed signed replayable proof + client-verifiable bundle (B0-B6, C1)"
metadata: 
  node_type: memory
  type: project
  originSessionId: 7758e121-f349-47d5-886b-6bb5a1d60e27
  modified: 2026-07-28T19:31:02.357Z
---

VIGIL Proof Studio turns a Strix free-text PoC into an oracle-confirmed, signed, replayable, offline-verifiable FACT (the moat: the machine can't lie about a finding). Part of the [[vigil-fusion-program]] Proof Studio phase.

**Merged:** B0-B4/B6 crypto backend (#132) · B5 live wiring + screen (#140) · C1 client-verifiable bundle (#141) · launcher activation (#142). Each slice: build → adversarial red-pen (a Workflow of independent skeptics that actually run mint→export→mutate→verify) → fix → CI → merge.

**Architecture (offense-side, FATAL-2: framework imports LAZY):**
- `proof.engine.mint_proof(provenance="reproduced")` — mints a FACT ONLY over executor-captured non-LLM bytes; content-gate FIRST (denies evasion/persistence/destructive PoC even if the oracle would fire); binds raw bytes into an EvidenceCertificate; re-proves from disk.
- `proof.sink.ProofSink` — the duck-typed `strix.report.state.proof_sink` hook; screens the report, mints on an attached `_vigil_capture`.
- `proof.run.build_report_mint` — the sink's mint callback; persists a proof RECORD (`<run_dir>/proofs/<id>.json`) AND, per FACT, a re-verifiable finding (`<run_dir>/proofs/reverifiable.json`) + materialises raw bytes under `<run_dir>/evidence/<action_id>`.
- `proof.bootstrap.install_from_env` — assigns the sink into the Strix process from `VIGIL_PROOF_RUN_DIR` (absent ⇒ NO-OP, vendored Strix byte-identical).
- `strix.report.proof_capture` (IMPORT-CLEAN, in vendor/strix) — turns Caido's raw RESPONSE bytes into `_vigil_capture` (channel `error_signature`); prefers a cited request id, else auto-correlates by endpoint/method; READ-ONLY (never re-sends).
- `proof.bundle.export_bundle` + `vigil proof-export` verb + console `proof_export` + `/api/proof/export` + Proof Studio "Export" button.

**Load-bearing lessons (non-obvious):**
- **The oracle judges the BYTES; the model only POINTS.** A capture cites a Caido request id / endpoint, never the bytes. A benign/wrong exchange → the oracle doesn't fire → honest LEAD, never a false FACT. This is why the wiring is sound even though the model influences the request.
- **`FindingContext.model_dump(mode="json")` is the oracle_context serializer** (NOT `to_verifier_context`, which is the lossy oracle-INPUT shape). The finding's top-level `bug_class` must mirror the class embedded in the context — `reverify_context` refuses a class flip.
- **The error-signature oracle's class is `error_based_sqli`** (fires on a datastore error in the response, absent in a control). The sound auto-proof path is a SQLi finding whose captured response carries a real SQL error; everything else is an honest LEAD.
- **C1 crypto-review finding (the big one): "zero trust in VIGIL" OVERCLAIMS if the trust-root ships inside the bundle.** An attacker controlling the bundle can re-sign it under their own key + ship a matching `trust-root.json` → verify exits 0. The CONTENT layers still hold (reproduction is signer-independent — a non-reproducing finding can't be forged), but authenticity must be anchored OUT-OF-BAND. Fix: export writes `TRUST-ROOT-FINGERPRINT.txt`; `evidence verify --trust-root-fingerprint <fp>` pins it (mismatch refuses) + warns loudly on an unpinned in-bundle root. Honest framing: you don't trust VIGIL's word — you re-run the check; trust reduces to the out-of-band-pinned governance key + the auditable open-source verifier.
- **The verifier is offense-free** — `python -m framework.v2 evidence verify` loads only `framework.v2.{common,entitlement,evidence,verify}` + vigil_core (no strix/scanner/engage/aegis/kernel). Deps: pydantic, cryptography, structlog, packaging (PyYAML optional). Don't claim "pydantic-only" — that undercounts.
- **Confine untrusted `action_id`** at the export boundary (absolute/`..` → drop artifacts) — the verify side has `_confined()` but the export walk didn't.
- **CI two-env boundary job** has TWO pytest invocations: framework-needing tests (that lazy-import `framework`) must be `--ignore`d in the first (`integration:gateway`, sovereign-path) and listed in the second (`integration:engine/crucible:gateway`). New proof tests (`test_proof_run/bootstrap/bundle`) all needed this.
- **Vendored strix tests go in `vendor/strix/tests_vigil/`** (CI runs that dir, `PYTHONPATH=vendor/strix`, only `pytest`+optional openai-agents), loaded via importlib direct-from-file to dodge the heavy `agents` dep; drive async with `asyncio.run` (no pytest-asyncio).

**Launcher activation (#142):** the console codebase→Strix launch (`_spawn_background` `env_extra`) now sets `VIGIL_PROOF_RUN_DIR=<run_dir>` + `VIGIL_ENGAGEMENT=<slug>`, so `install_from_env` fires the sink writing under that run dir. Scoped to the Strix path only (URL/scan get no proof env — negative-control tested). So the pipeline fires end-to-end from a real `vigil up` codebase run; the ONLY live-only piece left is Caido + a running web target producing the capture.

**A6a remediation oracle (#144):** `vigil patch`/autopatch had a sound fail-closed verify (`verify_fix`/`verify_patch`) but NO concrete oracle wired (`oracle=None`). `remediation/fix_oracle.py` (`build_fix_oracle`/`build_fix_signer`/`build_run_fix_oracle`) now RE-FIRES the driving FACT's oracle over the patched build's re-driven bytes (reusing `context_from_exchanges`+`reverify_context`) and signs a remediation cert ONLY on genuine silence — a remediation is proven the SAME way a finding is. The mint records the driving finding's `channel` in reverifiable.json; `autopatch_live` gains `verify_oracle` (default None = byte-identical). Live re-drive (standing up the patched build) is the caller-provided capability — same live-infra class as the Caido capture.
- **A6a crypto-review lesson (HIGH defect fixed):** the request-side guard checked the RE-DRIVE's SELF-REPORTED channel — a hostile/buggy re-drive claiming a different channel builds a context for the WRONG oracle family whose input the resolved oracle never reads → `reproduced=False` is a VACUOUS non-fire, minted as genuine silence → a still-vulnerable build certified fixed. FIX: PIN the driving finding's oracle channel (from reverifiable.json) and REQUIRE the re-driven capture's channel to equal it (mismatch → raise → unverified); `expected_channel` required, request-side refused at build. **Lesson: `reproduced=False` must be split into genuine-differential-silence-over-the-correct-oracle vs wrong/absent-evidence; never trust a driver's self-reported channel for a soundness gate.**

**Charter remote-target UI (#143):** the Charter & Attestation screen now HANDLES the remote case (verify + guide, never mint): `api.charter_status(slug)` (GET `/api/charter/`) splits scope into loopback vs REMOTE hosts + the out-of-band ceremony template; a "Remote target" card shows an advisory coverage check + the exact `vigil provision --scope <remote>` ceremony (run on a trusted host, NOT the UI). The UI provisions LOOPBACK only — can never mint/widen a remote charter.
