# Proof Studio (`vigil_integration.proof`)

## What it is / its job

Proof Studio is the seam that turns a Strix proof-of-concept into an **oracle-confirmed, signed,
replayable, offline-verifiable FACT** — or, honestly, a labelled LEAD. Where the live oracle seam
(`live/wiring.py:_build_oracle`) passes the model's *own* `extracted_info` with `provenance="llm"`
(always a LEAD), Proof Studio rebuilds the `oracle_context` **only from executor-captured, non-LLM
bytes** and passes `provenance="reproduced"`, so a deterministic oracle can re-fire over real target
output and mint a certificate. The package is a **soft dependency of vendored Strix**: absent its
run-context env var it is an inert NO-OP and Strix behaves byte-identically. See the deep-dive KB at
[`../../../knowledge/kb/proof-studio.md`](../../../knowledge/kb/proof-studio.md).

## The pipeline: capture → content-gate → reproduce → oracle → sign → spool

```
Strix report (+ _vigil_capture) ──► sink.ProofSink.__call__          screen poc_script_code
                                     └─ content_gate.screen_poc_content ──► DENY ⇒ quarantine, stays LEAD
                                     └─ ALLOW + capture present + mint wired
                                          └─ run.build_report_mint → mint(report)
                                               └─ engine.mint_proof
                                                    (1) content gate  (again, authoritative)
                                                    (2) reproduce      poc_translate.context_from_exchanges(bytes)
                                                    (3) oracle+provenance  oracle_adapter.confirm_and_certify("reproduced")
                                                        ├─ non-fire / unmapped / llm ⇒ LEAD
                                                        └─ FACT: build_certificate → sign_certificate
                                                                 → reverify_context (replay from on-disk bytes)
                                                                 → KeylessOffenseWorker.emit_finding_envelope
                                                                 → finding_spool.spool_envelope  (crosses to spine)
                                               └─ run._persist_record  + run._persist_reverifiable (reverifiable.json)
```

Each stage is authoritative code:

| Stage | File · symbol | Key lines |
|-------|---------------|-----------|
| Duck-typed Strix hook | `sink.py` · `ProofSink.__call__` | screens then mints; `sink.py:91` |
| Content safety floor | `content_gate.py` · `screen_poc_content` | 5 categories, `content_gate.py:115` |
| Report→mint seam | `run.py` · `build_report_mint` / `mint` | reads `_vigil_capture`, `run.py:185` |
| Deterministic mint | `engine.py` · `mint_proof` | the three gates, `engine.py:133` |
| Startup wiring | `bootstrap.py` · `install` / `install_from_env` | `bootstrap.py:45`, `:71` |
| Client bundle | `bundle.py` · `export_bundle` | `bundle.py:96` |
| Payload minimization (optional) | `minimize.py` · `minimize_payload` | ddmin, `minimize.py:48` |

**`_vigil_capture` is the only mint-eligibility signal.** It is attached under `CAPTURE_KEY =
"_vigil_capture"` (`sink.py:34`) *by the trusted executor capture path, never by the LLM*. A Strix
report alone carries only the model's free text, so by itself it can **never** mint a FACT — the sink
records the ALLOW and returns (`sink.py:107-115`). Shape: `{"exchanges": [...], "blobs": {ref: raw_bytes}}`
(`run.py:12-16`).

## `VIGIL_PROOF_RUN_DIR` — how activation works

Proof Studio only wakes up inside the **keyless offense Strix process** when the VIGIL console launches
it. The console exports `VIGIL_PROOF_RUN_DIR` (the run's dir) plus `VIGIL_ENGAGEMENT` on the Strix
subprocess (`engine/crucible/framework/v2/console/actions.py:552`). At Strix startup,
`vendor/strix/strix/interface/cli.py:140-145` best-effort calls `proof.bootstrap.install_from_env`, which:

- **returns `None` (NO-OP) when `VIGIL_PROOF_RUN_DIR` is unset** — standalone Strix runs unchanged
  (`bootstrap.py:75-76`);
- otherwise provisions the run's governance signers and assigns a `ProofSink` (whose `mint` is
  `run.build_report_mint`) onto `strix.report.state.proof_sink` (`bootstrap.py:58-68`).

Every path is fail-closed and swallows its own errors — **the sink must never break Strix's persistence
or startup** (`bootstrap.py:87-89`, `sink.py:116-118`).

## The client-verifiable bundle (`bundle.py`)

`export_bundle` (driven by `vigil proof-export`, `integration/vigil_integration/cli.py:462`) assembles a
self-contained directory a third party verifies **offline, with zero trust in VIGIL**:

- `evidence-bundle.json` — the signed `EvidenceCertificate`s + hash chain + governance-signed head;
- `trust-root.json` — the **public** governance keys + m-of-n threshold (only public keys ever hit disk);
- `TRUST-ROOT-FINGERPRINT.txt` — the authenticity anchor the client **pins out-of-band**;
- `reverifiable.json` — the `{active_findings: [...]}` report, each with its `oracle_context` to re-fire;
- `evidence/<action_id>/…` — the raw executor-captured bytes each certificate binds by sha256;
- `README.md` — the one-command verify.

Verify: `python -m framework.v2 evidence verify --report reverifiable.json --bundle . --trust-root
trust-root.json --evidence-root evidence --trust-root-fingerprint <op-published>`. Exit 0 iff **every**
certificate is authentic (m-of-n sig), bound, reproduced (the same deterministic oracle re-fires),
artifact-hashed, and chained. The material comes from `run.read_reverifiable` — each entry is written at
mint time by `run._persist_reverifiable` (`run.py:135`) as the *same plain-dict `oracle_context` shape* a
scan's `reverifiable.json` carries, so the open-source verifier re-fires it byte-identically.

## Invariants this package preserves — and why

1. **Oracle authority — only a fired deterministic oracle over non-LLM bytes mints a FACT.** The mint's
   provenance is a **module constant** `_REPRODUCED = "reproduced"` (`engine.py:52`), not a parameter, so
   no caller can relax it. `confirm_and_certify(provenance="reproduced")` (`engine.py:197`) demotes a
   non-fire / unmapped class / LLM-provenanced context to a labelled LEAD. `run._oracle_bug_class`
   (`run.py:70`) only *hints which oracle to try*; a wrong hint fails to fire → honest LEAD, never a
   fabricated FACT.
2. **Content gate is a fail-closed floor screened BEFORE anything is minted, stored, or replayed.**
   `screen_poc_content` DENYs on any of five payload classes (detection-evasion, persistence, destructive,
   self-propagating, credential-exfil), a non-`str`, oversized (>1 MiB), or any internal error — it can
   only DENY, never bless (`content_gate.py`). A DENY quarantines and returns **even if the oracle would
   fire** (`engine.py:166-171`): a dangerous "proof" is never stored, surfaced, or re-run.
3. **Gate of record + spine crossing.** A FACT crosses to the sovereign plane only via
   `KeylessOffenseWorker.emit_finding_envelope` → `finding_spool.spool_envelope`, which **refuses an
   unsigned envelope** (`engine.py:252-256`) — a LEAD can never cross. Planes bridge only by this signed
   inert file spool, never a shared interpreter.
4. **FATAL-2 lazy-framework rule.** This package is installed in **both** venvs (it lives under
   `vigil_integration`), so **every `framework.v2` import is function-local** — importing any module here
   in the sovereign env must never pull `framework`. Verified sites: `engine.py:174, 189, 209-212`;
   `run.py:140, 186`; `bundle.py:108-110`; `bootstrap.py:39, 58`. Module-scope imports are all
   import-clean (`content_gate`, `sink`, `run`, `offense_worker`, `finding_spool`). See the `__init__.py`
   docstring.
5. **Determinism + append-only + sealed-at-rest.** No wallclock / rng in mint math — `proof_id` and
   `action_id` are content addresses (`run.py:98-100`, `run.py:207`), `seq` is passed in, cert order is
   the reverifiable-finding order. Proof/quarantine dirs are `0700`, records `0600`; the governance
   **private** key is only ever an in-process Python argument — never argv or the spine (`bundle.py:106`,
   `bundle.py:87-93`).

## How to extend it safely

- **New dangerous payload class:** add a `(label, compiled-regex)` entry to a category in
  `content_gate._CATEGORIES` (`content_gate.py:65`). Keep it a *deny floor* over post-exploitation
  behaviour — do **not** flag ordinary injection PoCs (a SQLi tautology, a reflected `<script>`, an SSRF
  URL are intentionally clean). Add both a positive-match and a benign-PoC negative-control test.
- **New oracle bug-class hint:** extend `run._oracle_bug_class` (`run.py:70`). It only picks *which*
  oracle to try; the oracle still judges the bytes, so a bad hint is safe (→ LEAD). Never add a path that
  mints without `confirm_and_certify`.
- **Any code touching `framework.v2`:** import it **inside the function**, mirroring the existing lazy
  sites above. A module-scope `framework` import is a FATAL-2 regression — verify with
  `python -c "import vigil_integration.proof.<mod>"` in the sovereign env (`.venv-sovereign`).
- **Tests to copy:** `integration/tests/test_proof_bootstrap.py` (env-gated activation NO-OP + wiring
  end-to-end), `integration/tests/test_proof_bundle.py` (bundle contents + flip-a-byte fails closed).
  Any new mint path needs a test that a LEAD/denied case produces **no** signed cert and **no** spooled
  envelope.

## Gotchas

- **The sink never raises.** `ProofSink.__call__` and the injected `mint` swallow every exception; a mint
  error yields `minted=False` and the finding stays a LEAD (`sink.py:108-118`). Do not "fix" this by
  letting errors propagate — it protects Strix's persistence.
- **`reverifiable.json` is a sibling of the proof records, not one of them.** `run.read_proofs` explicitly
  skips it (`run.py:54`); it is read by `run.read_reverifiable`.
- **Replay proves from the retained on-disk bytes.** When an evidence dir is given, the FACT is
  re-verified by re-resolving each ref from `evidence_root/action_id` (`engine.py:232-244`) — a genuine
  offline re-proof that also catches a materialization/tamper bug. A cert that will not re-confirm demotes
  to a LEAD.
- **Reverify uses the ORIGINAL `bug_class`, not the normalized `res.bug_class`** (`engine.py:244`) —
  reverify compares class without normalizing, so re-firing with the normalized alias would spuriously
  demote every alias class.
- **The bundle's `trust-root.json` is only a convenience copy.** Zero-trust rests on the operator
  publishing `TRUST-ROOT-FINGERPRINT.txt` **out-of-band** and the client pinning it with
  `--trust-root-fingerprint`. Without the pin, exit 0 proves internal consistency + reproduction but
  **not authenticity** — anyone could have re-signed the bundle under their own key (`bundle.py:24-30`).
- **`minimize.py` is deliberately off the mint path.** It never mints, signs, or spools; it re-screens
  every candidate through the content gate first (`minimize.py:66-69`) so a reduction can never launder a
  dangerous payload past the safety floor, then hands the reduction back for the mint to re-certify.
- **A content-gate ALLOW is not a safety claim.** It is a deterministic pattern floor over five known
  classes with near-zero false positives — defence in depth, not proof the content is safe to execute
  (`content_gate.py:24-30`).
