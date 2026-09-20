# The Gold-Standard Web-Oracle Recipe (STD-WIRING)

This document is the canonical, reusable pattern for making a web-vulnerability class **FACT-capable** in
VIGIL to the near-zero-false-positive bar. It is the anchor every FACT-coverage-program slice instantiates and
every adversarial (red-pen) review checks against. It is descriptive of the machinery that already exists —
`integration/vigil_integration/live/runtime_redrive.py` (the injection/eval/error/traversal classes) and
`integration/vigil_integration/live/web_redrive.py` (open-redirect) are its two proven instantiations. **Do not
invent a parallel confirmation path**; extend these.

## The one rule this whole document serves

A claim is a **FACT** only when a deterministic VIGIL-owned oracle re-fires over evidence VIGIL captured live
through a gated channel **and** the certificate re-verifies offline. Anything weaker is a **LEAD**. A
conclusively-refuted predicate is **CLEAN**. Everything else is **INCONCLUSIVE** — and INCONCLUSIVE is *never*
rounded up to CLEAN.

The corollary that governs this recipe: **the loophole to avoid is not "a class we cannot yet FACT" — it is
*faking* a FACT.** For a small number of classes a sound deterministic FACT is structurally impossible (a
universal negative such as "no cost limit exists"; or a claim that requires operator intent to be meaningful,
such as clickjacking-as-exploit). For those, the gold standard is the strongest *sound* verdict the class
admits — a rigorous LEAD, a posture-FACT of the weakness, or a gated-workflow FACT that consumes an operator
attestation — with the irreducible boundary named in the branch `limitation` / `target_downgrade_rationale`.
Building the easy detector and calling its silence CLEAN, or minting a FACT off a signal a dishonest producer
could fabricate, are both corner cuts. This recipe forbids both.

---

## The seven steps

### Step 1 — The deterministic oracle predicate

Write (or reuse) a **pure** function in `verify/oracles.py` that returns an `OracleSignal`
(`verify/models.py`). Contract:

- No I/O, no wall-clock, no RNG. The oracle consumes only the JSON-safe evidence handed to it, so
  `verify/reverify.py` can re-run the identical decision procedure offline over the retained certificate.
- Set `conclusive=True` **only** on a channel-confirmed negative (the channel was established and the refuting
  observation is definitive). A fired signal is auto-conclusive.
- Register the class in `verify/verifier.py::BUG_CLASS_ORACLES` (and its spellings in `_ALIASES`), and add a
  dispatch arm in `OracleVerifier._run` **keyed on a fresh context key that no existing benchmark / scan /
  engage finding carries** (e.g. `csp_control`, `jwt_token`, `code_region`).
- Add a new `OracleKind` member **only** when no existing kind fits the evidence semantics — and **never** add
  it to the frozen `_ALL_ORACLES` fallback list (kept at its current count). Keeping new kinds out of that
  fallback is what makes `make gate` byte-identical: the kind is reachable *only* through its explicit
  `BUG_CLASS_ORACLES` row and fires *only* when the context carries its dedicated key.

### Step 2 — The near-zero-FP control (choose by oracle family)

Every oracle family has a matching control that a benign target trips instead of the oracle:

| Oracle family | Control | Reference |
|---|---|---|
| Differential / boolean-blind | **SPRT multi-round** — TRUE clause differs from FALSE, and the two FALSE responses agree (a dynamic page trips the "FALSEs agree" guard and cannot masquerade). **Never a single-shot differential.** | `scanner/checks.py::BooleanInferenceCheck` → `boolean_inference_oracle` |
| Probabilistic timing | **Mann-Whitney U + Hodges-Lehmann effect-size floor + optional dose-response**, benign and probe samples **interleaved** (no fixed threshold). | `scanner/checks.py::TimingCheck` → `timing_oracle` |
| Reflection / OOB | **Unique per-position / per-payload canary** (high-entropy, minted by VIGIL). The oracle fires only for the registered token. | `MarkerReflectionCheck`; `OOBCheck` + `oob.register_token` → `oob_callback_oracle` |
| Differential-presence (error / file-content / secret) | **Benign-twin baseline / soft-404 control, sent FIRST.** Refuse the finding if the signature already appears in the control. | `ErrorSignatureCheck.control_body`, `ContentSignatureCheck`, `PathProbeCheck`; shared `web_redrive.py::benign_control_fetch` |
| Achieved DOM execution | The canary must appear in a `Runtime.addBinding` call to a binding **only the driver registers** — an unforgeable planted callback, not incidental reflection. | `dom_execution_oracle`; `scanner/cdp.py`, `scanner/browser_xss.py` |
| Achieved state (IDOR / mass-assign / race / forgery / smuggling) | A **predicate over the observed post-state** with an explicit control leg that differs in exactly one variable (the ambient cookie, the CL/TE conflict, the second identity, …). | `predicate_oracle`, `achieved_state_oracle` |

### Step 3 — The VIGIL-owned live re-drive

The governed FACT does not trust the scanner's finding — VIGIL independently re-captures the evidence through a
gated channel. Model the re-drive on `runtime_redrive.py` and **reuse `web_redrive.py::_gated_web_send`
verbatim** — it is the reviewed transport:

- charter gate (`reachability_cloud._authorize`), DNS-pin (`dns_pin.resolve_and_validate` + `pinned_handlers`),
  a mandatory empty `ProxyHandler`, `_NoRedirect` (raw `Location` captured, never followed), a bounded read,
  and body-decode provenance (`body_decode.decode_body`, which sets `body_semantically_available`).
- **The runner crafts every probe** — never a tool/LLM-supplied value.
- Cover the insertion surfaces the class can live on — URL query value, URL path segment, cookie, urlencoded
  body, JSON body — each with the correct method and `Content-Type` (reuse `_candidate_query_names`,
  `_candidate_redirect_names`, `_redirect_templates`).
- Pre-flight `_authorize` once before any traffic. A probe that established **no channel** is INCONCLUSIVE,
  never CLEAN.

### Step 4 — Retained context + offline re-fire + tamper-reject

- Build the finding context with a `verify/adapter.py::FindingContext.from_*` factory (e.g.
  `from_boolean_probes`, `from_timing_samples`, `from_evaluation`, `from_error_signature`, `from_oob`,
  `from_dom_execution`, `from_predicate`, `from_code_region`) and serialize with `to_verifier_context()` so it
  carries exactly the context keys `_run` dispatches on.
- Mint the certificate **only** through admission: `oracle_adapter.certify_admitted(finding, admitted,
  provenance="live_redrive")` — documented in-code as "the ONLY sanctioned mint path" and imported
  function-locally per the FATAL-2 two-env boundary. A sovereign `live/*` module must **not** call
  `verify.confirm_and_certify` directly (see the rationale at `web_redrive.py`: a direct call would let a
  verdict outrun what the observation actually supports); it goes through `certify_admitted`, which admits the
  finding against its declared evidence-branch capability before minting.
- The certificate binds `verify.oracle_version(kind)` at mint. Offline `python3 -m framework.v2 verify
  <report.json>` re-runs the pure oracle over the retained `oracle_context`; a tamper or a spurious claim is
  caught by `reverify.matches_claim`.

### Step 5 — Evidence-branch registration

Add the branch(es) to `docs/capability-matrix/evidence-branches.json` (schema `vigil-evidence-branches/1`)
with the full field set the validator (`integration/vigil_integration/live/tool_manifest.py::
validate_branch_registry`) and `scanner/tests/test_claim_discipline.py` enforce:

- `id`, `check`, `evidence`, `fact_capable`, `clean_capable`, `preconditions[]`, `limitation`,
  `target_fact_capable`, `target_clean_capable`, `evidence_surface` (closed set), `implementation_refs[]`
  (must resolve to a real file + symbol), `oracle_version` (an `OracleKind` value resolvable via
  `oracle_version()`), `control_requirements[]` (non-empty).
- Rules the validator will fail you on: `fact_capable ⇒ non-empty resolvable oracle_version`; `LEAD-only ⇒
  empty oracle_version`; `evidence_surface == "response_body" ⇒ clean_capable = false` **and** a
  `body_semantically_available` precondition; any `current < target` gap needs `blocking_work` (> 40 chars);
  any `target == false` needs a `target_downgrade_rationale`.
- Wire the class→branch mapping into the runner's `_BRANCH_FOR` and `wiring.py::_redrive_branch_for`. Keep the
  shipped capability matrix (`hexstrike.json`) in step so it neither outruns nor lags the registry.

### Step 6 — Benchmark-corpus entry + a safe control it must NEVER flag

- Add a planted-bug handler + an `ExpectedFinding` to `eval/benchmark_app.py`, **and** a SAFE twin control
  endpoint (parameterised / escaped / benign) that the oracle must never flag.
- Refresh the signed baseline (`eval/baselines/*.json` + `.fingerprint.txt` + `.sig.json`).
- `eval/gate.py` is deliberately asymmetric: **a new false positive fails CI.** That asymmetry is the
  near-zero-FP enforcement — a class is not "done" until its safe control is green.
- For any class that introduced a new `OracleKind` kept out of `_ALL_ORACLES`, verify `make gate` stays
  byte-identical.

### Step 7 — The red-pen gate (adversarial FP construction)

Before merge, construct the adversarial cases the branch must refuse and prove non-fire as unit tests, then run
the `red-pen` agent (one reviewer never self-certifies near-zero-FP). Standing adversarial cases by family:

- a reflecting-but-not-evaluating page (SSTI/SSI — the raw-directive-survives guard);
- a static error banner independent of input (error-signature — the control-body differential);
- a soft-404 catch-all (exposure / path-probe);
- a dynamic per-request page (boolean — the SPRT "FALSEs agree" guard);
- a constant-offset slow proxy (timing — the dose-response requirement);
- a permissive RP that 200s everything (forgery-acceptance — the `control_status ∈ rejected` clause);
- a report-only CSP mislabelled as blocking (CSP achieved-bypass).

The standing machine guards are `scanner/tests/test_claim_discipline.py` + `validate_branch_registry`; the
human/agent guard is the red-pen pass.

---

## The honest-boundary ledger (what the recipe deliberately will not FACT)

These are recorded so no future slice "closes" them by fabricating a FACT:

- **Clickjacking as an achieved exploit** — framing-vs-intentional-embed is operator intent (an achieved-state
  oracle was built, false-positived on 8 variants, and was demoted; see `docs/DELIBERATE-REFUSALS.md`
  refusal 8). Stays a posture-FACT of the missing frame-defense.
- **GraphQL "no cost limit exists"** — a universally-quantified negative; oracles prove existentials. Stays a
  LEAD. The *achieved amplification* (depth/alias/batch over the returned payload) is already a FACT and is the
  sound existential dual.
- **JWT embedded-key (`jwk`/`x5c`) self-signed forgery** — refused (`docs/DELIBERATE-REFUSALS.md` refusal 7,
  guarded by `test_jwt_forgery.py`); the acceptance re-drive is driven only by the sound structural-forgery
  kinds.
- **Absence as CLEAN off a positive-only detector** (error-signature classes: nosqli/ldap/xpath) — a missing
  error is uninformative (the bug can live on a boolean/time/OOB channel this response cannot see), so those
  branches stay `clean_capable: false` with an explicit `target_downgrade_rationale`.

A sound CLEAN requires all of: (i) the channel established, (ii) evidence semantically available for the
surface, (iii) a *conclusive* refuting oracle signal, (iv) `clean_capable: true`, and (v) an honest coverage
bound (a family is CLEAN only if every branch was CLEAN; an empty composition is INCONCLUSIVE). "Found nothing"
is not CLEAN.
