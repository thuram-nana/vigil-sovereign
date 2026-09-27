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
| Differential-presence (error / file-content / secret) | **Controls sent FIRST, and the signature evaluated on the control BODY** — never inferred from whether a check returned a context, which is a STATUS test (`PathProbeCheck.probe` returns one for any status outside `(0, 404)` and leaves its signature predicate unevaluated). Refuse if the signature appears in a control. For file-content those same requirements — **TWO** controls (a **PATH-SHAPED** traversal to a nonce filename that cannot exist AND a benign **NON-path "constant emission"** value), plus a **second, semantically-different encoding of the same path that reproduces the signature** — are LEAD-QUALITY filters and are **NOT sufficient for a FACT**: they vary only the SHAPE OF THE INPUT, so an endpoint that CANONICALISES the requested name before deciding corroborates under every encoding, and one keyed on the BASENAME or a SUFFIX answers the path-shaped control with a miss because that control is built by APPENDING to the target name. Eight benign origins that read no file satisfied all of them at rate 1.0, which is why `path_traversal.file_signature` is registered `fact_capable: false`. A file-content FACT needs a **CONTENT-relationship** test (multi-file corroboration, a size/entropy relation, or a per-probe unpredictable target whose content VIGIL already knows) plus a multi-capture oracle row that can express a negation and a conjunction — see that branch's `blocking_work`. Each leg is adjudicated **FAIL-CLOSED**, and the two legs differ ON PURPOSE because they ask different questions. The **corroboration** leg asks *did the READ reproduce?* — an observation only when the answer is a **2xx whose body VIGIL completely decompressed, strictly decoded, and which is NOT EMPTY** (an empty 2xx is what a WAF or edge worker returns when it drops the payload; “nothing came back” is not evidence the read failed to reproduce). The **control** leg asks *does this origin emit the signature regardless of input?* — there the status is irrelevant (a 403 whose decoded body quotes a sample line is a good refusal) and a **provably empty body is a sound observation of absence**, without which every ordinary bare 404 control would stop the arm before the treatment. Do not collapse the two rules. An enumerated "throttle status" deny-list is NOT sufficient — it scored a WAF **403**, a 401, a 302, a 451, a 404 and an **undecodable** body (Brotli; two concatenated gzip members) as "observed, signature absent", each time persisting a correlation claim VIGIL had never measured and discarding a real file read. For a `KEY=` secret the right-hand side must be a **real value** (non-empty, long enough, no template/placeholder/self-referential marker) AND the occurrence must **BEGIN AN ASSIGNMENT** (start of line, optional whitespace, optional `export`) — a `notes:KEY=value` prose line is the key being NAMED. Index and slice the **same** string: `str.lower()` is not length-preserving. | `ErrorSignatureCheck.control_body`, `ContentSignatureCheck`; `runtime_redrive.py::_encoding_corroboration`, `runtime_redrive.py::_secret_assignment`, `runtime_redrive.py::_fetch_path`; shared `web_redrive.py::benign_control_fetch` |
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
- a soft-404 catch-all AND a 200-catch-all SPA (exposure / path-probe — the differential is over the
  control BODY, and a genuine leak behind a catch-all must still MINT: fixing a false positive by
  refusing everything is not a fix, and a refusal note must never assert an observation not made);
- a page whose output CORRELATES with what the payload means but reads nothing — a KB/search endpoint
  whose corpus documents the target file, a benign `403 path rejected` notice that quotes it. **The
  file-content arm does NOT refuse this class**; it only demotes it. A LITERAL-keyed page is refused by the
  encoding corroboration and a page that answers any path-ish input is refused by the path-shaped control,
  but a CANONICALISING page (advisory KB, canonicalising deny-list/WAF) and a BASENAME/SUFFIX-keyed matcher
  satisfy every guard — hence `fact_capable: false` on `path_traversal.file_signature`. Construct both and
  assert they mint NOTHING;
- an **EXTENSION-ALLOWLIST** static server (known/absent extension ⇒ a boilerplate help page that quotes a
  sample of the target file; unknown extension ⇒ a clean 403 with no sample). It is neither basename- nor
  suffix-keyed, and it is the counterexample that put the benign NON-path control back: the path-shaped
  control MISSES it (`…/etc/passwd.vigilctlN` is an unknown extension → the clean 403) while the
  constant-emission control (`vigilctlN.txt`, a known extension → the help page) REFUSES it. **A control is
  never deleted on a mutation-matrix result alone** — "removing it failed zero tests" measures the test
  suite, not the shape space; delete a control only after constructing the shape it uniquely refuses and
  showing that shape does not exist;
- a key NAMED rather than leaked — docs prose, a CI template, a JS concatenation, a `.env.example`
  (secret — the value-shape requirement);
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
- **A file-content signature as proof of a READ** (`path_traversal.file_signature`) — demoted to
  `fact_capable: false`. Named residual FP class: any endpoint keyed on the **canonical path**, the
  **basename** or a **suffix** of the requested name — a canonicalising hardening-advisory KB, a
  canonicalising deny-list or WAF whose 403 quotes a sample line, `v.endswith("passwd")`, an anchored WAF
  regex, `v.rsplit("/",1)[-1] == "passwd"`. Eight such benign origins minted signed FACTs at rate 1.0. The
  arm's guards vary only the SHAPE OF THE INPUT, and a read cannot be proven by varying input shape; the
  true-positive fixture and the worst false positive are the same program with a different dict value. A
  FACT here needs a CONTENT-relationship test plus a multi-capture oracle row (see the branch's
  `blocking_work`). Precedent: `verify/verifier.py:384`/`:401` dropped SIDE_EFFECT for
  `postmessage_exploited` and `csp_bypass` on the same predicate.
  **SCOPE — the demotion binds ONE layer.** `fact_capable:false` is enforced only by `live/verdict.py::admit`,
  the sole reader of this registry, so it binds `live/runtime_redrive.py`, `live/wiring.py` and the Strix
  proof rail. The CORE ENGINE never imports the integration layer, and measured on the same commit
  `framework.v2 scan` still emits `grounding:"fact"`/High/0.90 for 11/11 benign origins via
  `scanner/checks.py::ContentSignatureCheck`, `framework.v2 verify` re-verifies them `ok=True`,
  and `aegis/inspect.py:547` / `scanner/library.py:404` return `decision='confirmed'` / `action='block'`
  on legitimate traffic. That route is PRE-EXISTING and other-owned; the SECOND, independent refusal
  (dropping `SIDE_EFFECT` from `BUG_CLASS_ORACLES["path_traversal"]` and `["lfi"]`, `verify/verifier.py:139-140`)
  is the open follow-up and is recorded as a `MISSING:` control requirement on the branch.
- **A `KEY=` signature's *value* recall** (`exposure.secret_signature`) — the value shape is a character
  blacklist, so it refuses **roughly a third to a half** of a realistic leaked-credential corpus to a LEAD.
  The AGGREGATE IS CORPUS-COMPOSITION-DEPENDENT and must always be quoted with its corpus: 55% (12/22) on
  this branch's 22-shape corpus, 33.3% on an independent 30-shape corpus. The PER-CLASS figures are the
  property of the shape test and reproduce exactly across both: hex 100%, urlsafe-base64 100%, standard
  (non-urlsafe) base64 51.8% (it is refused whenever the encoding emits a `+`), every `$`-prefixed password
  hash 0%; anything with a space, a quote, `+`, `(`, `)`, `,` or the substring `example` is refused. A
  `KEY=` occurrence must additionally BEGIN AN ASSIGNMENT (start of line, optional whitespace, optional
  `export`), so a commented-out but genuine credential is refused too. These are false negatives, never
  false positives, and the measured numbers live in that branch's `limitation`.
- **The value-shape predicate AST does not re-derive the EXTRACTION** (`exposure.secret_signature`) — it
  tests only the self-consistency of `(secret_assignment, secret_value, body)`, so a value SUBSTITUTED for
  one absent from the body fails the conjunction, but a RUNNER-SIDE EXTRACTION BUG that returns the wrong
  window of the REAL body rides straight through. Measured: a `str.lower()`/original-string index
  desynchronisation (U+0130 `İ` lowercases to two characters — the only such codepoint in Unicode) minted a
  signed FACT out of a `.env` with an EMPTY `DB_PASSWORD=`, and it re-verified offline rc=0. The offset bug
  is fixed with a length-preserving fold; the AST residual is OPEN and needs a predicate op that re-derives
  "the first qualifying assignment" from `body` alone.

A sound CLEAN requires all of: (i) the channel established, (ii) evidence semantically available for the
surface, (iii) a *conclusive* refuting oracle signal, (iv) `clean_capable: true`, and (v) an honest coverage
bound (a family is CLEAN only if every branch was CLEAN; an empty composition is INCONCLUSIVE). "Found nothing"
is not CLEAN.
