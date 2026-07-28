# The veracity layer — verify/ and the oracles

This is the subsystem that makes VIGIL's moat literal: **the machine cannot lie about a
finding.** Nothing here sends traffic, mints a payload, or trusts an LLM's word. Every module
in `engine/crucible/framework/v2/verify/` is a *judge of already-captured bytes*: given evidence
a real target produced, a pure deterministic oracle decides whether a real signal fired, and only
a fired oracle can promote a proposal to a signed FACT. If you change anything here, you are
changing the definition of "true" for the whole platform — read this page first.

Companion prose: [`architecture.md` § Oracle authority](./architecture.md). This page is the
deep dive on the veracity layer specifically.

---

## 1. What it is / its job

An LLM agent (Strix) **proposes** a finding and points at where to look. The veracity layer
**adjudicates** it. The contract, in one sentence: a finding becomes a cryptographically-signed
FACT only when a *pure, deterministic oracle* re-fires over *target-produced (non-LLM) bytes* at
or above a confidence threshold, and the finding's class is one we actually have an oracle for.
Anything short of all three is a **LEAD** — retained, honestly labelled, replayable, but never
asserted as machine-verified.

The layer is deliberately split into dumb, single-responsibility pieces so no one component can
launder a guess into a fact:

| Module | Role | One-line contract |
|---|---|---|
| `verify/oracles.py` | the oracles | pure functions: observe bytes → `OracleSignal` (fired?/confidence/evidence). No I/O, clock, or rng. |
| `verify/models.py` | the types | `OracleKind` enum, `OracleSignal`, `VerificationResult`. |
| `verify/adapter.py` | `FindingContext` | typed, JSON-serialisable container of the retained evidence + `from_*` builders + `to_verifier_context()`. |
| `verify/verifier.py` | the router | `BUG_CLASS_ORACLES` map + threshold; runs the applicable oracles, applies the combine policy. |
| `verify/confirmation.py` | `confirm_finding` | the single promotion gate: `ConfirmedFinding` or `None`. No assertion-only path. |
| `verify/poc_translate.py` | the translator | executor-captured `CapturedExchange` bytes → `FindingContext`, or `None`. Not a judge. |
| `verify/reverify.py` | re-execution | re-fire the pure oracle over a retained context, offline, and check it matches the claim. |
| `integration/vigil_integration/oracle_adapter.py` | the provenance gate + minting | drives the above, enforces the honesty + provenance invariants, signs the certificate. |

---

## 2. Authoritative code paths

### The oracle contract (`verify/oracles.py`)

Every oracle is a pure function `(observed data) -> OracleSignal` (`models.py:248`). It **reads,
judges, returns — it never sends.** The module docstring (`oracles.py:1`) states the three
guarantees: pure (no I/O/network/clock/rng), deterministic (same inputs → same signal), and
side-effect-free. Confidence combination inside an oracle uses a **noisy-OR** (`_noisy_or`,
`oracles.py:179`), clamped to 0.99 so a deterministic oracle never claims certainty it cannot have.

`OracleKind` (`models.py:31`) is the family of signal a finding can be confirmed by — the value
strings are the on-the-wire identity used by re-verification, so treat them as frozen. The core
15 are what `_ALL_ORACLES` (`verifier.py:445`) contains; every later addition (AEGIS defensive
duals, posture oracles, request-side breakouts, SSO forgery) is an **additive append** reachable
*only* via an explicit `BUG_CLASS_ORACLES` row, never via the unknown-class fallback (see §3).

The oracles, grouped:

**Response-differential / blind (evidence = a baseline vs. mutated response pair)**
- `differential_response_oracle` (`oracles.py:193`, `DIFFERENTIAL_RESPONSE`) — quantifies how two
  responses diverge across `status`, `length`, `lexical` (difflib ratio), `structural`, `latency`,
  and a `marker` dimension. The `structural` dimension uses `structural_diff` (`oracles.py:155`):
  an AST-level divergence (JSON path-type set / HTML tag-path multiset) that is **invariant to
  token noise** — a per-request CSRF token or nonce does *not* read as a diff, an added record or
  DOM node does. This is the precision fix for lexical over-reporting.
- `boolean_inference_oracle` (`oracles.py:514`, `BOOLEAN_INFERENCE`) — a Wald **SPRT** over repeated
  probe rounds (shared core `_sprt_decision`, `oracles.py:476`). Each round's Bernoulli signal is
  `(TRUE differs from FALSE) AND (the two FALSE responses agree)` — the second half is a
  *dynamic-page control* that stops a page which simply changes every request from masquerading as a
  bug. Stops at the first likelihood boundary: confirm, refute, or (no boundary) **inconclusive —
  a non-fire, never a guess.**
- `timing_oracle` (`oracles.py:368`, `TIMING`) — a real hypothesis test for time-based blind, not a
  fixed latency threshold. Fires only when *all* hold: a one-sided **Mann-Whitney U**
  (`_mann_whitney`, `oracles.py:333`) rejects "no shift" at `alpha` (default 0.01); the
  **Hodges-Lehmann** median shift (`_hodges_lehmann`, `oracles.py:360`) clears an effect-size floor
  (robust to one slow request); and an optional **dose-response** check that the shift *scales* with
  the injected delay (a constant offset from a slow proxy cannot fake this). `holm_correction`
  (`oracles.py:579`) controls family-wise error when many parameters are probed at once.

**Achieved-state (evidence = raw observed values)**
- `predicate_oracle` (`oracles.py:653`, `ACHIEVED_STATE`) — evaluates a declarative predicate AST
  (`_eval_predicate`, `oracles.py:610`; ops `all/any/not/eq/contains/in/gt/…`) over the *actual*
  observed values (header values, both identities' bodies, statuses). This is the fix for the
  achieved-state rubber-stamp: the detector hands over values, the oracle decides and cites what it
  judged. The predicate is a pure JSON AST, so the certificate re-verifies offline.
- `achieved_state_oracle` (`oracles.py:682`) — fires when every field the attacker predicted appears
  in the observed record (full match only).

**Side-effect / reflection / evaluation (evidence = a sink / response body)**
- `side_effect_oracle` (`oracles.py:731`, `SIDE_EFFECT`) — a unique ≥4-char marker reached a sink it
  should never reach (stored/reflected canary, LFI/path-traversal read, log line).
- `reflection_context_oracle` (`oracles.py:812`, `REFLECTION_CONTEXT`) — for XSS. **Parses** the
  response (`_ReflectionScanner`, `oracles.py:768`, stdlib `HTMLParser`, `convert_charrefs=True`) and
  fires only when the marker landed in an *executable* position (a live tag name, inside `<script>`,
  or an `on*`/`javascript:` attribute). An HTML-encoded or text-only reflection is inert and does not
  fire — the materially-fewer-false-positives replacement for substring XSS detection.
- `evaluation_oracle` (`oracles.py:871`, `EVALUATION`) — for SSTI/EL. Fires only when the expression's
  *result* appears (e.g. `981538969`) AND the raw payload (`{{31337*31337}}`) does **not** survive
  verbatim (survival ⇒ reflected, not evaluated) AND, if a benign control is supplied, the result is
  absent from it. Separates "evaluated" from "reflected", which look identical otherwise.
- `dom_execution_oracle` (`oracles.py:1323`, `DOM_EXECUTION`) — the strongest XSS evidence: a canary
  appeared among the args the page passed to a CDP binding only the driver registered, so the injected
  JS provably *executed*.

**Crash / error / out-of-band (evidence = process output / body / OOB hits)**
- `sanitizer_signal_oracle` (`oracles.py:1284`, `SANITIZER_SIGNAL`) — scans captured stdout/stderr
  against `_SANITIZER_PATTERNS` (`oracles.py:1265`): ASAN/MSAN/TSAN/UBSAN, stack-smashing, glibc abort,
  Rust/Go panic, SIGSEGV, Python traceback (traceback fires only at moderate confidence).
- `error_signature_oracle` (`oracles.py:1398`, `ERROR_SIGNATURE`) — error-based injection: a
  distinctive engine-specific datastore/parser error (`_ERROR_SIGNATURES`, `oracles.py:1367`;
  MySQL/Postgres/MSSQL/Oracle/SQLite/Mongo/LDAP/XPath) that is present in the payload response and
  **absent** from the benign control (so a page that always shows a trace is not mistaken for a bug).
- `oob_callback_oracle` (`oracles.py:1439`, `OOB_CALLBACK`) — ≥1 inbound interaction against a
  per-finding unique correlation token: near-unforgeable proof of blind execution (SSRF, blind XXE,
  OOB SQLi, deserialization callback).

**AEGIS defensive duals & posture/forgery oracles** — `system_prompt_disclosure_oracle`
(`oracles.py:961`), `prompt_injection_oracle` (`oracles.py:1016`, control-vs-treatment behavior delta),
`credential_stuffing_oracle` (`oracles.py:1128`, SPRT + Holm), plus the request-side parse-proofs
`sql_injection_breakout_oracle` / `command_injection_breakout_oracle` / `nosql_injection_breakout_oracle`
(`oracles.py:3277`/`3332`/`3485`) and the offline posture/forgery oracles
(`k8s_posture`/`cloud_posture`/`mesh_posture`/`cicd_posture`/`mobile_posture`/`email_auth_posture`/
`identity_posture`, and `jwt_forgery_oracle` `oracles.py:3579` / `saml_forgery_oracle` `oracles.py:3901`).
Each is near-zero-FP *by structure* and reachable only through its own bug-class row.

### Routing and the threshold (`verify/verifier.py` + `verify/confirmation.py`)

`BUG_CLASS_ORACLES` (`verifier.py:33`) maps each normalized bug class → the ordered tuple of oracle
kinds that may confirm it (e.g. `boolean_sqli -> (BOOLEAN_INFERENCE, DIFFERENTIAL_RESPONSE)`,
`xss -> (REFLECTION_CONTEXT,)`, `ssrf -> (OOB_CALLBACK,)`). `OracleVerifier.confirm`
(`verifier.py:557`) selects the applicable kinds via `oracles_for` (`verifier.py:555`), runs each over
the context, keeps only signals that **fired at confidence ≥ `HIGH_CONFIDENCE` (0.7, `verifier.py:25`)**,
and applies the combine policy `any_high_confidence_fired`: one high-confidence fire is sufficient; a
non-firing oracle is recorded as **dissent**, never a veto (absence of a signal is not evidence of
absence — see `VerificationResult`, `models.py:272`). `confirm_finding` (`confirmation.py:102`) is the
one promotion gate: it returns a `ConfirmedFinding` iff an oracle fired, else `None`. There is no
code path from an assertion to a `ConfirmedFinding`.

### The provenance gate and minting (`integration/vigil_integration/oracle_adapter.py`)

`confirm_and_certify(finding, *, engagement_slug, signers, provenance="llm")` (`oracle_adapter.py:81`)
is the sovereign anti-hallucination pipeline. For one proposed finding carrying its retained
`oracle_context`, it enforces, in order (each failure returns a labelled **LEAD**, never a fact):

1. **Deterministic confirmation** (`confirm_finding`) — `None` unless an oracle fired at high
   confidence. No assertion path.
2. **Honesty invariant** — the confirmed class must be `is_known_bug_class` (in `BUG_CLASS_ORACLES`).
   A generic-oracle fire on an unmapped class stays a lead.
3. **Provenance gate (audit G4)** (`oracle_adapter.py:139`) — a signed FACT requires
   `provenance ∈ {"reproduced", "live_redrive"}` (`_REPRODUCED_PROVENANCE`, `oracle_adapter.py:48`).
   The **default `"llm"`** — the context is the model's own `extracted_info` — is demoted to a LEAD
   *even when the oracle fires*, because a crafted-but-firing context is an LLM-influenced route to a
   fact. This is the concrete line that stops the LLM from talking its way to a proof.
4. **Mint + sign** (`oracle_adapter.py:149`) — only now build the proof-carrying `EvidenceCertificate`
   (binding the `oracle_context_digest`) and sign it m-of-n with the governance authorisers.

`certify_to_scitt` (`oracle_adapter.py:167`) bridges a confirmed result to an offline-verifiable
OpenVEX/DSSE SCITT statement; it refuses a lead fail-closed.

### "Model points, oracle judges" — concretely

1. **Model points.** Strix crawls, forms a hypothesis, and proposes `{bug_class, oracle_context, …}`.
   The model chooses *where* to look and *what class* it might be. That is the entire extent of its
   authority.
2. **Bytes are reproduced, not narrated.** The `oracle_context` that will be judged must come from a
   non-LLM channel. `poc_translate.context_from_exchanges` (`poc_translate.py:71`) reshapes
   *executor-captured* request/response bytes (`CapturedExchange`) into a `FindingContext` — and
   returns `None`, never a fabricated context, if the capture lacks the structure an oracle needs
   (`poc_translate.py:15`). It is a **translator, not a judge**: a present-but-benign capture still
   translates; the oracle then declines to fire.
3. **Oracle judges.** `verifier.confirm` runs the pure oracle over that context. If it fires ≥0.7 and
   the class is mapped and the provenance is reproduced, it is a FACT; otherwise a LEAD.
4. **Anyone re-judges.** `reverify.py` re-runs the same pure oracle over the retained context offline
   and confirms the verdict reproduces byte-for-byte.

So the LLM's confidence is worth exactly nothing at the promotion boundary. The oracle's fire over
target-produced bytes is worth everything. That asymmetry *is* the product.

### Offline re-execution (`verify/reverify.py`)

Because oracles are pure, a certificate's retained `oracle_context` can be re-checked by anyone,
offline, with no target and no trust in the tool that produced it.
- `reverify_context` (`reverify.py:95`) / `_reverify_context_impl` (`reverify.py:123`) —
  reconstruct the `FindingContext`, re-run the oracle, and compare against the claimed
  `confirmed_by`/`confidence` (`_CLAIM_EPS = 1e-6`). A mismatch is flagged tampered.
- **Class binding** (`reverify.py:152`) — the retained evidence adjudicates its *own* bug_class; a
  request to re-verify a *different* class than the evidence proves is refused at the re-execution
  boundary (so a finding whose `bug_class` was flipped, e.g. sqli evidence relabelled `rce`, cannot
  re-confirm as the flipped class).
- `reverify_finding` / `reverify_document` (`reverify.py:187`/`209`) and `main` (`reverify.py:218`)
  back the CLI: `python3 -m framework.v2 verify <report.json>` — exit 0 iff *every* certificate
  reproduces and matches its claim, 2 otherwise. Run it in CI.
- The `lru_cache` memo (`reverify.py:77`) is determinism-safe: a pure function of canonical-JSON
  evidence bytes, so it can only elide a recompute that would return the identical result.

---

## 3. Invariants this subsystem must preserve (and why)

1. **Oracles are pure and deterministic — no wallclock, no rng, no I/O, no network.** This is what
   makes a certificate offline-re-verifiable and `make gate` byte-identical. A single `time.time()`,
   `random`, or network call anywhere in an oracle silently breaks re-verification: the retained
   context would re-fire to a *different* verdict and `reverify.py` would (correctly) flag every such
   finding as tampered. Determinism is not a style preference here; it is the mechanism of trust.
2. **Only a fired oracle promotes.** `confirm_finding` returns `None` with no assertion path;
   `verifier.confirm` counts only fires ≥ `HIGH_CONFIDENCE`. The LLM, critics, RL, learning, and
   self-consistency may advise, re-rank, or defer — never promote. If you find yourself adding a
   `return ConfirmedFinding(...)` that isn't gated on an `OracleSignal.fired`, stop.
3. **Provenance: a FACT needs non-LLM bytes.** The `provenance` gate (`oracle_adapter.py:139`) demotes
   an LLM-emitted context to a LEAD even when the oracle fires. A crafted context that fires is exactly
   the hallucination route this system exists to close (audit G4). Default is `"llm"` = LEAD:
   **fail-closed.** Every caller that cannot prove reproduction gets a lead.
4. **Known-class honesty.** A generic oracle firing on a class with no `BUG_CLASS_ORACLES` row stays a
   lead — we never assert a class we cannot deterministically judge.
5. **The unknown-class fallback (`_ALL_ORACLES`) is frozen at exactly the core 15.** Every AEGIS /
   posture / breakout / forgery kind is reachable *only* via its own explicit `BUG_CLASS_ORACLES` row,
   keyed on a context field (`request_payload`, `k8s_control`, `jwt_token`, `saml_xml`, …) that **no
   benchmark/scan/engage finding carries.** This is why appending oracles leaves `make gate`
   byte-identical and cannot change the verdict of any existing finding. A test asserts the tuple.
6. **Combine policy is safety-monotone.** `any_high_confidence_fired`: one fire confirms; a
   non-firing oracle is recorded as dissent, never a refutation. Absence of a signal is not evidence of
   absence.
7. **Everything an oracle judges and emits is JSON-serialisable** — the retained context and the
   `observed` field must round-trip so the certificate re-fires offline.

---

## 4. How to extend it safely

**Adding a new oracle (a new signal family):** copy the closest existing oracle as the template.
1. Add a member to `OracleKind` (`models.py:31`) with a stable snake_case `.value` (the value is the
   frozen on-wire identity; never rename one after findings exist). Append it — do **not** add it to
   `_ALL_ORACLES` (`verifier.py:445`) unless you truly intend it to run on every unknown class.
2. Write the pure function in `oracles.py`: signature `(observed…) -> OracleSignal`, no I/O/clock/rng,
   noisy-OR to combine sub-signals, an explicit non-fire (`fired=False, confidence=0.0`) with a reason
   on every rejection branch. Cite the concrete artifact in `evidence`. Bias toward **refusing** a
   weak or absent signal — near-zero-FP is the whole game; you cannot self-certify it (see §5).
3. Add a `BUG_CLASS_ORACLES` row (`verifier.py:33`) mapping the class → your kind, and a dispatch
   branch in `OracleVerifier` (`verifier.py:611` onward). Key it on a *new* context field so the
   unknown-class fallback stays frozen.
4. Add a typed `from_*` builder and the `to_verifier_context()` branch on `FindingContext`
   (`adapter.py:337`+ / `adapter.py:1016`) so the retained context round-trips.
5. If the evidence comes from captured traffic, add a channel to `poc_translate.py` (`_KNOWN_CHANNELS`,
   `poc_translate.py:39`) — remember it returns `None` (a LEAD, honest) when structure is missing, and
   never fabricates.

**Tests to add (all three, or the change is not done):**
- **Positive:** a real firing context confirms at ≥0.7 and mints a fact through `confirm_and_certify`
  with `provenance="reproduced"`.
- **Negative controls:** the benign/encoded/reflected-not-evaluated/token-noise cases do **not** fire
  (this is where FPs hide — assert the refusal *and* the reason).
- **Round-trip:** `reverify_context` reproduces the verdict from the retained JSON, and a flipped
  `bug_class` is refused (`reverify.py:152`).
- **Frozen fallback:** `oracles_for("<unknown>")` is unchanged, and `_ALL_ORACLES` still equals the
  core 15.
- **Provenance:** the same firing context with `provenance="llm"` returns a **LEAD**, not a fact.
- **Determinism:** same inputs → identical `OracleSignal` across runs.

Get an **independent adversarial reviewer** on any new oracle (see the `adversarial-sweep` and
red-pen practice) — near-zero-FP cannot be certified by the author alone.

---

## 5. Gotchas

- **`OracleKind` is `(str, Enum)`, not `StrEnum`.** `str(kind)` yields `'OracleKind.X'`, not the
  value. Always store/compare `kind.value` — the reproduction and `verify_certificate` layers compare
  against `.value` and will reject the repr as tampered (`oracle_adapter._kind_str`, `oracle_adapter.py:73`).
- **`provenance` defaults to `"llm"` = LEAD.** Forgetting to pass `provenance="reproduced"` silently
  gets you leads, not facts. That is intended fail-closed behavior — but if "everything is a lead", check
  this first.
- **A translated context is not a fired oracle.** `poc_translate` returning a `FindingContext` means
  "there is something to adjudicate", not "it's a bug". `baseline == mutated` still translates; the
  oracle declines. Keep the translator dumb and the oracle the sole authority (`poc_translate.py:15`).
- **Near-zero-FP is structural, not confidence-tuned.** The precision oracles win by *parsing*
  (reflection context), *separating evaluated from reflected* (evaluation), *controlling for the benign
  case* (error signature / evaluation controls), and *statistical tests with effect floors and
  dose-response* (timing) — not by nudging a threshold. Add a control, don't raise a number.
- **Don't grow `_ALL_ORACLES`.** Reaching a new oracle via the unknown-class fallback would change the
  verdict of existing findings and break the `make gate` byte-identical guarantee. Route via an explicit
  bug-class row keyed on a fresh context field.
- **Two-env boundary.** `oracle_adapter.py` lives in `vigil_integration` (installed in *both* venvs) and
  imports `framework.v2` **lazily** (function-local, `oracle_adapter.py:109`) so importing the module
  never drags CRUCIBLE into the sovereign interpreter. Keep any new `framework.v2` import lazy — a
  top-level import here is a FATAL-2 boundary break.
- **A traceback fires only at moderate confidence.** A bare Python `Traceback` can be an ordinary
  handled error; it sits below the strong sanitizer markers on purpose (`oracles.py:1280`).
