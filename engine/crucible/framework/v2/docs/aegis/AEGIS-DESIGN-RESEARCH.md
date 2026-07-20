# AEGIS — Unified Design Document

*The defensive dual of CRUCIBLE. Additive package `framework/v2/aegis/`. Built on the "moat" base; grafts the MVP's near-zero-FP honeypot tripwire and depth's honest per-class coverage map.*

---

## 1. AEGIS in one paragraph

AEGIS is **CRUCIBLE's prove-don't-guess reasoning core pointed inward** — an embeddable API/SDK a web app integrates that ingests its own request / LLM / content telemetry as provenance-tagged `Observation`s, fuses them into a **per-actor Beta belief** in the world-model, and promotes a "signal" to a **confirmed AI attack only when a deterministic oracle re-fires over retained evidence**, emitting a re-runnable certificate anyone can replay offline. The defensive-dual thesis: the exact machinery that makes CRUCIBLE's *offensive* findings non-hallucinated — the `OracleVerifier` → `reverify_context` → `veracity.admit()` (only-demotes) pipeline — makes AEGIS's *defensive* detections non-hallucinated. That is the moat no siloed WAF/bot-vendor has: **cross-signal reasoning over a per-actor belief + provable, replayable verdicts**, instead of an opaque scalar risk score. Where no honest oracle exists (is this text AI-generated? is this face a deepfake?), AEGIS ships a **calibrated LEAD with a conformal band and a refutation channel — never a fake verdict.** Shipping those as leads rather than "AI detects AI" verdicts is precisely what makes AEGIS doctrine-compliant.

---

## 2. Threat model (prioritized, honestly scoped)

AEGIS *emits a signal* for every class below. The honest split — which promote to CONFIRMED via a real oracle vs. which stay calibrated LEADs — is the spine of the design, not a weakness. This table is the public-facing detection catalog.

| # | AI-attack class | Detectability | Value | Deterministic oracle → CONFIRMED? |
|---|---|---|---|---|
| 1 | **Prompt injection / jailbreak vs the app's OWN LLM** | High | High (if LLM) | **Yes** — planted canary substring + control-vs-treatment behavior-change |
| 2 | **Indirect / stored injection (RAG poisoning)** | High at ingest | High (if RAG) | **Yes** — hidden-char present/absent (deterministic) + end-to-end propagation hash-linked on spine |
| 3 | **AI credential-stuffing / ATO** | Med-High | High (universal) | **Yes** — SPRT over unseen-`(account,source)` auth outcomes + Holm multi-identity control |
| 4 | **Agentic scraping / recon** | Medium | High | **Partial** — honeypot-link fetch is confirmed-automated; behavioral rest = LEAD |
| 5 | **AI-orchestrated scanning / fuzzing** | Med-High | Medium | **Exploitation yes** (reuse `verify/oracles.py` unchanged); "AI-ness" = LEAD |
| 6 | **AI phishing / spam / fake reviews** | Medium | High (UGC) | **Behavior yes** (IDN-lookalike + minhash dedup); "AI-generated" attribution = LEAD |
| 7 | **Behavioral-evasion human-mimic bots** | Low (adversarial) | Medium | **No** — signal-only + honeypot anchor |
| 8 | **Adversarial ML (evasion / extraction / MI)** | Medium | Med (if ML endpoint) | **Extraction-scale yes** (query-coverage threshold); evasion/MI = LEAD |
| 9 | **Synthetic identity / deepfake signup** | Low from request path | High (KYC) | **Velocity/dedup yes**; deepfake media = **out of AEGIS's lane** (say so plainly) |

**Explicitly deferred / never shipped as verdicts:** statistical "AI-generated text" attribution (§6, no reliable oracle — also an equity hazard for non-native writers), behavioral-mimicry biometrics (§7, direct arms race), deepfake media assessment (§9, needs a specialized media model outside an in-request-path SDK). These ship as LEADs where a signal exists, or not at all.

**The differentiated headline:** class 1 is the crown jewel because the app controls both ends of the LLM I/O, so a planted canary makes prompt-injection a *confirmed, re-runnable certificate* — the direct defensive dual of prove-don't-guess.

---

## 3. Architecture

### 3.1 The detection pipeline (signal → observation → scored → oracle → verdict)

```
 app telemetry (SDK)
   │  bounded, safe-parsed, PII-redacted at the ingest boundary (§5)
   ▼
[1] SENSOR.normalize()  ──►  intel.Observation(s)            sensors/base.py:37 (Sensor protocol)
      source_kind = request_telemetry | llm_interaction | content_submission | auth_telemetry | model_query
      source_reliability (Admiralty A-F×1-6), polarity (a PROVABLY-HUMAN obs REFUTES → lowers belief),
      monotonic caller-supplied seq (NEVER wallclock)          intel/models.py:39,90
   ▼
[2] project_observation(actor_world, obs)                    intel/project.py:35
      per-ACTOR Beta-belief upsert (alpha/beta) — corroboration/refutation/provenance for free,
      order-independent + deterministic; enters as GROUNDING_INTEL → provenance "intel:" (a LEAD)
   ▼
[3] FUSION + SCORE                                            worldmodel/models.py:203
      within-surface: socialdefense noisy-OR over weighted signals   socialdefense/models.py:27
      across-surface: belief_lcb (thinly-evidenced actor scores BELOW a proven one — honest)
      → candidate LEAD with a conformal band                         calibration/conformal.py
   ▼   (STOP HERE if no oracle applies — ship the calibrated LEAD)
[4] build FindingContext (retained evidence, a translator not a generator)   verify/adapter.py:122,461
   ▼
[5] OracleVerifier.confirm() / reverify_context()            verify/verifier.py:237, reverify.py:95
      NEW aegis oracles fire ONLY over retained evidence, deterministically.
      no oracle ⇒ non-firing signal, never an assumed pass
   ▼
[6] veracity.admit(Claim)  — re-executes each ground bound to its bug_class, can ONLY demote/abstain
      veracity/firewall.py:105  → UNGROUNDED for a fabricated actor; LLM-only can't reach fact strength
   ▼
[7] SCE assess_finding() → posterior vs the MECE benign twin  confidence/decision.py:63
      (fast-human vs bot; benign-edge-prompt vs jailbreak; nat-cgnat-bulk vs stuffing)
   ▼
   VERDICT {decision, confidence, band, certificate, provenance, ...}
   + lifecycle events on the signed spine                     agents/blackboard.py, spine_chain.py
   ▼
   operator/end-user confirm|dismiss → credit_outcome()       calibration/reward_bus.py:52
```

Two load-bearing invariants:
- **`decision == CONFIRMED` ⇒ `certificate is not None`** — the certificate is the output of `reverify_context`, replayable offline with no app and zero trust in AEGIS.
- **`provenance == "grounded:" ⇒ an oracle fired**, enforced because every "this was an AI attack" claim is routed through `admit()`, which can only demote or abstain.

### 3.2 The embeddable API/SDK surface

**Integration tier A — one-line passive middleware (auto-instruments classes 3 + 4):**
```python
from aegis import Aegis, Surface
aegis = Aegis.from_config("aegis.toml")          # loads config, opens spine sink, warms oracles

@app.middleware                                   # Flask/FastAPI/Express-equivalent shim
def aegis_hook(request, call_next):
    probe = aegis.observe(                         # PASSIVE, read-only, always safe
        surface=Surface.AUTH,
        actor=ActorRef(ip_hash=h(req.ip), session=req.session_id, principal=req.user),
        signal={"outcome": "fail", "username_hash": h(req.form["u"]), "seq": aegis.next_seq()},
    )
    resp = call_next(request)
    return aegis.annotate(resp, probe)             # attaches verdict header only if operator opts in
```
The middleware extracts **metadata only** (method, path, ordered header names + JA4/JA4H fingerprint if the TLS terminator exposes it, timing marks, auth outcome), serves the honeypot link, and watches for its path (class 4).

**Integration tier B — explicit LLM guard (class 1 flagship; the app must opt in because only it knows its LLM I/O):**
```python
with aegis.llm_turn(actor, system_prompt_id="sp_v7", canary_ids=["cx_9f"]) as turn:
    turn.record_input(user_text)                   # untrusted user turn
    out = my_llm(system=turn.rendered_prompt, user=user_text)
    turn.record_output(out)                        # canary/boundary oracle runs here
verdict = turn.verdict()                           # LEAD or CONFIRMED(prompt_injection) + certificate
```
Key move: the app **pre-registers** its system prompt and the planted canary sentinels once, out of band. At detect time AEGIS receives only `system_prompt_id` + `canary_ids` + the observed output — so the oracle re-fires deterministically **without AEGIS ever storing the operator's proprietary prompt text.**

**Integration tier C — raw HTTP escape hatch (non-Python):** `POST /aegis/detect` with a bounded `TelemetryEnvelope` → `Verdict` JSON. Same code path; the HTTP boundary is where untrusted-input hardening lives (§5).

**The `Verdict` object — honest by construction:**
```python
@dataclass(frozen=True)
class Verdict:
    decision:        Literal["confirmed", "lead", "clear"]   # NEVER a bare boolean
    attack_class:    str                 # a known_bug_classes() member — parse-rejected if hallucinated
    belief:          BeliefRef           # {mean, lcb, n_observations} — the per-actor posterior
    confidence:      float               # SCE posterior
    band:            tuple[float, float] | None   # conformal band — honest, or None (no finite-sample guarantee)
    top_alternative: tuple[str, float]   # the MECE benign explanation + its posterior
    certificate:     CertRef | None      # present iff decision=="confirmed"; re-runnable via reverify_context
    provenance:      str                 # "intel:..." (lead) | "grounded:..." (confirmed)
    contributing:    list[SignalRef]     # every observation that moved the belief
    action:          Literal["allow","observe","challenge","throttle","block"]  # default "observe"
    refutation:      RefuteChannel        # {how_to_dispute, dismiss_token} → feeds credit_outcome
```
`decision == "clear"` is **not "safe"** — it is "no oracle fired and signals below band." Documented as such.

---

## 4. CRUCIBLE reuse (cited) vs. what is NEW

### Reused verbatim — the load-bearing moat
- **Verifier / adapter / reverify certificate pipeline** — `verify/verifier.py:237` (`OracleVerifier.confirm`, no-oracle-no-confirmation), `verify/adapter.py:122,461` (`FindingContext` + `to_verifier_context`, an explicit *translator not generator* — matches "ingest telemetry, never attack"), `verify/reverify.py:95` (`reverify_context`, the offline-replayable cert; the branch's memoization cache at `:77` applies unchanged).
- **Existing oracles fire on AEGIS inputs with zero modification** — `boolean_inference_oracle` (SPRT, `oracles.py:471`), `timing_oracle` (Mann-Whitney U + Hodges-Lehmann + dose-response, `oracles.py:363`), `holm_correction` (`oracles.py:548`), `reflection_context_oracle` / `evaluation_oracle` (`oracles.py:781,840`). **The single biggest already-built win: the hard timing/behavioral statistics are done.**
- **Veracity only-demotes firewall** — `veracity/firewall.py:105` (`admit()`); `_oracle_ok` re-executes via `reverify_context` bound to the claim's own `bug_class` (`firewall.py:50`). Firewall unchanged; AEGIS only builds `Claim`/`GroundingToken` (`veracity/claims.py`, `tokens.py`).
- **Sensor → Observation → projection keystone** — `sensors/base.py:37` (Sensor protocol = a gated `Tool` + `normalize`; the shared minter pattern `service_observations` at `:67`), `intel/models.py:90` (`Observation` with Admiralty `source_reliability`, refuting `polarity`, monotonic `seq`), `intel/project.py:35` (`project_observation`, order-independent Beta upsert), `:85` (`observation_to_evidence`).
- **World-model Beta belief + provenance tiers** — `worldmodel/models.py:203` (`belief_mean`/`belief_lcb` — the per-actor score a scalar risk number structurally can't express), `classify_provenance` `GROUNDING_INTEL → GROUNDING_GROUNDED` (`models.py:159`) = the literal signal→confirmed pipeline.
- **Signed event spine** — `agents/blackboard.py` + `spine_chain.py`; existing `EventKind` (`agents/models.py:29`) already covers AEGIS's lifecycle: `tool_call`/`tool_result` (a sensor ran), `finding` (confirmed detection), `refusal` (a gate fired), `reward`, `critic_verdict`.
- **SCE calibrated posterior** — `confidence/decision.py:63` (`assess_finding` vs the specific MECE benign competitor, `_ALTERNATIVES`/`_CONFIRMATION_LR` at `:33,44`), `calibration/conformal.py` + `confidence/engine.py:62` (honest band or Bayesian fallback).
- **Reward/calibration loop** — `calibration/reward_bus.py:52` (`credit_outcome` fans operator confirm/dismiss to bandit + calibration ledger + priors).
- **Fail-closed gate chain** — `agents/tools/invoker.py:143` (`invoke_tool`: kill-switch → entitlement → scope → destructive-confirm → egress, every gate fail-closed, every call spine-logged before it runs). Every AEGIS *response* rides this unchanged.
- **Lead-not-verdict content detector** — `socialdefense/detectors.py` + `models.py:27` (weighted noisy-OR, `RiskBand`, "leads not verdicts") — extended for content classes.

### Genuinely NEW (the buildable delta — small, additive)
1. **New oracle bodies** in `aegis/oracles.py` (same purity contract as `verify/oracles.py` — pure, deterministic, no wallclock/rng): `prompt_injection_oracle` (structurally the `evaluation_oracle` control-vs-treatment pattern + canary substring), plus later assembly-of-existing-stats bodies `credential_stuffing_oracle`, `model_extraction_oracle`, and the `honeypot_hit_oracle` set-membership helper.
2. **New vocabulary (additive appends, not rewrites):** new `OracleKind` members + `BUG_CLASS_ORACLES` rows + `known_bug_classes()` entries (`verify/models.py:31`, `verify/verifier.py:33,186`) for `prompt_injection`, `credential_stuffing`, `automated_scraping`, `model_extraction` — so an AI-attack class asserted as oracle-provable **cannot be a hallucinated label** (`require_known_bug_class` rejects OOV at pydantic parse, `verifier.py:205`); new `IntelSourceKind` members (`intel/models.py:39`); a couple of external-actor `NodeKind`/`EdgeKind` (`ACTOR` node, `ISSUED`/`TARGETS`/`EXHIBITS` edges — some reuse `SESSION`+`INDICATOR`); new `_ALTERNATIVES`/`_CONFIRMATION_LR` rows.
3. **New `FindingContext` builders** for LLM I/O triples, auth-outcome sequences, honeypot hits — note the existing `eval_control`/`eval_observed`/`marker`/`baseline`/`*_latencies` fields (`adapter.py:139-169`) already carry most of what class 1 needs, so the delta is genuinely small.
4. **New infrastructure with no CRUCIBLE analogue:** (a) the **inbound embeddable API/SDK + ingest boundary** — CRUCIBLE has no inbound API; (b) a **continuous online loop** with actor-graph **windowing/eviction** + spine **retention/rollup** (CRUCIBLE is batch-per-engagement); (c) the response-action `Tool`s (challenge/throttle/block) that *ride* the existing gate.

---

## 5. Doctrine & privacy

- **Defensive-only / correlatable / never offensive.** AEGIS protects the operator's own app and never attacks anything. The adapter is a *translator not a generator* (`adapter.py:10`) — it judges already-observed telemetry. The only acting surface (challenge/throttle/block) is opt-in `Tool`s riding `invoke_tool`; responses are stable-actor-ref, spine-logged *before* they run, never evasion, never anti-defender. Default `mode="observe"` is read-only.
- **Prove-don't-guess.** A detection enters as `GROUNDING_INTEL` ("intel:" tier — real, not proof) and reaches fact strength only via a fired oracle admitted by `firewall.admit()` (which can only demote). `belief_lcb` gives the honest "thinly-evidenced actor scores below a proven one." `decision` is never a bare boolean; a `certificate` is present iff confirmed and is offline-replayable. Inferential classes stay LEADs with a conformal band + `dismiss_token`.
- **PII-safe.** Default `retain="hashes"`: hashed/truncated identifiers (usernames, IPs), minhash shingles of free text, counts, outcome sequences. For class 1 only the **canary-match span + hashes** survive as the certificate — never raw transcripts, credentials, or IPs. Redaction reuses the X2 at-rest posture (exact/segment/suffix, never substring). No exfiltration — certificates carry hashes, not user data. Refuting/benign observations are first-class (`polarity=REFUTES`) so the system can *lower* suspicion, not only raise it.
- **Untrusted-input-safe.** The ingest boundary treats all telemetry + user content as hostile: bounded envelope sizes (reject oversized), depth-capped **strict JSON parse — no `eval`/shell/`pickle`/object-deserialization**, field caps, hidden-unicode normalization, fail-closed reject on malformed input. AEGIS's own detectors must not be injectable by the content they inspect. The parse layer is new; the redaction layer reuses X2.
- **Deterministic scoring.** `normalize → Observation → project → Beta → oracle` is a pure replayable function of the input: caller-supplied monotonic `seq`, no wallclock, no global RNG in the decision path (the `sensors/base.py` determinism clause AEGIS inherits). Same evidence → same verdict → same `certificate`.
- **Additive / default-safe / gated — `make gate` stays byte-identical.** `make gate` runs `benchmark --gate --no-incumbents` over the corpus/library (`Makefile:27`). Nothing under `aegis/` is imported by `scan`, `engage`, `benchmark`, `__main__`, or any `scanner/library_entries/` JSON, and **no existing library entry references an AEGIS `bug_class`** — so the benchmark output is unchanged. New enum members / dict rows / `known_bug_classes()` entries are **additive appends** that alter no existing class's oracle set or verdict. A test asserts the baseline benchmark JSON is byte-identical with `aegis/` present, and that `oracles_for(bug_class)` is identical before/after for every pre-existing class. (The MVP-proposal's idempotent-registrar mechanism is **not needed** — verified unnecessary since the gate never imports AEGIS.)

---

## 6. FIRST-BUILD SLICE (the MVP to build now)

**Scope decision:** ship **class 1 — direct prompt-injection / system-prompt-exfil against the app's own LLM** — the one surface where the app controls both I/O ends, so the canary oracle yields a *confirmed, re-runnable certificate on day one.* Bundle **the class-4 honeypot tripwire** because it is near-zero-FP and nearly free (grafted from the MVP proposal). Everything else ships as a calibrated LEAD or is deferred.

### Package layout — `framework/v2/aegis/`
```
framework/v2/aegis/
  __init__.py          # public API: Aegis facade (from_config, observe, llm_turn, next_seq), Verdict, Surface
  models.py            # Surface, ActorRef, LLMInteraction, TelemetryEnvelope, Verdict, CertRef, AegisConfig
                       #   (pydantic, extra="forbid"; attack_class validated against known_bug_classes())
  boundary.py          # ingest: size/depth caps, strict safe parse, PII redaction, shingle/hash free text
  sensors.py           # LLMInteractionSensor + RequestTelemetrySensor  (implement sensors.base.Sensor)
  actor_graph.py       # per-actor Beta belief via intel.project.project_observation + windowing/eviction
  oracles.py           # prompt_injection_oracle, honeypot_hit_oracle  (PURE; no wallclock/rng)
  adapter.py           # FindingContext builders for LLM I/O tuples + honeypot hits
  pipeline.py          # detect(): boundary → sensors → project → fuse(SCE) → confirm → admit → assess → Verdict
  guard.py             # LLMGuard: mint_canary, plant sentinel, inspect(); honeypot link seeding
  middleware.py        # AegisMiddleware (WSGI/ASGI shims) + HTTP POST /aegis/detect boundary
  registry.py          # additive: OracleKind members, BUG_CLASS_ORACLES rows, known_bug_classes() entries,
                       #   IntelSourceKind members, _ALTERNATIVES/_CONFIRMATION_LR rows
  tests/
    test_prompt_injection_oracle.py
    test_honeypot_oracle.py
    test_boundary_untrusted_input.py
    test_determinism.py
    test_verdict_never_hallucinates_class.py
    test_certificate_reverifies_offline.py
    test_default_observe_is_read_only.py
    test_gate_byte_identical.py
```

### What it detects end-to-end
1. App registers `system_prompt_id="sp_v7"` with planted canary `cx_9f` once (out of band). At each chatbot turn it wraps the call via `aegis.llm_turn(actor, system_prompt_id, canary_ids=["cx_9f"])`.
2. `boundary.py` redacts PII and caps size; `LLMInteractionSensor.normalize()` mints `Observation`s (source_kind `llm_interaction`): a structural-override marker (imperative-override / role-token / delimiter-breakout regex, `source_reliability` C-3) → an immediate **LEAD**; and, when the model output contains the canary span, a high-confidence observation.
3. `project_observation` upserts the actor's Beta belief (`intel/project.py:35`).
4. `pipeline.detect` builds a `FindingContext` (reusing `marker`, `eval_control`/`eval_observed` at `adapter.py:139-169`) and calls the *unchanged* `OracleVerifier.confirm` with `bug_class="prompt_injection"` → **`prompt_injection_oracle` fires only when** the canary/boundary span appears verbatim in the output **OR** an injected directive provably changed a structurally-detectable behavior (tool selected, refusal flipped, boundary token echoed) vs. a control turn that omits the user directive. Exact substring / behavior-delta over retained I/O = re-runnable.
5. On fire → `admit()` demote-or-abstain → `assess_finding` posterior vs. `("benign-edge-prompt", …)` → **`Verdict(decision="confirmed", attack_class="prompt_injection", certificate=<reverify cert>, provenance="grounded:…")`**. Lifecycle `tool_result` + `finding` events hit the signed spine; operator confirm/dismiss → `credit_outcome`.
6. Structural-markers-without-canary-or-behavior-change stay **`decision="lead"`** with a conformal band + `dismiss_token`. Correct by construction.
7. **Honeypot tripwire:** `guard.py` seeds an invisible, robots-disallowed link no human UI renders; the middleware watches its path; any fetch → `honeypot_hit_oracle` set-membership → `decision="confirmed"` (`automated_scraping`). The request either exists in the retained log or not.

### New oracles / signals
- `prompt_injection_oracle` — canary substring + control-vs-treatment behavior change (structurally `evaluation_oracle`, `oracles.py:840`).
- `honeypot_hit_oracle` — deterministic set-membership over retained request paths.
- LEAD signals: structural-override markers (regex, weighted, noisy-OR per `socialdefense/detectors.py`).

### Gating / off the gate path
- Default `mode="observe"` = read-only; no `Tool` runs. Any response requires the `aegis.respond` entitlement and rides `invoke_tool` fail-closed; a tripped kill-switch halts all AEGIS response.
- Nothing under `aegis/` is imported by `scan`/`engage`/`benchmark`/`__main__`. Registry additions are additive appends. Optional `aegis` CLI subcommand in `_DISPATCH` (`__main__.py:188`) is safe — the gate never invokes it.

### Test plan (the doctrine is the test suite)
- `test_prompt_injection_oracle.py` — canary-in-output ⇒ CONFIRMED + cert; markers-only ⇒ LEAD; benign edge prompt quoting "ignore the above" with canary absent + behavior unchanged ⇒ the FP twin does not confirm; control-not-clean ⇒ ABSTAIN. Pure, deterministic.
- `test_honeypot_oracle.py` — seeded path fetched ⇒ CONFIRMED automated; any other path ⇒ no fire.
- `test_boundary_untrusted_input.py` — oversized/deeply-nested/hidden-unicode/`__proto__`-style envelope ⇒ fail-closed reject, never `eval`'d; PII fields hashed; no raw transcript retained under `retain="hashes"`.
- `test_determinism.py` — same envelope + `seq` twice ⇒ byte-identical Verdict and identical `certificate` id; reordering observations in a batch collapses idempotently (belief never inflates).
- `test_verdict_never_hallucinates_class.py` — a Verdict with an OOV `attack_class` fails pydantic parse (`require_known_bug_class`).
- `test_certificate_reverifies_offline.py` — every `confirmed` verdict's `certificate` re-verifies via `reverify_context` with `verifier=None` (no app).
- `test_default_observe_is_read_only.py` — `mode="observe"` performs zero writes and never invokes a response `Tool`; response `Tool`s refuse without `aegis.respond` (fail-closed); a fabricated actor not in the world-model ⇒ `admit()` returns UNGROUNDED.
- `test_gate_byte_identical.py` — baseline `benchmark --gate --no-incumbents` output unchanged with `aegis/` present; `known_bug_classes()` grew by exactly the AEGIS classes; `oracles_for(bug_class)` identical before/after for every pre-existing class.

---

## 7. Roadmap (slices after the MVP)

Ordered by value-per-effort, each riding the same pipeline and adding at most one sensor + one oracle:

1. **Class 3 — AI credential-stuffing / ATO** (highest value-per-effort; the stats already exist). `AuthTelemetrySensor` + `credential_stuffing_oracle` = pure assembly of `boolean_inference_oracle` (SPRT, `oracles.py:471`) over unseen-`(account,source)` successes + `holm_correction` (`oracles.py:548`) for the multi-identity family-wise control. MECE alternative `nat-cgnat-bulk` keeps failed-only NAT bursts as LEADs.
2. **Class 2 — indirect / stored injection (RAG poisoning).** `ContentSubmissionSensor` flags hidden-char (deterministic present/absent) + imperative-to-future-model markers at write-time as an ingest LEAD; when the tagged artifact is later retrieved into a prompt and the class-1 oracle fires, the two events are **hash-linked on the signed spine** → confirmed end-to-end.
3. **Class 4 (behavioral rest) — agentic scraping.** Add navigation-graph anomaly + JA4↔UA contradiction as LEADs (`timing_oracle` for cadence); the honeypot oracle already anchors the CONFIRMED case from the MVP.
4. **Class 8 — model extraction** (if the app exposes an ML endpoint). `ModelQuerySensor` + `model_extraction_oracle`: distinct-query-count + near-boundary-concentration threshold over retained query metadata (a `BOOLEAN_INFERENCE`-style oracle). Evasion / membership-inference ship as LEADs.
5. **Class 6 — phishing / spam / fake reviews** (UGC apps). Reuse `socialdefense` intent indicators + deterministic IDN-homoglyph lookalike + minhash cross-submission dedup; "AI-generated" attribution stays a LEAD by design.
6. **Class 9 — synthetic identity** (KYC verticals). Signup-burst velocity + disposable-domain set-membership + template dedup promote deterministically; deepfake media stays explicitly out of lane.
7. **Continuous-loop hardening** — actor-graph windowing/eviction policy and spine retention/rollup for sustained production volume (CRUCIBLE is batch-per-engagement; this is the one genuinely new operational concern), plus the response-action `Tool`s (challenge/throttle/block) for operators who opt into `enforce` mode.

Classes 7 (human-mimic bots), evasion, and membership-inference remain **LEAD-only, permanently** — shipping them as verdicts would be the exact "AI detects AI" hype the doctrine forbids, and saying so is the product.

---

**One-line summary:** AEGIS = one inbound SDK/ingest boundary + a per-actor Beta-belief fusion graph + ~4 new oracle bodies, reusing unchanged the verifier/adapter/`reverify_context` certificate pipeline, the `veracity.admit()` only-demotes firewall, the Sensor→Observation→`project_observation` keystone, the signed spine, the SCE calibrated posterior, the reward/calibration loop, and the fail-closed `invoke_tool` gate — the prove-don't-guess core pointed inward, shipping re-runnable certificates where an oracle exists (own-LLM injection first, then credential-stuffing, RAG, model-extraction) and honest calibrated leads everywhere else, additive and byte-identical to `make gate`.