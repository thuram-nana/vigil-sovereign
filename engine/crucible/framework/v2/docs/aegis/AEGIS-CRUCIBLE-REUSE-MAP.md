I have grounded the full reuse map in the actual code. Here is the architecture output.

---

# AEGIS ⟵ CRUCIBLE: Concrete Crown-Jewel Reuse Map

Every claim below cites a real file under `/home/kali/Pictures/PENTEST-main/framework/v2`. The governing principle: **AEGIS is the same prove-don't-guess reasoning core pointed inward at the operator's own app.** A detection is a provenance-tagged *signal*; it is a *confirmed AI attack* only when a deterministic oracle re-fires over retained, re-runnable evidence — the identical contract `verify/reverify.py` already enforces for offensive findings.

---

## 1. The prove-don't-guess oracle layer — REUSE THE PATTERN, ADD KINDS

**Files:** `verify/oracles.py`, `verify/verifier.py`, `verify/models.py`, `verify/adapter.py`, `verify/reverify.py`

**What is reused verbatim:**
- **`OracleSignal` / `VerificationResult`** (`verify/models.py:86,110`) and the **`OracleVerifier.confirm`** dispatch (`verify/verifier.py:237`) — the "no oracle, no confirmation; an absent input yields a non-firing signal, never an assumed pass" gate. AEGIS confirmations flow through the *same* verifier.
- **`FindingContext` + `to_verifier_context()`** (`verify/adapter.py:122,461`) — the typed, JSON-serialisable carrier of *already-observed* evidence. This is exactly what an AEGIS detection needs: the SDK collects request/LLM telemetry, packs it into a `FindingContext`, and the oracle judges it. The adapter is explicitly a *translator, not a generator* (`adapter.py:10`) — it never touches the target — which matches AEGIS's "ingest telemetry, never attack" doctrine.
- **`reverify_context` / `reverify_finding`** (`verify/reverify.py:95,187`) — every AEGIS detection ships a certificate that anyone can re-run offline with no app and no trust in AEGIS. The memoization cache just added on this branch (`reverify.py:77`, `_REVERIFY_CACHE_MAX`) applies unchanged.
- **Several existing oracles fire on AEGIS inputs with zero modification:**
  - `boolean_inference_oracle` (SPRT, `oracles.py:471`), `timing_oracle` (Mann-Whitney U + Hodges-Lehmann + dose-response, `oracles.py:363`), and `holm_correction` (`oracles.py:548`) are *exactly* the statistics needed to separate **machine-speed adaptive attacks (AI credential-stuffing, agentic probing) from jitter/noise** across many requests. This is the single biggest "already built" win — the hard math for behavioral/timing bot detection is done.
  - `reflection_context_oracle` (`oracles.py:781`) and `evaluation_oracle` (`oracles.py:840`) already prove "an injected string reached an *executable* position / was *evaluated* rather than merely reflected." That control-vs-treatment discipline is the template for the new prompt-injection oracle (see §9).

**The seam AEGIS plugs into:** the `BUG_CLASS_ORACLES` table + `known_bug_classes()` value-membership (`verify/verifier.py:33,186`). AEGIS registers **new `OracleKind` members** (`verify/models.py:31`) and **new `bug_class → oracle` rows**, and — critically — extends `known_bug_classes()` so an AI-attack class asserted as oracle-provable can't be a hallucinated label. `require_known_bug_class` (`verifier.py:205`) already rejects out-of-vocabulary classes at pydantic parse time.

**NEW:** the AI-attack `OracleKind` values, the `BUG_CLASS_ORACLES` entries, the new `FindingContext` fields/builders, and the new oracle *bodies* (§9).

---

## 2. The unified world-model — REUSE VERBATIM (beliefs + grounding tiers)

**File:** `worldmodel/models.py`

- **Beta-belief accumulation** (`Node.alpha/beta`, `belief_mean`, `belief_lcb`, `models.py:203-236`) is how AEGIS accumulates evidence about a *suspected AI actor* (an IP, session, or identity) across many requests: each corroborating signal raises `belief_mean`; a refuting observation (a provably-human interaction) lowers it — the thing a scalar "risk score" structurally cannot express. `belief_lcb` gives the honest "thinly-evidenced actor scores below a proven one."
- **Provenance grounding tiers** (`classify_provenance`, `GROUNDING_INTEL` vs `GROUNDING_GROUNDED`, `models.py:159-181`) *are* AEGIS's signal→confirmed pipeline: a detection enters as `intel:` (real, not proof), and only a fired oracle / signed cert promotes it to `grounded:`. This is the single source of truth the veracity firewall reuses.
- Existing kinds that map directly: `SESSION`, `PRINCIPAL`, `IDENTITY` (OSINT persona), `INDICATOR` (IOC), `CONTROL` (a defensive control), and edges `REACHED`, `AUTHENTICATES_TO`, `CONTROL_PROTECTS`, `OBSERVED_ON` (`models.py:48-143`).

**NEW:** a small set of node/edge kinds for the *external-actor* view — e.g. an `ACTOR`/attacker-session node and `ISSUED`/`TARGETS`/`EXHIBITS` edges (attacker → request → app-surface). Some can reuse `SESSION`+`INDICATOR`; a couple are genuinely new enum members. Also NEW: a **windowing/eviction policy** for a *continuously-running* actor graph (CRUCIBLE's graph is engagement-batch; AEGIS is a live stream).

---

## 3. The veracity firewall — REUSE VERBATIM (the only-demotes choke point)

**File:** `veracity/firewall.py` — `admit()` (`firewall.py:105`)

This is AEGIS's anti-hallucination guarantee, for free. Every "this was an AI attack" claim is constructed as a `Claim` and passed through `admit()`, which **re-executes** each cited ground *bound to the claim's own bug_class* (`_oracle_ok` calls `reverify_context`, `firewall.py:50-63`) and **can only demote or abstain** (`firewall.py:15-19`). A fabricated actor not in the world-model → `UNGROUNDED` (`firewall.py:123`); a dry-run/LLM-only detection → cannot reach fact strength (`firewall.py:154`). AEGIS reuses this unchanged; it only builds `Claim`s.

**NEW:** nothing in the firewall. AEGIS supplies `Claim`/`GroundingToken` objects (existing `veracity/claims.py`, `veracity/tokens.py`).

---

## 4. Intel Observation + projection + the Sensor framework — REUSE VERBATIM (universal producer)

**Files:** `sensors/base.py`, `intel/models.py`, `intel/project.py`

The **Sensor protocol** (`sensors/base.py:37`) *is* the AEGIS ingestion abstraction. `sensors/base.py:1-21` states it: a Sensor is a gated `Tool` plus a `normalize(result) → list[Observation]` step, minting **observations, never facts**, entering the graph as `GROUNDING_INTEL` and becoming a FACT only if an oracle re-verifies (`base.py:13-16`). That is a verbatim statement of AEGIS doctrine.

- `Observation` (`intel/models.py:90`) with Admiralty source-reliability, `polarity` (a *refuting* observation — a provably-human signal — drives belief DOWN, `models.py:118`), and monotonic `seq` (no wallclock).
- `project_observation` (`intel/project.py:35`) — THE KEYSTONE: streaming Path A projects telemetry onto the world-model and gets corroboration/refutation/provenance for free via the Beta upsert. Order-independent and deterministic (`project.py:35-43`).
- `observation_to_evidence` (`intel/project.py:85`) bridges an Observation into a `confidence.Evidence` for the SCE (§6).

**NEW:** concrete AEGIS sensors implementing the protocol — `RequestTelemetrySensor`, `LLMInteractionSensor`, `ContentSubmissionSensor` — plus new `IntelSourceKind` members (`intel/models.py:39`: add `request_telemetry`, `llm_interaction`, `content_submission`). The **shared minter pattern** in `service_observations` (`sensors/base.py:67`) is the template for a shared actor/request minter.

---

## 5. The signed event spine — REUSE VERBATIM (tamper-evident audit of every determination)

**Files:** `agents/blackboard.py`, `agents/spine_chain.py`, `agents/models.py`, `agents/spine_sink.py`

AEGIS emits every detection-lifecycle event onto the append-only, hash-linked, governance-signed spine — exactly what a defensive product needs for a defensible audit trail. The existing `EventKind` vocabulary already covers AEGIS's needs (`agents/models.py:29-46`): `tool_call`/`tool_result` (a gated sensor ran — "a PROVENANCE-labelled observation, not a fact"), `finding` (a confirmed detection), `refusal` (a gate fired — "refusals are evidence"), `reward` (a learning signal), `critic_verdict`, `reflection`. `spine_chain.py` gives content+order tamper-evidence with the "no wallclock in digests" discipline (`spine_chain.py:1-19`), reused verbatim.

**NEW:** minimal. AEGIS writes through the duck-typed `SpineSink`. The one genuinely new concern is **spine volume/retention under continuous production** (CRUCIBLE assumes bounded engagements) — the X3 paging/cursor work in `blackboard.replay` (`spine_chain.py:_events` pages to exhaustion) mitigates but a retention/rollup policy is new.

---

## 6. Scientific Confidence Engine — REUSE (calibrated posterior with competing benign explanations)

**File:** `confidence/decision.py` — `assess_finding` (`decision.py:63`)

This is how AEGIS avoids false positives: a confirmed detection is weighed against **the specific benign explanation that masquerades as it** — a fast human vs a bot, a legit edge-case prompt vs a jailbreak — as a real MECE competitor (`decision.py:44-54,92-107`). The oracle stays the authority; SCE expresses *how confident* (`decision.py:12-16`). Output: "posterior 0.994, top alternative 0.004."

**NEW:** entries in `_ALTERNATIVES` and `_CONFIRMATION_LR` (`decision.py:33-53`) for AI-attack classes (e.g. `behavioral_evasion_bot → ("fast-human", …)`, `prompt_injection → ("benign-edge-prompt", …)`).

---

## 7. Calibration / reward bus — REUSE VERBATIM (AEGIS learns which detectors are productive)

**File:** `calibration/reward_bus.py` — `credit_outcome` (`reward_bus.py:52`)

When an operator confirms or dismisses a detection (the ground-truth label), `credit_outcome` fans that outcome to the bandit (orders detector effort), the calibration ledger (keeps confidence honest over time), and cross-engagement priors — best-effort, each sink independent (`reward_bus.py:72-80`). This is AEGIS's online learning loop, reused as-is; it emits a `reward` event to the same spine sink.

**NEW:** nothing structural — AEGIS supplies the `bug_class`/`surface_pattern`/`spine_sink` arguments and an operator feedback channel.

---

## 8. Fail-closed gate chain — REUSE VERBATIM (keeps AEGIS default-safe & non-offensive)

**Files:** `agents/tools/invoker.py`, `agents/tools/base.py`, `authority/`, `entitlement/`, `agents/scope_gate.py`, `agents/egress_guard.py`

AEGIS's **active responses** (challenge, throttle, alert, block) are the only part that acts, and each is a `Tool` run through `invoke_tool` (`invoker.py:143`): kill-switch → entitlement → scope → destructive-confirm → egress (`invoker.py:80-140`), every gate fail-closed, every call recorded on the spine before it runs (`invoker.py:160-171`). This is what makes AEGIS **DEFAULT-SAFE and gated**: passive detection is read-only and off this path; any response is opt-in, entitlement-gated, and a tripped kill-switch halts all AEGIS response. Its "correlatable, not anti-defender" posture is inherited by construction.

**NEW:** the response-action `Tool` implementations themselves (they *ride* the existing gate; they don't modify it).

---

## 9. What is genuinely NEW (must be built)

**A. New oracle bodies** (in an `aegis/oracles.py`, same purity contract as `verify/oracles.py`):
1. **`prompt_injection_oracle`** — over retained LLM prompt/response/control triples, fire only when an injected directive *provably altered* the model's output vs a control that omits it. Structurally the `evaluation_oracle` pattern (`oracles.py:840`): effect present + control clean + not merely reflected. Covers direct *and* indirect (content-borne) injection against the app's own chatbot/RAG.
2. **`behavioral_bot_oracle`** — over retained inter-request timing / navigation traces, reuse the **existing** `_mann_whitney`/`_hodges_lehmann`/SPRT machinery (`oracles.py:328-545`) to fire on machine-generated regularity beyond a floor. Mostly assembly of existing statistics.
3. **`credential_stuffing_oracle`** — over retained auth-attempt telemetry, deterministic signature of distributed low-per-identity machine-speed attempts; reuse `holm_correction` (`oracles.py:548`) for the multi-identity family-wise control.
4. **Adversarial-ML oracles** (`model_extraction`, `membership_inference`, `synthetic_content`) — genuinely new deterministic checks over retained query distributions; no existing analogue.

**B. New vocabulary/models** (extensions, not rewrites):
- New `OracleKind` members (`verify/models.py:31`) + `BUG_CLASS_ORACLES` rows + `known_bug_classes()` entries (`verify/verifier.py`).
- New `FindingContext` fields + builders (`verify/adapter.py`) for LLM I/O, timing traces, auth telemetry.
- New `IntelSourceKind` members (`intel/models.py:39`); a few new `NodeKind`/`EdgeKind` for the external-actor view (`worldmodel/models.py`).
- New `_ALTERNATIVES`/`_CONFIRMATION_LR` rows (`confidence/decision.py`).

**C. New infrastructure** (no CRUCIBLE analogue):
- **The embeddable API/SDK surface** — an *inbound* ingestion endpoint + client library a third-party app integrates. CRUCIBLE has no inbound API; this is the core new artifact. Must enforce **bounded sizes + safe parsing (no eval/shell) + PII redaction** at the boundary (partially reuses X2 at-rest redaction, but the untrusted-input parse layer is new).
- **The `framework/v2/aegis/` package** — additive, OFF the default scan/engage/gate path so `make gate` stays byte-identical (the doctrine every prior wave held).
- **A continuous online detection loop** with actor-graph windowing/eviction and spine retention/rollup (CRUCIBLE is batch-per-engagement).
- **Response-action `Tool`s** (challenge/throttle/block) registered in a `ToolRegistry`.

---

## One-line summary

AEGIS builds **~4 new oracle bodies + one inbound API/SDK + a continuous loop**, and reuses everything load-bearing unchanged: the **verifier/adapter/reverify certificate pipeline** (`verify/`), the **veracity `admit()` only-demotes firewall** (`veracity/firewall.py`), the **Sensor→Observation→`project_observation` producer keystone** (`sensors/base.py`,`intel/project.py`) with **Beta-belief actor scoring** (`worldmodel/models.py`), the **signed event spine** (`agents/blackboard.py`,`spine_chain.py`), the **SCE calibrated-posterior gate** (`confidence/decision.py`), the **reward/calibration loop** (`calibration/reward_bus.py`), and the **fail-closed `invoke_tool` gate chain** (`agents/tools/invoker.py`) that keeps every AEGIS response opt-in, gated, and non-offensive.