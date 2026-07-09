# CRUCIBLE — the AI's guide to the system, its agents, and its spine

This is the reasoning agent's map of CRUCIBLE: what the system is, the agents that run it, the
one immutable event stream they share, the anti-hallucination layer that makes claims
trustworthy, the learning/metacognition core that makes it improve honestly, and the safety
stack that keeps it inside its authorization. It is written to match the **shipped** code — where
a mechanism is a primitive not yet wired into a live loop, it says so. For the design rationale
see [ARCHITECTURE.md](./ARCHITECTURE.md); for operating it see [OPERATOR-GUIDE.md](./OPERATOR-GUIDE.md);
the binding constitution is [/CLAUDE.md](../../../CLAUDE.md); the runtime doctrine injected into
every LLM call is [/framework/cognitive/metacognition.md](../../../framework/cognitive/metacognition.md).

---

## 0. The one rule

> A finding is `confirmed` for exactly one reason: a **deterministic oracle fired** at or above
> threshold over data a **real target actually produced** (`verify/verifier.py`). The LLM
> proposes; the oracle disposes.

Every other subsystem is subordinate to this. Any AI addition — critics, reinforcement learning,
reflection, self-consistency — may only **advise, re-rank, defer, or abstain**. None may promote
a claim the oracle refused, and none may silently skip an authorized attack surface.

---

## 1. Two execution paths, one spine

- **Flagship engage/scan** (`engage.py`, `scanner/`): crawl → audit insertion points → confirm
  via oracles → chain attack paths → score confidence. Synchronous, best-effort at every
  value-add stage (a failure never sinks the run).
- **Multi-agent orchestration (MAO)** (`agents/coordinator.py` over `agents/blackboard.py`):
  specialist agents (recon, hypothesis, exploit, critique, reporter, memory) post typed events;
  the coordinator schedules them and refuses to quiesce while findings are unreviewed.

Historically these were separate worlds. The **event spine** unifies them: `engage` can mirror
its whole run onto the blackboard (`run_engagement(spine=…)` / `--spine`), so one immutable,
replayable stream carries the entire engagement.

---

## 2. The event spine (`agents/blackboard.py`)

The blackboard is an **append-only, typed, provenance-linked, seq-clocked** SQLite event log —
the single stream every subsystem communicates through.

- **Kinds** (`agents/models.py`, each with a validated payload): `observation`, `hypothesis`,
  `plan`, `action`, `result`, `finding`, `critique`, `decision`, and the nervous-system kinds
  `reward`, `critic_verdict`, `reflection`, `refusal`. A `critic_verdict` is `endorse|object|
  abstain` — it **cannot** say "confirm" (oracle authority at the type level).
- **Write path**: only `post()` (and `supersede()` — edits are new rows referencing the old).
  SQL triggers refuse UPDATE/DELETE.
- **Read/replay**: `read(...)` and `replay(engagement, since_id=…)` — a durable cursor a
  consumer polls for new events.
- **Bridge**: `agents/spine_sink.py::SpineSink` implements the scanner's `ProgressSink` Protocol
  (real-time phases/findings → observation events) plus typed helpers (`finding_event`,
  `refusal`, `reward`, `decision`, `reflection`, `critic_verdict`). Best-effort — a spine write
  can never perturb a run.
- **Cryptographic tamper-evidence**: `agents/spine_chain.py` hash-links the events and anchors
  them with a governance-signed head (reusing `evidence/chain.py`). `verify_spine_head` rebuilds
  the chain from the live log and fails on any altered/reordered/deleted/appended-after-signing
  event; it pages the full log and fails **closed** on a truncated read, and binds the head to
  its engagement (no cross-engagement replay). Purely additive; no schema change.

---

## 3. The anti-hallucination (veracity) layer — P0–P7

The one place grounding was enforced (scanner promotion) is now universal and unforgeable.
**No claim becomes a fact unless a cited grounding token RE-EXECUTES** — the oracle re-fires, a
signed cert re-verifies, a belief traces to proof, or it is a gated, capped hypothesis. The
layer only ever **demotes or abstains**.

- **P0/P1 — `veracity/`**: `firewall.admit()` re-executes each cited ground *bound to the claim's
  subject* (a SQLi proof cannot ground an RCE claim). `critique_agent` reserves `confirmed` for a
  fired oracle; an LLM-only verdict is `llm_advisory`.
- **P2 — world-model admission**: every `worldmodel` write is tagged with a provenance grounding
  tier; belief is byte-identical by default.
- **P3 — live over findings**: `veracity/adapters.py::admit_finding` runs the firewall over real
  findings in the engage loop; a finding whose proof no longer reproduces is demoted.
- **P4 — reporting gate**: report sentences bound into the `EvidenceCertificate`
  (`evidence/`) so `verify_certificate`/`verify_bundle` fail closed when a report sentence has no
  backing evidence; the reporter re-executes each finding's oracle at report time; the scanner
  export states each finding's live grounding; attack paths become fail-closed, head-anchored
  path certificates. (A deterministic gate certifies the *structured* claim + tamper-evidence; it
  does **not** do natural-language entailment — that boundary is stated honestly.)
- **P5 — kernel self-consistency** (`kernel/consistency.py`): N-sample agreement + semantic
  entropy → ABSTAIN, on **no-oracle bindings only**; the entropy is a confidence *penalty*, never
  a boost, and never enters the oracle path.
- **P6 — value-membership** (`verify/verifier.py`): an out-of-vocabulary `bug_class` is caught at
  parse time; a hypothesis carries `oracle_provable`.
- **P7 — conformal coverage** (`calibration/conformal.py`): coverage bands gated on MIN_LABELS,
  falling back honestly (never a false coverage guarantee).

---

## 4. The learning / metacognition core — N0–N6 ("nervous system")

Additive, default-safe, deterministic, oracle-respecting.

- **Reward + credit** (`calibration/reward_bus.py`, `agents/spine_credit.py`): `outcome_label`
  single-sources the **non-circular** label (EXPLOITABLE only on ≥2 corroborating oracle kinds).
  `credit_outcome` fans one outcome to the bandit (check productivity), the calibration ledger
  (non-circular label), memory priors, and a spine `reward` event. `credit_finding_path` walks
  the provenance DAG crediting the decisions/hypotheses that led to a confirmed finding.
- **Multi-critic panel** (`agents/critics.py`): differentiated deterministic critics
  (grounding / provenance / calibration); `aggregate_panel` — a major objection stands, high
  disagreement → abstain, else the modal — **never** "confirm". `panel_verdict_for` is the quorum
  gate; `MultiCriticAgent` is addable to the coordinator.
- **Reflection + cognitive refusal** (`agents/reflection.py`, `agents/cognitive_refusal.py`):
  `reflect` detects dead threads and stalls and posts re-orienting `reflection` events
  (re-rank/defer, never skip a surface); `epistemic_refusal` refuses to *conclude* a finding that
  will not re-ground, recording a `refusal` event.
- **Governance in the prompt** (`kernel/binding.py`, `framework/cognitive/metacognition.md`): the
  metacognition/oracle-authority/critic/refusal/self-consistency/learning doctrine is quoted
  verbatim into **every** LLM system prompt, bounded and cache-stable.
- **Learning about learning** (`calibration/meta_monitor.py`): `assess_learner_health` reports
  label count, ECE, Brier, and realized conformal coverage, and recommends *only more caution*
  (gather evidence / trust confidence less) — never gates. `BanditPolicyProvider` + `rank_by_policy`
  generalize the bandit's learned value to order (never drop) any decision.

The RL substrate is the existing Thompson bandit (`scanner/learning.py`) + outcome ledger + PAV
calibrator + conformal bands (`calibration/`) + memory priors — the reward bus reuses them; it
does not add a second learner. **The bandit ORDERS effort; it never gates.**

**Wiring status (honest — a primitive is not a live loop).** What is live in the default flagship
`engage --spine` loop today: the spine mirror of findings/refusals, a per-finding spine `reward`
event, and the veracity firewall over findings (P3). What are additive **primitives / schedulable
agents you opt into** — not run in the default `engage` loop: `credit_outcome` (the full
bandit+ledger+priors fan-out), `credit_finding_path` (DAG credit), the `MultiCriticAgent` panel,
the `ReflectionAgent`, `epistemic_refusal`, and `meta_monitor` are called by their tests and are
addable to the MAO coordinator / invoked by a caller; they are the building blocks, wired in as
the operator adopts them. The doctrine they encode is already live in every reasoning call via
the governance preamble (§4, `metacognition.md`).

---

## 5. The safety stack (fail-closed, inviolable)

Every target-touching action passes, in order: charter/scope (`agents/scope_gate.py`), the
per-action kill-switch re-read (`authority/killswitch.py`), the egress allowlist, sovereignty
tier (`kernel/sovereignty.py` — air-gapped fails closed, cloud backends are never even imported
in strict tiers), and capability entitlement for exploitation (`entitlement/`). These RAISE and
propagate — the coordinator re-raises `CrucibleError`; nothing swallows a refusal. Self-
improvement (`improve/`) is **authorise-not-apply**: it never self-mutates offensive code.

**Declined by design:** capability to evade detection, rotate identities, or stay hidden from
defenders. CRUCIBLE is deliberately correlatable and authorized (constitution §VI). The
constructive alternative is purple-team detection-efficacy, never anti-defender tradecraft.

---

## 6. Structured workflows (`python3 -m framework.v2 <subcommand>`)

| Goal | Command |
|------|---------|
| Authorized end-to-end engagement | `engage <slug> <seed-url> [--recon] [--spine]` |
| Loopback quick scan (grounded export) | `scan http://127.0.0.1:<port>/ --format json\|sarif\|html [--strict-evidence]` |
| Re-verify a report offline | `verify <report.json>` |
| Build / verify signed evidence | `evidence …` |
| OSINT into the shared world-model | `intel …` |
| Cross-engagement memory / priors | `memory …` |
| Authorise (not apply) a self-improvement | `improve …` |
| Read-only operator console (loopback) | `console` |
| Status / kill-switch / authority | `status`, `authority …` |

Run any subcommand with `--help` for its flags. Full dispatch table: `framework/v2/__main__.py`.

---

## 7. When you extend CRUCIBLE

- Keep it **additive + default-safe**: a new sink/flag OFF must leave `engage`/`scan` byte-identical.
- Preserve **oracle authority**: your addition advises/re-ranks/abstains — it never promotes.
- Keep it **deterministic**: caller-supplied seq, injected rng; no wallclock/global-rng in
  learning/reward/spine math (it breaks replay + the calibration audit).
- **Never over-claim** what the deterministic layer enforces — a doc/field/guarantee that
  promises more than the code verifies (NL entailment, causal hop-linkage, coverage from sparse
  data) is itself a hallucination. State the boundary.
- Any full-set read of the append-only spine must **page** (the default read limit truncates) and
  fail **closed** on an incomplete read.
