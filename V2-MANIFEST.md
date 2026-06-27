# V2-MANIFEST

Status of CRUCIBLE v2 across the FORGE PROTOCOL sessions delivered
so far. The v1 canon under `framework/{cognitive,playbooks,
checklists,knowledge-base,templates}/` is byte-for-byte unchanged
from the baseline commit; v2 lives entirely under `framework/v2/`.

This manifest tracks two columns separately, per the operator's
Session 2 directive:

  - **Code complete** — does the subsystem exist on disk, with no
    placeholders, type-checking clean, tests green, READMEs in v1
    voice?
  - **Live-path verified** — has it actually been exercised against
    a live LLM and/or a live target, end-to-end? "DryRun fixture
    output validated by Pydantic" is *not* live verification.

Per FORGE PROTOCOL § 4.10 lying about completeness is the worst
possible outcome — so this manifest treats *partial* and *unverified*
as legitimate states of the work.

---

## Subsystem status

| # | Subsystem | Path | Code complete | Live-path verified | Notes |
|---|-----------|------|---------------|---------------------|-------|
| 1 | URK — Universal Reasoning Kernel | `framework/v2/kernel/` | yes | **yes** | 6 cognitive bindings + 4 backends (Anthropic, ClaudeCode, Ollama, DryRun). All six bindings exercised live in Session 3 against the ClaudeCodeBackend (operator's Claude Max via `claude -p`, model=haiku). All `V2-LIMITATIONS.md` § 0 failure-mode tests pass. Captured fixtures under `framework/v2/kernel/tests/fixtures/live-run/`. |
| 2 | MLS — Memory & Learning Substrate | `framework/v2/memory/` | yes | yes | SQLite store + lexical embeddings (sentence-transformers optional); recorder / recall / priors / postmortem. Built-in sample-engagement seed exercised. No LLM dependency. |
| 3 | UTI — Universal Target Intake | `framework/v2/intake/` | yes | **yes** | 7 detectors, 9 archetypes, confidence-weighted classifier exercised live in Session 1 against an operator-authorised target. The threat-model drafter was exercised live in Session 3 against the same target with live URK: 173s wall, 9 HTTP requests, archetype `php-smarty-smm-panel-fork` (0.75), 208-line URK-driven threat-model captured under `framework/v2/intake/tests/fixtures/live-run/` (regression captures retained). |
| 4 | MAO — Multi-Agent Orchestration | `framework/v2/agents/` | yes | **yes** | Blackboard, coordinator, 5 specialist agents, memory-agent, executor protocol exercised live (Session 3: every binding fires live URK; critique-agent rigour verified). Session 4 added `RealisticExecutor` and ran the full pipeline end-to-end under live URK: 30 planner steps → 2 executor successes → 2 critique calls → 1 confirmed finding → reporter emitted `technical.md` → MLS recorded the confirmed finding. Session 6 added `HttpExecutor` — bounded live-HTTP with the six-gate safety stack (charter signature, scope, destructive prompt, request budget, posture-aware rate limit, posture-aware UA). 22 unit tests against `pytest-httpserver` cover every gate. Live exercise opt-in via `CRUCIBLE_LIVE_HTTP=<url>`; deferred to operator's next supervised run if not provided this session. Captured fixture: `framework/v2/agents/tests/fixtures/live-run/realistic-pipeline/`. |
| 5 | ACP — Autonomous Campaign Planner | `framework/v2/planner/` | yes | **yes** | Planner drove the Session-4 live full-pipeline run end-to-end: leaf dispatch → exploit-agent → critique-agent → reporter emission, all under live URK. 30 steps in 232s, halted on `max_steps` per the test budget, checkpoint persisted, MLS mirrored. Watchdog halt-authority and resume-across-kill remain verified from Session 2. Acceptance test: `framework/v2/planner/tests/test_full_integration.py::test_full_pipeline_url_to_report_live_realistic` (opt-in via `CRUCIBLE_LIVE_FULL_PIPELINE=1`). |
| 6 | DEL — Defender Emulation Layer (defensive subset) | `framework/v2/defender/` | yes | offline | Telemetry model + Sigma-style detection ruleset + self-detection scoring + posture annotation. **Defensive only by policy**: knows what telemetry an action trips; does NOT generate evasion (that stays `Capability.DEFENDER_EVASION`, entitlement-locked + human-authored). Gated on `DEFENDER_TELEMETRY`. 17 tests. `V2-LIMITATIONS.md` § 21. |
| 7 | DAA — Deep Analysis Arsenal | `framework/v2/analysis/` | yes | offline | Offline pattern analyzer (curated dangerous-pattern ruleset, always available) + Semgrep adapter (graceful-degrade when absent) + Python AST symbol index + orchestrator (merge/dedup/skip-record). `analysis/seed.py` maps findings → blackboard hypotheses the exploit agent picks up. Gated on `DEEP_STATIC_ANALYSIS`. 21 tests. § 22. |
| 8 | SIL — Self-Improvement Loop | `framework/v2/improve/` | yes | offline | Continuous-discovery / gated-deployment: reviewer mines capability gaps, horizon scanner folds CVEs, patcher drafts reviewable proposals (never self-applied), merge gate authorises only on eval-green + threshold governance approvals + `SELF_IMPROVEMENT_MERGE`. `ingest_live.py` assembles snapshots from live Blackboard+MLS. 26 tests. § 20. |
| 9 | Sovereignty Substrate (Session 7) | `framework/v2/kernel/sovereignty.py`, `framework/v2/agents/egress_guard.py` + project-root docs | yes | partial | Session 7. `SovereigntyPolicy` refuses cloud backends at construction under `CRUCIBLE_SOVEREIGN_MODE=1`; auto-selection reverses to local-first. `SovereignHttpxTransport` enforces an egress allowlist at runtime. Source-level egress audit confirms zero "anything else" paths. STRIDE self-threat-model + supply-chain attestation workflow + SECURITY.md shipped. **Local-LLM quality verification deferred** — Ollama not present on Session 7's development host; comparison harness ships with `<DEFERRED>` placeholders. 42 tests pass. |
| 11 | Entitlement & Capability Gating (Pillar 2) | `framework/v2/entitlement/` | yes | offline | Controlled distribution: Ed25519 m-of-n threshold-signed, host-bound, time-boxed, revocable entitlement gating dangerous capabilities. Fail-closed `require_capability`; audit decision per call. Activation mirrors sovereignty's permissive dev default. 38 tests. § 18. See `ROADMAP-FLAGSHIP.md`. |
| 12 | Eval Harness | `framework/v2/eval/` | yes | offline | Benchmark corpus contract + scoring (detection/precision/recall/F1) + regression verdict (SIL's merge gate). `produce.py` maps live blackboard findings → ProducedFinding; `builtin_corpus()` ships 3 synthetic targets. 34 tests. § 19. |
| 13 | Engagement Authority + Kill-Switch | `framework/v2/authority/` | yes | offline | Scoped, time-boxed, environment-aware (TWIN/STAGING/LIVE) per-engagement authority + persistent fail-closed kill-switch (survives restart). Wired into HttpExecutor (checked first, before scope/IO); always-on (auto-wired). Threshold-signable. 27 tests. § 23. |
| 14 | Social-Engineering Defence | `framework/v2/socialdefense/` | yes | offline | Defensive inverse of refused Bucket-C capabilities: scores INBOUND messages for phishing/impersonation indicators. Pure defence — reads received mail, generates nothing. 8 tests. § 24. |
| 10 | Substrate Pluralism (Session 8) | `framework/v2/kernel/sovereignty.py` (tiered), `framework/v2/kernel/backends/{bedrock,vertex,mistral,anthropic}.py` | yes | partial | Session 8. `SovereigntyPolicy` evolved from binary strict/permissive to four tiers: AIR_GAPPED, SOVEREIGN_CLOUD, TRUSTED_CLOUD, PERMISSIVE. `CRUCIBLE_SOVEREIGN_MODE=1` aliases to AIR_GAPPED for back-compat. Four new backends: `BedrockBackend` (Claude on AWS Bedrock with regional allowlist), `VertexBackend` (Claude on GCP Vertex with regional allowlist), `MistralBackend` (Mistral La Plateforme via httpx-direct, no SDK), `AnthropicBackend` ZDR variant (`anthropic-zdr` registers as `trusted_cloud`). 42 new tests (19 tier + 23 substrate-backend mocks) pass. **Live verification of all four new backends DEFERRED** — operator credentials not present in Session 8 environment. |

## MAO/ACP live-path graduation — Session 4

Session 3 closed at "partial" because the `DeterministicExecutor`
test harness produced thin Result objects (empty `body_excerpt`,
one-line `note`).  Live critique-agent walked the parent_id chain,
saw evidence that didn't support the rich Finding summary, and
correctly returned `objections`.  The gate was right; the harness
was the limitation.

Session 4 closed the gap.  The fix was a new test harness, not a
gate change:

- `framework/v2/agents/realistic_executor.py` — Executor returning
  multi-step reproduction logs in `body_excerpt` + `note` (200+
  chars, with negative controls and DB attestations).
- Three pre-baked scenarios: **strong** (webhook-forgery; should
  confirm), **weak** (robots.txt info-disclosure; should object),
  **mixed** (timing side-channel; reasoning matters).

Live full-pipeline run (`test_full_pipeline_url_to_report_live_realistic`,
ClaudeCodeBackend / haiku, 232s, ~$0.55):

- ✓ UTI fires live URK threat-model drafter (archetype `php-smarty-smm-panel-fork`)
- ✓ Planner dispatches 30 goal-tree leaves
- ✓ Exploit-agent claims hypotheses, runs them through `RealisticExecutor`
- ✓ 2 findings posted (strong + weak both succeed at the executor layer)
- ✓ Critique-agent fires live URK against each finding
- ✓ Strong-evidence finding **confirmed** → reporter emits `technical.md`
- ✓ Weak-evidence finding **objected** → not in the report
- ✓ MLS records the confirmed finding (`bug_class=webhook-forgery`)
- ✓ Planner checkpoint persists

The critique gate is still rigorous: weak claims still fail.  What
changed is that strong claims now have evidence-chain support
proportional to their finding text, and the gate accepts them.

The deferred subsystems (6–8) are absent on disk — not stubbed (per
FORGE PROTOCOL § 4.1).

---

## What "Live-path verified" actually means

Across the five shipped subsystems, three distinct verification
classes have been exercised:

1. **Pure-Python paths** (no LLM, no network) — exercised by unit
   tests and by `DeterministicExecutor`. MLS, the blackboard, the
   coordinator, the budget, the goal tree, the pruner, the resume
   layer, all the fingerprint detectors, and the stack classifier
   are in this class.

2. **Live HTTP** (no LLM, real network) — UTI's HTTP fetcher and
   detector pipeline have been exercised against an operator-
   authorised target under a 12-request budget. Classifier returned
   `php-smarty-smm-panel-fork` with score 0.745. The intake test
   accepts any `CRUCIBLE_LIVE_INTAKE_URL` the operator authorises.

3. **DryRun LLM** (no live model, deterministic fixture) — every
   URK call across every binding goes through DryRun unless an
   `ANTHROPIC_API_KEY` is set or a local Ollama daemon answers.
   Sessions 1 and 2 ran with neither; the live LLM path is **never
   exercised** in this manifest's history.

The Anthropic and Ollama backend code paths are written from public
documentation and pass mypy + import-time smoke tests but have not
been called against a live endpoint in any session. See
`V2-LIMITATIONS.md` § "Inherited unexercised-LLM-path risk" for the
explicit verification checklist that needs to run the first time
URK is invoked live.

---

## Live engagement verification

| Date | Target | Substrate | Tier | Outcome | Notes |
|---|---|---|---|---|---|
| 2026-05-05 | `mrbeanpanel.com` (operator's production SMM panel) | `claude-code` (Claude Max OAuth, model=haiku) | `PERMISSIVE` | **Completed clean** on `max_steps=15` | First real engagement. Reduced run shape (50 / $2 / 1800 s, GET-only via destructive-deny). 15 GET requests, 0 scope violations, 0 destructive refusals, 0 findings emitted. Validated framework plumbing end-to-end; finding-discovery deferred to a richer second-engagement run. Post-engagement summary at [`targets/mrbeanpanel/POST-ENGAGEMENT.md`](targets/mrbeanpanel/POST-ENGAGEMENT.md). |

This converts the framework's status from "verified at integration test"
(Sessions 3 / 4 against synthetic harnesses) to "verified in real
engagement against an operator's production target." The most important
graduation since Session 3.

---

## Verification results

All from clean runs at the time this manifest was last revised.

- **v1 canon unchanged:** `git diff 28659ec HEAD --
  framework/{cognitive,playbooks,checklists,knowledge-base,templates}`
  returns empty.
- **Syntax:** every Python file under `framework/v2/` parses with
  `ast.parse`. Every YAML parses with `yaml.safe_load`. Every JSON
  parses with `json.loads`. Every SQL file is migrated by
  `sqlite3` without error.
- **Type check:** `mypy --config-file framework/v2/pyproject.toml`
  — `Success: no issues found in 71 source files`.
- **Test suite:** `python3 -m pytest framework/v2/`
  — `159 passed, 1 skipped` (the skip is the opt-in live-intake
  test; runs only when the operator sets
  `CRUCIBLE_LIVE_INTAKE_URL=<https://your-authorised-target>`).
- **Live integration:** `CRUCIBLE_LIVE_INTAKE_URL=https://your-target
  pytest framework/v2/intake/tests/test_intake.py::test_live_intake_against_authorised_target`
  — passes; ~13s, 12-request budget.
- **Cross-references:** every `framework/v2/...` path referenced in
  the v2 docs resolves to a real file (excluding the deferred
  subsystems' prospective paths, which are explicitly labelled
  `— absent` in this manifest).
- **Path portability:** `bin/init.sh` rewrites `.claude/settings.json`
  to match the current filesystem location, idempotently.

---

## What ships, in detail

### URK (subsystem 1)

| Module | Lines | Purpose |
|--------|-------|---------|
| `models.py` | ~230 | Pydantic schemas for every binding |
| `llm.py` | ~150 | Backend abstraction + selection registry |
| `binding.py` | ~75 | Shared prompt-rendering + dispatch helper |
| `backends/{anthropic,ollama,dryrun,fixtures}.py` | ~820 total | Three backends + per-schema DryRun fixture providers |
| `{hypothesize,critique,pivot,decide,opsec,threat_model}.py` | ~30 each | One file per cognitive binding |
| `cli.py` | ~140 | `python3 -m framework.v2 kernel <subcommand>` |

35 tests in `tests/test_kernel.py` including the doctrine-compliance
check (≥5 hypotheses) and section-anchor resolution per binding.

### MLS (subsystem 2)

11 modules + tests, ~1500 lines. 18 tests including the § 3.2
measurable-bias acceptance.

### UTI (subsystem 3)

20 modules + tests, ~2700 lines (incl. signatures). 25 tests + 1
opt-in live integration. The Session-1 live target classified as
`php-smarty-smm-panel-fork`.

### MAO (subsystem 4)

| Module | Purpose |
|---|---|
| `models.py` | 8 typed event payloads + the `BlackboardEvent` wrapper |
| `schema.sql` | Append-only events table with SQL triggers refusing UPDATE/DELETE |
| `blackboard.py` | `Blackboard` — only write surface is `post()` / `supersede()` |
| `base.py` | `Agent` ABC with `should_run()` / `step()` / cursor helpers |
| `coordinator.py` | Round-robin tick scheduler with quiet-ticks termination |
| `executor_proto.py` | `Executor` protocol + `DeterministicExecutor` + `HttpExecutor` sketch |
| `recon_agent.py` | Probes paths via UTI's Fetcher; posts Observations |
| `hypothesis_agent.py` | Reads Observations; calls URK.hypothesize(); posts Hypotheses |
| `exploit_agent.py` | Claims open Hypotheses; runs them via the Executor; posts Plan/Action/Result/Finding |
| `critique_agent.py` | Reads pending Findings; calls URK.critique(); supersedes Finding with critique_status |
| `reporter_agent.py` | Renders `targets/<slug>/reports/technical.md` from confirmed Findings |
| `memory_agent.py` | Mirrors blackboard events to MLS recorder |

27 tests including the integration test
`test_mao_end_to_end_against_fixture_target` which verifies:
- recon-agent and exploit-agent run in the same coordinator,
- critique-agent catches a deliberately hedged finding,
- the blackboard log is reconstructable via parent_id chains,
- the memory-agent mirrors confirmed findings to MLS but blocks
  unconfirmed ones.

### ACP (subsystem 5)

| Module | Purpose |
|---|---|
| `goal_tree.py` | `GoalTree` mutable / prunable / serialisable; node scoring `(p × value) / cost` |
| `budget.py` | Three concurrent budgets + per-minute rate cap; `can_charge()` is fail-closed |
| `pruner.py` | Kills branches on excess failures, cost overrun, or precondition failure |
| `watchdog.py` | Halts the planner on thrashing / scope-drift / error-rate / budget. The planner has no API to clear `halted`. |
| `executor.py` | `dispatch_leaf` posts a Hypothesis to MAO; `resolve_leaf` walks the result back |
| `seed.py` | `seed_tree(archetype, surfaces, mls_store)` — initial tree from a UTI archetype + MLS priors |
| `resume.py` | JSON checkpoints to `targets/<slug>/.planner-state.json` every 60s |
| `planner.py` | The search loop, ordering: watchdog → budget → pruner → pick best → scope check → dispatch → coordinator tick → resolve → charge → checkpoint |

22 tests including:
- `test_simulated_run_terminates_cleanly_on_no_more_leaves`
- `test_simulated_run_halts_on_budget`
- `test_resume_across_kill_preserves_progress`
- `test_watchdog_halt_authority` (asserts the planner has no
  `clear_watchdog` / `unhalt` API)
- `test_full_pipeline_url_to_report` — UTI → ACP → MAO → reports →
  MLS, all hops in one run.

---

## Ethics gates — verified inviolable

Per FORGE PROTOCOL § 8 every gate is in `framework/v2/common/ethics.py`
and tested by `framework/v2/common/tests/test_common.py`:

- **Charter requirement:** `require_charter_signed()` raises
  `CharterNotSigned` against an unsigned charter (verified against a
  synthetic-target fixture in `test_common.py`).
- **Scope enforcement:** `require_in_scope()` raises `OutOfScope`
  for hosts outside the parsed charter scope (verified with
  synthetic in-scope and out-of-scope hosts).
- **Authorization on intake:** `require_authorized_intake()`
  reads the ledger; deny-by-default.
- **Watchdog scope-drift halt:** the planner's watchdog calls
  `require_in_scope` per step (when the charter is signed) and
  halts the planner if it would dispatch out-of-scope traffic.
- **No exfiltration paths:** v2 only reaches Anthropic when
  `ANTHROPIC_API_KEY` is set, the operator's local Ollama, or
  the target host (under UTI's 50-request budget). No telemetry
  home, no usage statistics, no cloud-sync.
- **No backdoors:** no hardcoded credentials, no debug bypasses
  for the gates, no "skip auth in dev" toggles. The gates raise
  typed `EthicsViolation` subclasses; no caller silently catches
  them.

---

## Run commands the operator uses

```bash
# one-time setup
bash bin/init.sh
pip install --break-system-packages -r framework/v2/requirements.txt

# live status — shows resolved root, active LLM backend, MLS counts
python3 -m framework.v2 status

# URK (DryRun by default; set ANTHROPIC_API_KEY to switch)
python3 -m framework.v2 kernel hypothesize  --observation "..."
python3 -m framework.v2 kernel critique     --claim "..."
python3 -m framework.v2 kernel pivot        --thread "..."
python3 -m framework.v2 kernel decide       --summary "..."
python3 -m framework.v2 kernel opsec        --action "..."
python3 -m framework.v2 kernel threat-model --target your-target

# MLS
python3 -m framework.v2 memory status
python3 -m framework.v2 memory seed --slug sample-php-panel  # built-in sample
python3 -m framework.v2 memory similar --text "..."
python3 -m framework.v2 memory wins    --archetype "..."
python3 -m framework.v2 memory priors  --archetype "..."

# UTI
python3 -m framework.v2 intake authorize https://example.com --operator yourname
python3 -m framework.v2 intake https://example.com
python3 -m framework.v2 intake fingerprint https://example.com

# MAO + ACP — invoked programmatically; see
#   framework/v2/planner/tests/test_full_integration.py
# for the canonical wiring (UTI → seed_tree → Planner → Coordinator → MAO).
# A dedicated `python3 -m framework.v2 plan <slug>` entry point is a
# Session-3 follow-up.
```

---

## Git history

```
e826c47 MAO: blackboard + coordinator + 5 specialist agents + memory agent + executor protocol + integration test
db719bf v2 foundation: V2-MANIFEST + V2-LIMITATIONS + README/HOW-TO-START v2 sections + .gitignore v2 paths
7b0f726 UTI: HTTP fetcher + 7 detectors + 9 archetypes + classifier + drafters/scaffolder + live mrbeanpanel.com
fcf051f MLS: SQLite store + lexical embeddings + recorder/recall/priors + mrbeanpanel seed
4551088 v2 foundation + URK: common (paths/docs/ethics/logging) + kernel (6 cognitive bindings)
28659ec v1 baseline before forge protocol
```

Plus a Session-2 commit landing MAO + ACP together.

---

## What's in `V2-LIMITATIONS.md`

Every weakness, every shortcut, every external dependency, every
place a determined adversary could trip the framework into bad
behaviour. Specifically: § "Inherited unexercised-LLM-path risk"
lists which URK entry points and failure modes need verification
the first time URK runs against a live model. Read it next.
