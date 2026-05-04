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
| 1 | URK — Universal Reasoning Kernel | `framework/v2/kernel/` | yes | **partial — DryRun only** | 6 cognitive bindings + 3 backends. AnthropicBackend / OllamaBackend implemented from public docs but never exercised end-to-end with a live model in any session so far. DryRun fixture output is structurally valid; reasoning quality is bounded. |
| 2 | MLS — Memory & Learning Substrate | `framework/v2/memory/` | yes | yes | SQLite store + lexical embeddings (sentence-transformers optional); recorder / recall / priors / postmortem. mrbeanpanel seed exercised. No LLM dependency. |
| 3 | UTI — Universal Target Intake | `framework/v2/intake/` | yes | yes (HTTP path); **partial (drafter)** | 7 detectors, 9 archetypes, confidence-weighted classifier exercised live against `mrbeanpanel.com`. The threat-model drafter calls URK and therefore inherits the DryRun limitation. |
| 4 | MAO — Multi-Agent Orchestration | `framework/v2/agents/` | yes | **partial — DryRun only** | Blackboard + coordinator + 5 specialist agents + memory-agent + executor protocol. Pipeline exercised via `DeterministicExecutor` against the fixture-replay harness. The hypothesis-agent and critique-agent both call URK and inherit DryRun. |
| 5 | ACP — Autonomous Campaign Planner | `framework/v2/planner/` | yes | **partial — DryRun only** | Goal tree, budget, pruner, watchdog, resume, executor router, planner core. Acceptance test = simulated run against the fixture-replay harness with compressed wall-clock budget; resume-across-kill verified; watchdog halt-authority verified. |
| 6 | DEL — Defender Emulation Layer | (`framework/v2/defender/` — absent) | no | no | Telemetry model, detection scoring, evasion library, Sigma runner. Deferred to a future session. |
| 7 | DAA — Deep Analysis Arsenal | (`framework/v2/analysis/` — absent) | no | no | Semgrep / CodeQL / Joern / API fuzzer / differential testing / AST indexer. Largest deferred subsystem. |
| 8 | SIL — Self-Improvement Loop | (`framework/v2/improve/` — absent) | no | no | Engagement-end reviewer + reviewable patch generator. Runs after everything else. |

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
   detector pipeline have been exercised against the operator's own
   `mrbeanpanel.com` (in scope per the existing charter) under a 12-
   request budget. Classifier returns `php-smarty-smm-panel-fork`
   with score 0.745.

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
  — `159 passed, 1 skipped` (the skip is the opt-in
  `mrbeanpanel.com` live-intake test).
- **Live integration:** `CRUCIBLE_LIVE_INTAKE=1 pytest
  framework/v2/intake/tests/test_intake.py::test_live_intake_against_mrbeanpanel`
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
opt-in live integration. mrbeanpanel.com classifies as
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
  `CharterNotSigned` on the actual unsigned mrbeanpanel charter.
- **Scope enforcement:** `require_in_scope()` raises `OutOfScope`
  for `evil.com`; `mrbeanpanel.com` and its subdomains pass.
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
python3 -m framework.v2 kernel threat-model --target mrbeanpanel

# MLS
python3 -m framework.v2 memory status
python3 -m framework.v2 memory seed --slug mrbeanpanel
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
