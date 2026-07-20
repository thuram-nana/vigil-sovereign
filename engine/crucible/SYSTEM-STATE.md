# SYSTEM-STATE.md — CRUCIBLE living brain

> **You are a stateless cloud agent. Read this FIRST, every run.** It
> reconstructs what CRUCIBLE is, where the build stands, which seams are
> load-bearing, and what is still missing — so you don't re-derive it from
> a cold `ls`. At the END of your run, update it (see § 6). Ground every
> edit in real code; cite paths. If this file and the code disagree, the
> code wins and you fix this file.

Last refreshed: 2026-07-03 · Branch `claude/flagship-wave1` · HEAD `f0c9fa6`
(Wave 3). Repo root `/home/kali/Pictures/PENTEST-main`. Executable layer
lives under `framework/v2/` (Python 3.11, Pydantic v2). v1 is frozen canon.

---

## 1. Mission + where the build stands

CRUCIBLE is an autonomous, **governed** red-team platform whose moat is the
governance / sovereignty / entitlement stack (accreditable for classified,
air-gapped deployment) — not raw offense. It is DEFENSIVE / VERIFICATION /
PLANNING capability only: no turnkey weapons, no working evasion of real
defenders, localhost-only test targets.

A prior audit found the platform confirmed findings by **LLM opinion**, had
**no world-model graph** and **no attacker state** (couldn't chain or plan a
path), shipped **fixture-theatre** tests, stamped "confirmed" with a
hardcoded **1.0 confidence**, and kept an honesty ledger that contradicted
itself. Root cause seen 9/10 ways: no graph, no state, no deterministic
oracle. Gap-analysis average maturity was 1.2/5.

Waves 1–3 (this branch, merged) lay the foundations that close the single
most important finding — *"no real target ever drove a real confirmed
finding"* is **CLOSED**: `verify/` (the deterministic ORACLE layer) is now
the confirmation authority inside `agents/critique_agent.py`, and
`verify/confirmation.confirm_against_local_target` proves it end-to-end
against a real loopback target. New substrate also landed: `worldmodel/`
(typed attack-graph + ranked path search, now wired into the planner),
`calibration/` (PAV isotonic scoring replacing the hardcoded 1.0, wired into
`eval/produce`), and `knowledge/` (techniques as STRIPS planning operators).
The build is *foundations solid, producers not yet emitting oracle evidence*
— see § 5.

Tests: **559 passed / 11 skipped** in the configured suite, **+182 passed**
in the four new modules that are *not yet in `testpaths`* (§ 3, § 5). Grand
total **741 passed, 11 skipped, 0 failed**.

---

## 2. Subsystem atlas

Every module under `framework/v2/`. Status: **solid** (mature, load-bearing),
**partial** (works, known gaps), **new** (Waves 1–3 substrate).

| Module | Purpose | Key files | Status | Integration seams (what calls what) |
|---|---|---|---|---|
| `common/` | Shared spine: path discovery, typed errors, charter/scope gates, JSON-line logging | `paths.py`, `errors.py` (`CrucibleError`), `ethics.py`, `logging.py` (`bind_engagement`), `docs.py` | solid | Everything imports it. `conftest.py` resets `bind_engagement(None)` after each test. |
| `kernel/` (URK) | Wraps v1 cognitive prose as typed callables over an LLM backend | `critique.py` (`critique()`), `hypothesize.py`, `pivot.py`, `decide.py`, `llm.py` (+`backends/` anthropic/ollama/dryrun), `models.py` | solid | `critique_agent` calls `kernel.critique.critique`. Backend forced to `dryrun` in tests via `conftest`. |
| `memory/` (MLS) | SQLite + embeddings + recall + priors; postmortems | `store.py`, `embed.py`, `recall.py`, `priors.py`, `recorder.py`, `schema.sql` | solid | Fed by `agents/memory_agent.py`; recall consumed by kernel/planner. |
| `intake/` (UTI) | Target intake: fingerprint, stack-classify, scaffold engagement dirs | `intake.py`, `stack_classifier.py`, `scaffolder.py`, `drafters.py`, `http.py` | solid | Produces `targets/<slug>/`; feeds recon/planner. |
| `agents/` (MAO) | Blackboard multi-agent orchestration; the promotion pipeline | `blackboard.py`, `critique_agent.py`, `exploit_agent.py`, `reporter_agent.py`, `http_executor.py`, `coordinator.py`, `models.py` (`FindingPayload`) | solid (critique_agent **new-wired**) | **LOAD-BEARING (§4):** `critique_agent` → `verify.confirmation.confirm_finding` when a Finding carries `oracle_context`. Reporter promotes only `critique_status=="confirmed"`. |
| `planner/` (ACP) | Goal-tree campaign planning, budget, watchdog, resume | `goal_tree.py`, `planner.py`, `watchdog.py`, `budget.py`, `pruner.py`, `seed.py` | solid (world-model **new-wired**) | `goal_tree.py` + `planner.py` take an optional `world: WorldModel` and call `worldmodel.pathsearch.best_paths` / `surface_to_node_id` to bias planning toward high-value routes. `world=None` ⇒ legacy behaviour. |
| `defender/` (DEL) | Defender emulation: telemetry, detection rules, posture scoring | `telemetry.py`, `rules.py`, `scoring.py`, `posture.py`, `models.py` | solid | Consumes agent actions; scores detectability. |
| `analysis/` (DAA) | Static taint arsenal (builtin + semgrep + joern CPG) | `orchestrator.py`, `analyzers/builtin.py`, `analyzers/external.py` (semgrep), `analyzers/joern.py`, `review_loop.py` | solid | Corpus-measured (honest 8/8 on the CVE-class corpus). semgrep/joern tests skip when tools absent. |
| `improve/` (SIL) | Self-improvement loop: ingest, review, patch, merge-gate | `ingest_live.py`, `reviewer.py`, `patcher.py`, `merge_gate.py`, `horizon.py`, `canonical.py` | solid | `merge_gate.py` enforces the never-merge-to-main / signed-review discipline. |
| `entitlement/` | Ed25519 m-of-n capability gating | `crypto.py`, `policy.py`, `registry.py`, `provision.py`, `binding.py`, `canonical.py` | solid | Each capability is entitlement-gateable — the sovereignty moat. |
| `authority/` | Kill-switch + charter authority + signing | `killswitch.py`, `charter.py`, `gate.py`, `signing.py`, `canonical.py` | solid | Global stop authority; signs/verifies authority records. |
| `eval/` | Corpus + produce + scoring + regression harness | `corpus.py`, `produce.py`, `produce_daa.py`, `harness.py`, `scoring.py`, `regression.py` | solid (calibration **new-wired**) | `produce.py` lazily imports `calibration.{Calibrator,OutcomeLedger,fit}` to score findings with a *learned* probability instead of 1.0. |
| `socialdefense/` | Social-engineering defense detectors | `detectors.py`, `models.py`, `cli.py` | solid | Standalone detection surface. |
| **`verify/`** | **Deterministic ORACLE layer — the confirmation authority** | `verifier.py` (`OracleVerifier.confirm`, `BUG_CLASS_ORACLES`), `oracles.py` (5 pure oracles), `oob.py` (`OOBReceiver`, loopback-only), `adapter.py` (`FindingContext`), `confirmation.py` (`confirm_finding`, `confirm_against_local_target`), `models.py` (`OracleKind/Signal/Probe`, `VerificationResult`) | **new** | Consumed by `agents/critique_agent.py`. `knowledge/catalog.py` imports `verify.models.OracleKind`. `HIGH_CONFIDENCE=0.7`: a finding confirms only when ≥1 oracle *fires* at/above threshold; absent inputs *skip*, never pass. |
| **`worldmodel/`** | **Persistent typed attack-graph + ranked path search** | `models.py` (`Node/Edge/Path`, `NodeKind/EdgeKind`), `graph.py` (`WorldModel`, idempotent upserts), `pathsearch.py` (`best_paths`, `shortest_paths` Yen, `choke_points` min-cut), `derivation.py` (monotonic Datalog forward-chainer to fixpoint), `query.py`, `store.py` (JSON save/load) | **new** | Consumed by `planner/goal_tree.py` + `planner/planner.py`. Time is a caller-supplied **sequence int**, never wallclock. All queries bounded + simple-path. |
| **`calibration/`** | **Learned exploitability probability + outcome ledger** | `calibrate.py` (`fit`, PAV isotonic, ECE/Brier, identity fallback under `MIN_LABELS`), `ledger.py` (`OutcomeLedger`, append-only, seq-ordered), `models.py` (`Prediction/Outcome`) | **new** | Consumed by `eval/produce.py`. Nothing returns 1.0; probs clamp to `MAX_PROB=0.999`. Oracle prior is the *observed* exploit-rate, not a constant. |
| **`knowledge/`** | **Technique Knowledge Graph: TTPs as planning operators** | `models.py` (`Operator/Predicate/Effect`, typed over world-model vocab), `operators.py` (`applicable/match/apply/derive/saturate`), `catalog.py` (`CATALOG` — 6 seed operators, 2 deliberately chain) | **new** | Imports `worldmodel` + `verify.OracleKind`. **Not yet consumed by any runtime producer** (§5) — substrate ready, unwired. |

CLI dispatch is `python3 -m framework.v2 <subcommand>` (`__main__.py`).

---

## 3. Invariants & conventions

- **Pydantic v2, `model_config = ConfigDict(extra="forbid")`** on the typed
  carriers (`FindingContext`, `ConfirmedFinding`, world-model models,
  calibration models). Unknown keys are a validation error, not silent drop.
- **Determinism / no wallclock.** The new substrate never reads the clock.
  worldmodel, calibration ledger, and knowledge operators all order and
  timestamp by a **caller-supplied monotonic `seq: int`**. The oracle verdict
  in `confirmation.py` rests on response *content* (status/length/lexical),
  never latency, so it is replayable. Oracles in `oracles.py` are pure: no
  I/O, no network, no clock, no randomness.
- **Honesty doctrine / no fixture-theatre.** Confirmation must come from a
  *fired signal over data a real target produced*. `confirm_against_local_target`
  stands up a real loopback HTTP app (`DifferentialDemoHandler`) and its safe
  twin (`SafeDemoHandler`, the negative control that returns `None`). Never
  claim completeness not achieved.
- **Tests layout.** Each module has `tests/` beside it (`test_*.py`,
  `test_*` functions). Root `conftest.py` forces
  `CRUCIBLE_LLM_BACKEND=dryrun` unless the operator overrode it, and unbinds
  the engagement log after every test.
- **Run the suite** (from `framework/v2/`):
  - Configured suite: `python3 -m pytest` → **559 passed, 11 skipped**
    (`testpaths` in `pyproject.toml`: common, kernel, memory, intake, agents,
    planner, entitlement, eval, improve, defender, analysis, authority,
    socialdefense).
  - **The four new modules are NOT in `testpaths`** — run them explicitly:
    `python3 -m pytest verify/tests worldmodel/tests calibration/tests knowledge/tests`
    → **182 passed** (verify 56, worldmodel 68, calibration 33, knowledge 25).
  - **Full gate before any commit:** run BOTH, expect **741 passed, 0 failed**.
- **The 11 skips are honest, environment-gated, not silent xfails:** live
  LLM (`CRUCIBLE_LIVE_LLM`), live intake URL, live full pipeline
  (`CRUCIBLE_LIVE_FULL_PIPELINE`), live HTTP target, semgrep-not-installed
  (×3), joern-not-provisioned (×2). Each prints exactly why.
- **mypy** strict-ish (`disallow_untyped_defs`), excludes `tests/`,
  `benchmark/`, `corpus/`.

---

## 4. Load-bearing seams — DO NOT BREAK

1. **Oracle-is-confirmation-authority path.** This is the audit's headline
   fix. In `agents/critique_agent.py::_review`:
   - When `FindingPayload.oracle_context is not None`, the deterministic
     oracle is the **authority**: `_oracle_confirm` → `verify.confirmation.confirm_finding`.
     A fired signal ⇒ `critique_status="confirmed"`, `verified_by_oracle=True`.
     No fired signal ⇒ `"objections"`, **regardless of what the LLM says**.
     The URK critique still runs and is still posted as a Critique event, but
     it is **advisory** — it can neither rubber-stamp a refusal nor veto a fire.
   - When `oracle_context is None`, the **legacy LLM-advisory path is
     unchanged** and `verified_by_oracle` stays `False`. This backward-compat
     branch must keep working — most existing findings still take it.
   - Any error building/running the oracle ⇒ treated as "did not fire". The
     authority **never promotes on an error**.
2. **`confirm_finding` returns `None` unless an oracle fired at/above
   `HIGH_CONFIDENCE` (0.7).** There is no assertion-only path to a
   `ConfirmedFinding`. Do not add one.
3. **`FindingContext.to_verifier_context()` only emits keys whose inputs are
   present**, and paired oracles (differential, achieved-state, side-effect)
   only wire when *both* halves exist. An oracle with no data is *skipped*,
   never fed empties. Preserve this — it is what stops false confirmations.
4. **Adapter is a translator, not a generator** (`verify/adapter.py`): it
   never sends traffic, mints payloads, or contacts a target. Keep that
   boundary.
5. **worldmodel/knowledge/calibration determinism**: never introduce a
   wallclock read or unsorted iteration into these — tests assert byte-stable
   serialization and replayable fits.
6. **Guardrails (non-negotiable):** tests green (0 failures) before any
   commit; NEVER merge to main (human reviews the PR); NEVER force-push or
   rewrite history; no fixture-theatre; defensive/verification/planning only —
   no turnkey offense, no real-defender evasion, localhost-only targets; keep
   the governed/sovereign posture; every capability stays entitlement-gateable.

---

## 5. Known gaps / open seams (current)

- **Producers don't populate `oracle_context` yet.** Grep confirms: outside
  `agents/models.py` and `critique_agent.py`, *nothing* writes
  `oracle_context`. `exploit_agent` / `http_executor` / `realistic_executor`
  collect observations but do not yet build a `FindingContext` and attach its
  `model_dump()` to the emitted `FindingPayload`. Until they do, live findings
  fall through to the legacy LLM-advisory path and the oracle authority only
  fires in tests + `confirm_against_local_target`. **This is the top open
  seam** — the wiring exists end-to-end; the last mile (producer → oracle
  evidence) is unbuilt.
- **The four new modules are outside `pyproject.toml` `testpaths`.** A bare
  `pytest` (what a naive CI gate runs) silently skips 182 tests. Either add
  `verify/tests`, `worldmodel/tests`, `calibration/tests`, `knowledge/tests`
  to `testpaths`, or always run the explicit command in § 3. Treat the 741
  total as the real gate.
- **`knowledge/` is substrate-only, unwired at runtime.** `CATALOG` operators
  and `saturate` are tested but no producer/planner calls them yet — the
  Technique-KG → world-model-derivation → path-search chain is authored but
  not yet driven in a live engagement. worldmodel derivation (`derive`) is
  likewise not yet invoked by the planner path (planner reads the graph but
  doesn't run forward-chaining first).
- **calibration ledger has no live outcome feed.** `eval/produce` can fit and
  apply, but nothing yet resolves real findings into `record_outcome` calls,
  so in practice the calibrator runs in identity-fallback until an outcome
  feed exists.
- **Deeper roadmap unbuilt** (per gap analysis, all still ≥Wave 4):
  symbolic/concolic + SMT, coverage-guided fuzzing over a code-property graph,
  IFDS/IDE taint, POMDP/MCTS sequential decisioning, cross-engagement bandits,
  deconfliction leasing, enterprise identity/cloud/AD/K8s graph.

---

## 6. HOW TO REFRESH THIS FILE (do this at end of every run)

This file is self-maintaining. Before you finish, reconcile it with reality:

1. **Re-scan modules.** `ls framework/v2/*/` and diff against the § 2 atlas.
   Any new dir ⇒ add a row (purpose, key files, status, seams). Any module
   whose key files changed ⇒ update the row. Read the module `__init__.py`
   docstring — the repo keeps an accurate public-surface summary there.
2. **Re-count tests.** From `framework/v2/`:
   - `python3 -m pytest 2>&1 | tail -1` → update the configured count in § 1/§ 3.
   - `python3 -m pytest verify/tests worldmodel/tests calibration/tests knowledge/tests 2>&1 | tail -1`
     → update the new-module count. Recompute the grand total.
   - If any module joined `testpaths`, fix § 3 and drop it from the § 5 gap.
   - If skips changed, re-list them (`pytest -rs`) and confirm each is still
     honestly environment-gated.
3. **Re-trace the load-bearing seams (§ 4).** Confirm the oracle-authority
   branch in `critique_agent.py` still holds (oracle authoritative when
   `oracle_context` present; LLM advisory; error ⇒ no promotion). Confirm
   `confirm_finding` still returns `None` without a fired signal.
4. **Re-scan the gaps (§ 5).** The decisive check:
   `grep -rn 'oracle_context' framework/v2 --include=*.py | grep -v tests`.
   The day a producer (`exploit_agent`/`http_executor`/`realistic_executor`)
   appears here, move "producers don't populate oracle_context" from § 5 to a
   solid seam in § 4 and update § 1 — that closes the top open seam. Re-run
   the import-trace to see if `knowledge`/`worldmodel.derive`/calibration
   outcome-feed got wired.
5. **Update the header** (date, branch, HEAD `git log --oneline -1`) and the
   § 1 "where the build stands" paragraph.
6. **Keep the voice terse, senior, honest.** Cite file paths. Never claim a
   capability the code doesn't have. If code and this file disagree, the code
   wins — fix the file, note it in the engagement log.
