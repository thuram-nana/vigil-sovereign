# V2-MANIFEST

Status of CRUCIBLE v2 as delivered in this session of the FORGE
PROTOCOL. The v1 canon under `framework/{cognitive,playbooks,
checklists,knowledge-base,templates}/` is byte-for-byte unchanged
from the baseline commit; v2 lives entirely under `framework/v2/`.

This file is honest about what shipped, what didn't, and what was
done to preserve the ethics layer. Per FORGE PROTOCOL § 4.10, lying
about completeness is the worst possible outcome — so this manifest
treats *partial* and *deferred* as legitimate states of the work.

---

## Subsystem status

| # | Subsystem | Path | Status | Notes |
|---|-----------|------|--------|-------|
| 1 | URK — Universal Reasoning Kernel | `framework/v2/kernel/` | **Shipped** | 6 cognitive bindings + 3 backends (Anthropic/Ollama/DryRun); cites v1 prose verbatim. |
| 2 | MLS — Memory & Learning Substrate | `framework/v2/memory/` | **Shipped** | SQLite + lexical embeddings (sentence-transformers optional); recorder/recall/priors/postmortem; mrbeanpanel seeded. |
| 3 | UTI — Universal Target Intake | `framework/v2/intake/` | **Shipped** | 7 detectors, 9 archetypes, confidence-weighted classifier, drafters, scaffolder; live-tested against `mrbeanpanel.com`. |
| 4 | MAO — Multi-Agent Orchestration | (`framework/v2/agents/` — absent) | **Deferred** | Blackboard, coordinator, and 6 specialist agents. Single-session scope: foundation only. |
| 5 | ACP — Autonomous Campaign Planner | (`framework/v2/planner/` — absent) | **Deferred** | Goal tree, MCTS-style search, budget enforcement, watchdog, resume. Depends on MAO. |
| 6 | DEL — Defender Emulation Layer | (`framework/v2/defender/` — absent) | **Deferred** | Telemetry model, detection scoring, evasion library, Sigma runner. |
| 7 | DAA — Deep Analysis Arsenal | (`framework/v2/analysis/` — absent) | **Deferred** | Semgrep / CodeQL / Joern / API fuzzer / differential testing / AST indexer. Largest deferred subsystem. |
| 8 | SIL — Self-Improvement Loop | (`framework/v2/improve/` — absent) | **Deferred** | Engagement-end reviewer + reviewable patch generator. Runs after everything else. |

The decision to scope this session to subsystems 1, 2, and 3 was
made and acknowledged at the start of the session by the operator.
The deferred subsystems are not stubbed (per FORGE PROTOCOL § 4.1 —
no placeholder code). Their absence is documented here and in
`V2-LIMITATIONS.md`.

---

## Verification results

All from a clean run of the verification suite at the time this
manifest was written.

- **v1 canon unchanged:** `git diff <baseline> HEAD --
  framework/{cognitive,playbooks,checklists,knowledge-base,templates}`
  returns empty.
- **Syntax:** every Python file under `framework/v2/` parses with
  `ast.parse`. Every YAML parses with `yaml.safe_load`. Every JSON
  parses with `json.loads`.
- **Type check:** `mypy --config-file framework/v2/pyproject.toml`
  — `Success: no issues found in 50 source files`.
- **Test suite:** `python3 -m pytest framework/v2/`
  — `110 passed, 1 skipped` (the skipped test is the live
  integration test, which is opt-in via
  `CRUCIBLE_LIVE_INTAKE=1`).
- **Live integration:** `CRUCIBLE_LIVE_INTAKE=1 pytest
  framework/v2/intake/tests/test_intake.py::test_live_intake_against_mrbeanpanel`
  — passes; live request against `mrbeanpanel.com` (in scope per
  the existing operator charter) under a 12-request budget.
- **Cross-references:** every `framework/v2/...` path referenced in
  the v2 docs resolves to a real file.
- **Path portability:** the framework finds its root via
  `CRUCIBLE_ROOT` env override or by walking up to `CLAUDE.md`. The
  installer at `bin/init.sh` rewrites `.claude/settings.json` to
  match the actual filesystem location.

---

## What ships, in detail

### URK (subsystem 1)

| Module | Lines | Purpose |
|--------|-------|---------|
| `models.py` | ~230 | Pydantic schemas for every binding (HypothesisSet, CritiqueResult, PivotProposal, SeverityDecision, OpsecGuidance, ThreatModel) |
| `llm.py` | ~150 | Backend abstraction + selection registry |
| `binding.py` | ~75 | Shared prompt-rendering + dispatch helper |
| `backends/anthropic.py` | ~125 | Anthropic Messages API; default model `claude-sonnet-4-6` |
| `backends/ollama.py` | ~135 | Local Ollama HTTP; default model `qwen2.5-coder:32b` |
| `backends/dryrun.py` | ~80 | Default fallback; deterministic per-schema fixtures |
| `backends/fixtures.py` | ~480 | Per-schema fixture providers (the bug-class catalogue, lateral-move templates, severity heuristics, posture-keyed opsec) |
| `hypothesize.py` … `threat_model.py` | ~30 each | One file per cognitive binding |
| `cli.py` | ~140 | `python3 -m framework.v2 kernel <subcommand>` |
| `tests/test_kernel.py` | ~210 | 35 tests including doctrine compliance for hypothesize, anchor resolution per binding |

Every binding loads the v1 cognitive markdown via `common.docs`
and quotes the relevant section verbatim into the system prompt.
`URK does not paraphrase the cognitive layer; it cites it.`

### MLS (subsystem 2)

| Module | Lines | Purpose |
|--------|-------|---------|
| `schema.sql` | ~140 | 8 tables, version-1 schema |
| `migrate.py` | ~75 | Idempotent migrations + schema_meta |
| `embed.py` | ~165 | Lexical (default, 256-dim feature-hashing) + SentenceTransformer (optional) embedder |
| `store.py` | ~110 | SQLite connection + per-instance state |
| `recorder.py` | ~225 | Write-only API for engagements / findings / hypotheses / payloads / dead ends / playbook outcomes |
| `recall.py` | ~245 | similar_targets / winning_hypotheses / payload_priors / dead_end_priors / playbook_yield + Provenance type |
| `priors.py` | ~100 | Bayesian-flavoured priors (Laplace mean + Wilson lower bound) |
| `postmortem.py` | ~145 | Engagement-end retrospective; updates priors and writes `targets/<slug>/postmortem.md` |
| `seed_mrbeanpanel.py` | ~290 | Reads existing mrbeanpanel files; seeds engagement + 122 attack-tree leaves + 3 representative confirmed findings |
| `cli.py` | ~140 | `python3 -m framework.v2 memory <subcommand>` |
| `tests/test_memory.py` | ~280 | 18 tests including the § 3.2 measurable-bias acceptance |

Provenance is tracked: every recall result carries
`Provenance(table, row_id, engagement_id, engagement_slug)`.

### UTI (subsystem 3)

| Module | Lines | Purpose |
|--------|-------|---------|
| `models.py` | ~150 | HTTPExchange, Detection(Result), Fingerprint, Archetype, Classification, IntakeOutcome |
| `http.py` | ~210 | Fetcher with 50-request budget cap, polite UA, fixture-replay mode for offline tests, capture mode |
| `fingerprint/_common.py` | ~115 | Shared signature engine (header/cookie/body/path/url/status; diminishing-returns aggregation) |
| `fingerprint/{server,framework,cms,auth,api,payment,cdn_waf}_detection.py` | ~100 each | ~120 curated signatures total across 7 detectors |
| `archetypes/*.yaml` | 9 files | Stack archetypes with required+optional fingerprint lists, common-vuln lists, playbook priorities, attack-tree seeds |
| `archetypes/__init__.py` | ~35 | Lazy registry loader |
| `stack_classifier.py` | ~95 | Confidence-weighted scoring; falls back to `generic-web` |
| `drafters.py` | ~265 | Charter draft (NEVER signs), threat-model (URK-driven, falls back to skeleton), attack-tree (archetype × common-vuln) |
| `scaffolder.py` | ~110 | `cp -r targets/_template targets/<slug>` + draft writes; refuses to overwrite signed `charter.md` |
| `intake.py` | ~135 | Orchestrator: ethics gate → fetcher → 7 detectors → classifier → drafters → scaffolder → MLS recorder |
| `cli.py` | ~125 | `python3 -m framework.v2 intake [run|authorize|fingerprint] <url>` |
| `tests/test_intake.py` | ~430 | 25 tests including the live mrbeanpanel.com integration |

Live confirmation: `mrbeanpanel.com` correctly classifies as
`php-smarty-smm-panel-fork` with score 0.745.

---

## Ethics gates — verified inviolable

Per FORGE PROTOCOL § 8 every gate is in `framework/v2/common/ethics.py`
and tested by `framework/v2/common/tests/test_common.py`.

- **Charter requirement:** `require_charter_signed("mrbeanpanel")`
  raises `CharterNotSigned` because the operator's actual charter
  carries the literal `<name>` placeholder. Verified by test
  `test_require_charter_signed_raises_for_unsigned`.
- **Scope enforcement:** `require_in_scope("mrbeanpanel",
  "https://evil.com")` raises `OutOfScope`; the same call against
  `https://api.mrbeanpanel.com/v2/users` passes.
- **Authorization on intake:** `require_authorized_intake` reads
  `framework/v2/.intake-authorizations.txt`; refuses any host not
  listed. UTI's first action calls this; deny-by-default.
- **No exfil paths:** v2 makes outbound HTTPS only to (a) the
  Anthropic API when `ANTHROPIC_API_KEY` is set and the operator
  invoked URK, (b) the operator's local Ollama daemon when
  configured, (c) the target host (during UTI's fingerprint pass,
  bounded by the 50-request budget). No telemetry, no usage
  statistics, no cloud-sync.
- **No backdoors:** there are no hardcoded credentials, no debug
  bypasses for the gates, no "skip auth in dev" toggles. The
  gates raise typed `EthicsViolation` subclasses; no caller
  silently catches them.

The `.claude/settings.json` permission model (v1) is now
path-portable thanks to `bin/init.sh` and unchanged in policy.

---

## Run commands the operator uses

```bash
# one-time setup
bash bin/init.sh
pip install --break-system-packages -r framework/v2/requirements.txt

# live status
python3 -m framework.v2 status

# URK
python3 -m framework.v2 kernel hypothesize  --observation "..."
python3 -m framework.v2 kernel critique     --claim "..."
python3 -m framework.v2 kernel pivot        --thread "..."
python3 -m framework.v2 kernel decide       --summary "..."
python3 -m framework.v2 kernel opsec        --action "..."
python3 -m framework.v2 kernel threat-model --target mrbeanpanel

# MLS
python3 -m framework.v2 memory status
python3 -m framework.v2 memory seed --slug mrbeanpanel
python3 -m framework.v2 memory similar  --text "..."
python3 -m framework.v2 memory wins     --archetype "..."
python3 -m framework.v2 memory priors   --archetype "..."
python3 -m framework.v2 memory postmortem --slug mrbeanpanel

# UTI
python3 -m framework.v2 intake authorize https://example.com --operator yourname
python3 -m framework.v2 intake https://example.com
python3 -m framework.v2 intake fingerprint https://example.com
```

---

## Git history

```
7b0f726 UTI: HTTP fetcher + 7 detectors + 9 archetypes + classifier + drafters/scaffolder + 24 tests passing + live mrbeanpanel.com correctly classifies
fcf051f MLS: SQLite store + lexical embeddings + recorder/recall/priors + mrbeanpanel seed (17 tests passing, total 86)
4551088 v2 foundation + URK: common (paths/docs/ethics/logging) + kernel (6 cognitive bindings) + 69 passing tests
28659ec v1 baseline before forge protocol
```

---

## What's in `V2-LIMITATIONS.md`

Frank, detailed list of every weakness, every shortcut, every
external dependency, every place a determined adversary could trip
the framework into bad behaviour. Read it next.
