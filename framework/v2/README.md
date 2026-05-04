# framework/v2/

v2 is the executable layer. v1 is the canon — frozen, untouched. This
directory adds three subsystems on top of v1 in this session:

| Subsystem | Path | Status |
|-----------|------|--------|
| URK — Universal Reasoning Kernel | `kernel/` | shipped this session |
| MLS — Memory & Learning Substrate | `memory/` | shipped this session |
| UTI — Universal Target Intake | `intake/` | shipped this session |
| MAO — Multi-Agent Orchestration | `agents/` | deferred (see V2-MANIFEST.md) |
| ACP — Autonomous Campaign Planner | `planner/` | deferred |
| DAA — Deep Analysis Arsenal | `analysis/` | deferred |
| DEL — Defender Emulation Layer | `defender/` | deferred |
| SIL — Self-Improvement Loop | `improve/` | deferred |

Each shipped subsystem has its own `README.md`. The deferred ones are
not stubbed (per FORGE PROTOCOL § 4.1 — no placeholder code) and their
absence is documented in `V2-MANIFEST.md` and `V2-LIMITATIONS.md` at
the repo root.

---

## Run

The framework is path-portable. Set `CRUCIBLE_ROOT` once, or invoke
from anywhere inside the tree containing `CLAUDE.md`. From the
repository root:

```bash
# one-time setup
bash bin/init.sh

# install deps
pip install --break-system-packages -r framework/v2/requirements.txt

# verify
python3 -m framework.v2 status
```

Then:

```bash
python3 -m framework.v2 intake https://target.example
python3 -m framework.v2 memory recall <archetype>
python3 -m framework.v2 kernel hypothesize  # see --help
```

## Layout

```
framework/v2/
├── pyproject.toml           build / mypy / pytest config
├── requirements.txt         runtime deps
├── __init__.py              package marker
├── __main__.py              CLI dispatcher
├── README.md                (this file)
│
├── common/                  shared utilities
│   ├── errors.py            typed exception hierarchy
│   ├── paths.py             CRUCIBLE_ROOT discovery + canonical paths
│   ├── docs.py              v1 markdown loader (URK reads through this)
│   ├── ethics.py            charter / scope / authorization gates
│   └── logging.py           structured JSON-line logging
│
├── kernel/                  URK — wraps v1 cognitive prose as callables
│   ├── models.py            Pydantic schemas for hypothesis / critique / etc.
│   ├── llm.py               backend abstraction
│   ├── backends/            anthropic / ollama / dryrun
│   ├── prompts/             rendered prompt templates
│   └── (cognitive bindings) hypothesize.py, critique.py, pivot.py, ...
│
├── memory/                  MLS — SQLite + embeddings + recall + priors
│   ├── schema.sql
│   ├── store.py
│   ├── embed.py
│   ├── recorder.py
│   ├── recall.py
│   └── priors.py
│
└── intake/                  UTI — URL → fully scaffolded engagement
    ├── intake.py
    ├── fingerprint/         per-class detectors (server, framework, cdn, ...)
    ├── archetypes/          YAML stack archetype registry
    ├── stack_classifier.py
    └── (drafters)           charter_drafter.py, threat_model_drafter.py, ...
```

## Ethics

Three gates are non-negotiable and live in `common/ethics.py`:

1. `require_charter_signed(slug)` — no active testing without a signed
   charter at `targets/<slug>/charter.md`.
2. `require_in_scope(slug, url)` — every action's target host is checked
   against the charter's in-scope list.
3. `require_authorized_intake(url)` — UTI cannot draft against a URL
   until the operator has appended an attestation to
   `framework/v2/.intake-authorizations.txt`.

These functions raise typed `EthicsViolation` subclasses. No subsystem
catches `EthicsViolation` — it propagates to the CLI and halts.

## What v2 does not do (this session)

- **Run autonomously for hours.** That requires ACP + MAO, which are
  deferred. v2 today scaffolds engagements and seeds priors; humans
  drive the actual testing.
- **Match XBOW or Big Sleep.** This is foundation. The frontier
  capabilities live in the deferred subsystems.
- **Live-call any LLM by default.** Without `ANTHROPIC_API_KEY` or a
  reachable Ollama, URK runs in DryRun mode — prompts written to
  `framework/v2/.dryrun/`, deterministic structured stubs returned.
  Works offline; reasoning quality bounded accordingly.

See `V2-LIMITATIONS.md` at the repo root for the full list.
