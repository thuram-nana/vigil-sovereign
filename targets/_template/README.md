# `_template/` — Engagement Skeleton

> Copy this entire directory to start a new engagement: `cp -r targets/_template targets/<name>`. The files in here are **stubs**; the canonical, latest version of each template lives in `framework/templates/`. If a template here drifts from the framework, treat the framework version as authoritative and resync.

---

## What's Here

```
_template/
├── README.md                    ← this file (do not delete; describes the layout)
├── charter.md                   ← scope, authorization, RoE — FILL FIRST
├── threat-model.md              ← STRIDE / kill-chain analysis
├── attack-tree.md               ← objectives → sub-goals → attack leaves
├── recon/                       ← passive + active recon outputs
│   └── README.md
├── findings/                    ← FINDING-NNN and CHAIN-NNN files
│   └── README.md
├── evidence/                    ← screenshots, raw HTTP captures, PoC outputs
│   └── README.md
├── notes/                       ← engagement-log, command-log, hypotheses, etc.
│   ├── engagement-log.md
│   ├── command-log.md
│   ├── hypotheses.md
│   ├── endpoints.md
│   ├── role-matrix.md
│   └── test-artifacts.md
├── loot/                        ← extracted creds & tokens — gitignored
│   └── README.md
└── reports/                     ← client-facing deliverables
    └── README.md
```

## Order of First-Time Operations

1. **`charter.md`** — fill scope, authorization, RoE. Do not touch the target until this is signed/agreed.
2. **`threat-model.md`** — derive from charter; identify actors and assets.
3. **`attack-tree.md`** — top-level objectives broken down to leaves; this is your priority queue.
4. **`notes/engagement-log.md`** — start the daily journal.
5. **`notes/command-log.md`** — every command you run goes here with timestamp and rationale.
6. Begin Phase 1 from `framework/playbooks/00-pre-engagement.md` → `01-passive-recon.md` → ...

## Fields You Must Fill in Each Stub

The stubs contain `<TARGET>`, `<DATE>`, `<OPERATOR>`, `<CLIENT>` placeholders. Search and replace before starting:

```
grep -rn '<TARGET>\|<DATE>\|<OPERATOR>\|<CLIENT>' .
```

## Don't Edit These Files in Place

The files in `framework/templates/` are the source of truth. If you find yourself wanting to change a template, change the framework copy and resync. That way every future engagement benefits.
