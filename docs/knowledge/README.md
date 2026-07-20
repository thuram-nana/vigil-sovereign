# VIGIL — Knowledge Base (durable session context, copied into the repo)

Everything a fresh session (cloud or local) needs to resume this project at 100% is committed here, so no
context lives only in a chat window. Read order for a cold start:

1. [`../CONTINUATION.md`](../CONTINUATION.md) — **start here**: build state (P0–P4 done), how to build/test,
   the exact remaining phases, and the autonomous-build protocol + the standard.
2. [`../PLAN.md`](../PLAN.md) — the approved architecture, the two FATAL flaws, the no-hallucinated-findings
   pipeline, governance, and the P0–P10 + I1–I5 sequencing. LOCKED decisions in §12.
3. [`../research/FRONTIER.md`](../research/FRONTIER.md) — the 1-of-1 case with sources; the moonshot techniques
   (I1–I5) mapped to standards + open-source reference systems (Buttercup, Tessera, SCITT, angr/Z3, FROST, CGC).

## What's in this folder
- **`memory/`** — the maintainer's persistent Claude memory (29 files, incl. `MEMORY.md` as the index). This is
  the *complete build history + hard-won lessons* for the three source systems:
  - `sigil-*.md` — SIGIL phases 0–9 + production-hardening + spine-rotation + hard-prune (the sovereign spine,
    Rust WARDEN, agent mesh, voice, embodiment, companion). The signed-spine + governance substrate VIGIL fuses.
  - `anti-hallucination.md`, `intel-engine.md`, `nervous-system.md`, `enterprise-platform.md`, `speed-program.md`,
    `unified-autonomy-program.md`, `coverage-/credibility-/pcf-forge-/gap-closure-/prover-to-discoverer-program.md`,
    `crucible-beyond-sota-program.md`, `crucible-testing-and-gotchas.md`, `ops-console.md` — CRUCIBLE's oracle
    authority, veracity firewall, PCF certs, intel engine, and every merged program + its gotchas.
  - `aegis-runtime-defense-frontier.md` — AEGIS (the defensive dual; 27 OracleKinds; the dual-review bar).
  - **These are load-bearing:** they record *why* each design decision was made and *which defects* the
    adversarial review caught each slice — the discipline VIGIL must keep. Do not re-derive; read them.
- **`constitution-obsidian.md`** — the OBSIDIAN operating constitution (the offensive framework's doctrine:
  authorization, scope, OODA cognitive loop, coverage doctrine, documentation discipline, honesty rules). The
  governing rules the offense side of VIGIL inherits.
- **`graphify/`** — the graphify knowledge graph of the CRUCIBLE/PENTEST codebase:
  - `GRAPH_REPORT.md` — human-readable god-nodes + community structure (read this before architecture questions).
  - `graph.json` — the full AST-derived graph (33M). Regenerate with `graphify update .` after code changes.
- **`../research/raw-session-research/`** — 101 raw outputs from this session's deep-research + build/review
  agents (the unabridged source material `FRONTIER.md` distills). Kept verbatim so nothing is lost.

## Provenance
Copied 2026-07-19 from the maintainer's live environment before the workstation went offline, per the directive
to leave nothing out. The source-of-truth code is the four subtree members (`apps/sigil`, `engine/crucible`
[AEGIS at `framework/v2/aegis`], `vendor/strix`, `packages/core/vigil_core`); this folder is the *context* around
that code. When the workstation returns, local memory + graphify stay authoritative and are re-synced forward.
