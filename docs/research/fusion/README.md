# VIGIL-FUSION research

Grounding for the **VIGIL-FUSION** program — absorbing the two strongest open-source autonomous-hacker
codebases into VIGIL's sovereign, provable core:

- **[redamon](https://github.com/samugit83/redamon)** — Python / LangGraph AI red-team framework
  (MIT, 2.2k★, actively developed). The primary fusion source: same language as VIGIL's offense env,
  and it already has a mature MCP registry, Fireteam parallel specialists, EvoGraph attack-chain
  memory, AI-Gauntlet offensive-LLM testing, CypherFix autonomous remediation, a deep LLM-safety
  guard stack, and KB-RAG.
- **[pentagi](https://github.com/vxcontrol/pentagi)** — Go autonomous-pentest platform
  (MIT source + a *lawful-pentest* EULA). **Design-only** for us (Go + EULA): its Chain-AST /
  Chain-Summary context engineering, mentor-supervision loop, bi-temporal Graphiti memory, role
  taxonomy, and one-identity observability are reimplemented in Python — not vendored.

## The governing invariant

> Every ported subsystem only **proposes**. Only a CRUCIBLE deterministic **oracle** mints a signed
> FACT; only the conjunctive **gate** authorizes an action; only the **egress gate** lets traffic out.
> No LLM, graph node, productivity verdict, or LLM-judge is ever an authority.

Both source repos treat the LLM (or an LLM-judge, or a graph node) as an authority — exactly what
VIGIL forbids. The fusion attaches their "body" *through* VIGIL's provable layer so nothing becomes
truth or an authorization without the oracle + gate + signed spine.

## Contents

- **[ANALYSIS.md](ANALYSIS.md)** — the fusion-architect synthesis: feature inventory, gap analysis,
  per-capability integration doctrine (C1–C11), the F0–F12 roadmap, licensing + sovereignty risks,
  and the recommended first phase.
- **[SCOUT-INVENTORY.md](SCOUT-INVENTORY.md)** — the full 14-module deep-scout extraction: for each
  area, what it does, the exact reusable abstractions, novel ideas, the VIGIL gap it fills, and the
  provable-layer integration.

The executable plan lives in the plan file (`PROJECT VIGIL-FUSION`); this directory is its evidence
base. Extracted read-only via the GitHub API + raw endpoints (no clone; the sandbox has no bash
network) — a point-in-time snapshot; re-verify a file, symbol, or flag against upstream before relying
on it.

## Licensing

redamon = MIT (Python modules lifted/adapted with attribution + NOTICE). pentagi = MIT + lawful-pentest
EULA, Go (ideas reimplemented, source not vendored). AI-Gauntlet tools (garak Apache-2.0, PyRIT MIT,
Giskard, promptfoo) run as **subprocesses**, keeping their deps/licenses out of VIGIL's process.
