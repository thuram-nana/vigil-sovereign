# VIGIL — system architecture (living KB)

This is the human-readable map of the system. It is the prose companion to the machine-readable
[`../system-map/`](../system-map/) manifest that SIGIL reads.

## The two planes (the LOCKED safety boundary)

VIGIL runs as **two isolated processes that never co-load in one interpreter** (a violation is `FATAL-2`):

- **Sovereign plane** — `.venv-sovereign` (holds the owner key). Code: `apps/sigil` + `packages/core/vigil_core`
  + `integration`. This is SIGIL: voice, gesture, the owner-signed action broker, settings/secrets, the
  Kùzu knowledge-graph memory + Qdrant vectors + the `sigil-memory` MCP server.
- **Offense plane** — `.venv-offense` (keyless). Code: `engine/crucible` + `vendor/strix` + `gateway` +
  `integration`. This is CRUCIBLE: crawling, oracles, the world-model, the intel feed, the Neo4j projection.

`vigil` (`integration/vigil_integration/cli.py`) is the only cross-plane orchestrator; it dispatches by
**subprocess only**. The two planes bridge **only through the signed, append-only spine** (or a shared
**immutable committed file**, which is data, not a live handle). They never share a live DB/agent handle.

The unified UI (`packages/vigil-ui`) is served over one origin by a stdlib reverse proxy (`vigil up`,
`integration/vigil_integration/uiproxy.py`): `/sovereign/*` → the SIGIL cockpit, `/offense/*` → the CRUCIBLE
console. Never a public bind; strict `'self'` CSP.

## Oracle authority (the truth model)

Only a **fired deterministic oracle**, re-executing over retained evidence a real target produced, mints a
**FACT**. The LLM advises where to look and what a result might mean; the oracle confirms. Critics, learning,
reflection, and self-consistency may only *advise, re-rank, defer, or abstain* — never promote a finding.
Learned/retrieved/fed knowledge is a **lead / prior / skill / proposal**, stamped at write by
`worldmodel/models.py classify_provenance` (`intel`/`ungrounded`, never `grounded`).

## The knowledge graph (projection, never source of truth)

The offense world-model is a typed attack graph (`engine/crucible/framework/v2/worldmodel/`). It is projected
**one-way** into Neo4j (`integration/vigil_integration/live/graph_neo4j.py`) as an audit/read model: nothing
reads a tier or grant back from the graph, and a `:Confirmed` node requires a signed `evidence_ref` or is
dropped fail-closed. The graph is scoped by a free-string partition key — per engagement, and (this program)
per **session**.

## The gate (authorization model)

Target-touching, destructive, live-cloud/-fetch, install, input-injection, and open-PR steps **queue for owner
approval** (WARDEN / approve-then-run). Nothing self-authorizes. A kill-switch and a never-liftable floor
always win. Capability latches gate optional autonomous behavior (voice, gesture, autonomous learning).

## Where this program adds

See [`../decisions/0001-knowledge-and-embodiment-program.md`](../decisions/0001-knowledge-and-embodiment-program.md)
for the approved program: permanent sessions, a per-session Neo4j knowledge graph with session-connect, SIGIL
voice/gesture navigation + an on-screen HUD, agent-to-agent messaging, and a gated self-evolving
vulnerability-intelligence engine.
