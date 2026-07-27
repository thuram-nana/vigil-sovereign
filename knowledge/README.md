# VIGIL knowledge base

This folder is the **durable, version-controlled knowledge of the whole VIGIL system**. It exists so the
system's knowledge always survives (it is committed and — on explicit operator request — pushed to GitHub),
and so **SIGIL can read it to "know the system"**: its screens, features, agents, and the safety model.

It is a *living* knowledge base — kept current as the system is built.

## What lives here

| Path | Purpose | Written by |
|------|---------|-----------|
| `kb/` | Living prose knowledge: architecture, the two-plane model, the graph/oracle/gate model, agents, features. | Humans + the orchestrator, as the system evolves. |
| `system-map/` | The **machine-readable** screen/nav/feature manifest SIGIL ingests to navigate by voice. `screens.yaml` (human source of truth) → `system-map.json` (generated, committed). | S1 (`tools/system-map/generate.py`); CI drift-checks it against the UI. |
| `skills/{find,detect,prevent}/` | The Knowledge Engine's learned playbooks for a vulnerability — how to **find**, **detect**, and **prevent** it. Loadable by `SkillLoader`. **Advisory only.** | K3 (deep-learn), on operator accept. |
| `decisions/` | ADR-style decision logs — one file per significant design/approval decision. | The orchestrator, on `vigil knowledge sync`. |
| `sessions/` | **Redacted** build-session transcripts, for a durable history of how the system was built. | The orchestrator, on `vigil knowledge sync` (secrets scrubbed before commit). |

## Doctrine — what this folder is NOT

The single most important rule of VIGIL is **oracle authority**: *only a fired deterministic oracle, over data a
real target produced, mints a FACT.* Everything in this folder is knowledge that **advises** — leads, priors,
skills, playbooks, proposals. **None of it is a fact, an authorization, or a detector oracle.**

- A learned skill (`skills/**`) grants **no authority** and confirms nothing. It is a playbook a human or the
  planner may read; the graph counterpart of any learned item is stamped `intel`/`ungrounded`, never `grounded`.
- Committing something here **does not make it true**. Proof still requires a fired oracle over real evidence.
- **Pushing** this folder to a remote is the **only outward-facing act** in the whole knowledge flow, and it is
  **always explicit and operator-gated** (`vigil knowledge push`). No agent and no automation ever pushes.

See [`kb/architecture.md`](kb/architecture.md) for the system model this knowledge describes.
