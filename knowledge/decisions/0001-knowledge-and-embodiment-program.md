# ADR 0001 — Permanent sessions, per-session knowledge graph, SIGIL embodiment, and a self-evolving knowledge engine

- **Status:** Accepted
- **Scope:** VIGIL (`/home/kali/vigil`, repo `thuram-nana/vigil-sovereign`)

## Context

The operator asked for a large, joined-up capability set: permanent/organized engagement sessions
(open/rename/delete/manage-several); the whole system's knowledge in a committed repo folder (this folder);
SIGIL that fully knows the system and **navigates by voice**, supports **gesture control**, and shows a **small
on-screen HUD**; a **per-session knowledge graph on cloud Neo4j** with a **session-connect** button; **agents
that talk to one another**; and a **self-evolving vulnerability-intelligence engine** (auto-updating feed,
propose-to-learn/accept, deep find/detect/prevent, manual add + point-at-URL learning, one managing screen, and
a gated self-evolve loop).

Exploration (three parallel Explore agents + three Plan agents) found that **most primitives already exist but
are disjoint, offline-only, or backend-only** — the work is mostly joining, exposing, adding a live tier, and
building the genuinely-missing session/graph-wiring/nav/HUD/feed pieces.

## Decision

Build the program in phases, each slice `build → adversarial red-pen → re-check → CI → merge`:

- **Phase 0** — this knowledge-folder scaffold.
- **Phase F** — Foundation: F1 cloud-Neo4j credentials + driver-factory + auto-connect; F2 unified permanent
  session registry (rename/soft+hard delete/multi); F3 per-session Neo4j graph (session id as partition key);
  F4 session-connect (read-time partition union, provenance-tagged).
- **Phase S** — SIGIL embodiment: S1 system-knowledge manifest; S2 voice→screen navigation; S3 gesture nav;
  S4 the small HUD; S5 agent-to-agent directed messaging.
- **Phase K** — Knowledge Engine: K1 auto-updating vuln feed; K2 propose/accept/activate-deactivate/STOP;
  K3 deep-learn find/detect/prevent; K4 manual-add + point-at-URL learning + the one managing screen;
  K5 gated self-evolve; K6 the knowledge folder → GitHub.

## Locked operator decisions

- **Knowledge folder** = living KB + decision logs + redacted build-session transcripts.
- **Neo4j** = cloud/remote auto-connect (a remote `bolt/neo4j+s://` URI + user + password in Settings; tested +
  connected on deploy). Local docker Neo4j is a dev-only fallback.
- **Build all clusters** (phased).
- **Self-evolve = gated + honest** — learns/proposes autonomously; learned knowledge is **leads/skills/priors,
  never oracle-confirmed facts**; new detections/solutions and any framework change require operator **accept**;
  activate/deactivate + **stop** always honored; **only a fired oracle mints a FACT**.

## Consequences / invariants preserved

The **two-env boundary (FATAL-2)** and **oracle authority** hold at every seam. The per-session graph and
session-connect are **projection-only** (never a source of truth, never a shared live handle across the
boundary, never a read-back of a grant/tier). Every outbound fetch routes through the egress gate. "Predict
future weaknesses" is **bounded**: deterministic horizon-scanning over *disclosed* CVEs + coverage-gap
synthesis + calibration, producing **gated proposals** — not autonomous forecasting and not self-applied change.

The full plan is tracked in the operator's planning file (`parsed-popping-lemur.md`).
