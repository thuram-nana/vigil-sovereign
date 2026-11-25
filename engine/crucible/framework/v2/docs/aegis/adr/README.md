# AEGIS Architecture Decision Records

This directory holds the Architecture Decision Records (ADRs) for AEGIS — the
defensive section of the one VIGIL platform operated by SIGIL SARL. Each ADR
captures one decided architectural choice: the context that forced it, the decision
itself, and the consequences that follow. They are the governance foundation
(slice AS-0) for the AEGIS SaaS production program.

## What an ADR is here

Each record follows the standard form — **Title, Status, Context, Decision,
Consequences** — and is grounded in the AEGIS SaaS production plan. Status is
**Accepted** for every record below: these are owner decisions (E1–E3) and the
architecture reconciled around them, not open proposals. Open decisions and external
prerequisites are tracked in the plan (§14), not here.

## Publication rule

`vigil-sovereign` is a public repository. These ADRs record **fixed-state
governance** — decided architecture and the mitigations in place. They describe the
*decision* and the *mitigation*, never an unfixed weakness, an exploit recipe, or an
un-shipped attack technique. This follows the plan's publication split (§4.7): the
public repository carries only fixed state; open items live in private operations.

## Index

| ADR | Decision | Summary |
|-----|----------|---------|
| [0001](0001-scope.md) | **E1 — scope** | Full production system, not an MVP: every engine, every supported path, isolation, fairness, operations, self-security and the rollout procedure. DONE = proven end to end through VIGIL on staging (TT-A, TT-B control) with a signed record; "Blocked" only for external prerequisites. |
| [0002](0002-H1-zones-orchestration-placement.md) | **E2 — one AWS platform** | One unified platform on AWS, isolation internal by zones (Z1 edge … Z4 sandbox). EC2 + systemd + a reconciler; placement reuses the frozen shard-assignment mechanics. Kernel isolation (D7) is an R1-gate analysis item, not a build dependency. |
| [0003](0003-E1-engines.md) | **E1 — engines** | Which engines SIGIL operates and the evaluation bar each clears; engines run only per active connection; third-party rule hits are leads, not standalone blocks; service-vs-distribution licence posture, enforced by the licence gate. |
| [0004](0004-E3-competitive.md) | **E3 — competitive** | Rent the pipes (CloudFront + Shield edge, not an enforcement point), bring path 1b forward (Cloudflare first); differentiate on exploit-proven virtual patching and signed, offline-re-verifiable outcomes; every comparative claim earned by a signed benchmark. |
| [0005](0005-EV-evidence.md) | **EV — evidence** | The evidence/DONE-record model: the signed, offline-re-verifiable AS-25 record, why the claims registry cannot hold DONE, and the ten-question validator each claimed protection must answer. |

## Related documents

- [`../AEGIS-DESIGN-RESEARCH.md`](../AEGIS-DESIGN-RESEARCH.md) — the unified design
  document (detection pipeline, threat model, CRUCIBLE reuse).
- [`../AEGIS-DOCTRINE-CRITIQUE.md`](../AEGIS-DOCTRINE-CRITIQUE.md) — doctrine review.
- [`../AEGIS-CRUCIBLE-REUSE-MAP.md`](../AEGIS-CRUCIBLE-REUSE-MAP.md) — what is reused
  from CRUCIBLE vs. net-new.
- [`../AEGIS-SIGNAL-CATALOG.md`](../AEGIS-SIGNAL-CATALOG.md) — the detection/signal
  catalogue.
- [`../DEPLOYMENT.md`](../DEPLOYMENT.md) — the honest-promise deployment guide.
