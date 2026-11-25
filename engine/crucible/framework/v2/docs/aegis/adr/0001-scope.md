# ADR 0001 — AEGIS scope: full production system (E1)

**Status:** Accepted

## Context

AEGIS is the defensive section of the one VIGIL platform operated by SIGIL SARL. It
is never a separate product, account or deployment. The AEGIS production
specification is a 28-section document; against it the owner issued a scope
correction (SIGIL-operated SaaS; no on-prem or sovereign packaging) and three
decisions, E1–E3. This ADR records E1 — the scope and the completion bar. E2
(platform, ADR 0002) and E3 (competitive posture, ADR 0004) are recorded
separately.

The baseline the program starts from is one partially built path — an inline
gateway per `(org, host)` using VIGIL's deterministic oracles — hosted nowhere and
below the production bar. E1 fixes what "done" means so that no capability is
declared complete on the strength of installed-but-unproven code.

## Decision

**E1 — build the full production system, not an MVP.**

- **In scope.** Every engine SIGIL operates (ADR 0003). Every supported connection
  path: 1a managed gateway, 1b the customer's existing CDN/WAF, 2 cloud/identity,
  3 runtime, 4 network — path 4 only where a real observation and enforcement point
  exists. Tenant isolation and capacity fairness. Operations: monitoring, upgrade,
  rollback, capacity, on-call. Self-security. **The production rollout procedure
  itself** is a deliverable, not a side effect.
- **Sequence.** Build each capability to production grade → prove it end to end on
  an isolated staging test tenant (TT-STG) → go live only at an explicit owner gate.
- **Out of scope by this correction.** The offline/sovereign profile, offline
  bundles and air-gap content handling; the customer-installed gateway, middleware/
  SDK and console setup. These would be distribution rather than hosted service;
  the code stays byte-identical and is marked `not offered` rather than deleted.
- **"Blocked" is reserved.** A capability may be marked Blocked only for an external
  prerequisite that has a reproducible verification step (ADR 0001 defers the list
  to the plan's §14.3: counsel rulings, AWS quotas, provider test tenants, and
  tenant authorization for real-tenant outcome verification). Nothing is left
  unbuilt as "demand-driven"; paths 2 and 3 carry committed defaults.

**The DONE standard (plan §13.1).** A capability is DONE when:

- TT-A uses it end to end **through VIGIL** — the authenticated customer API plus
  the browser — with TT-B as the co-located cross-tenant control;
- the run is on TT-STG built from merged infrastructure-as-code, at production
  grade, and is proven by a signed evidence record (the AS-25 record, ADR 0005);
- acceptance covers operations, isolation, fairness, runbooks and failure
  behaviour, not just the happy path.

An installed engine or adapter is **never** DONE on its own. Go-live is a separate
owner act, distinct from DONE.

## Consequences

- E1 supersedes the 2026-11-16 "no server/VPS work" directive **for this program
  only**; the prior Contabo hosting track stays out of scope.
- Every production stage (R1 Observe → R2 Defend → R3 slow path / virtual patching
  → R4 paths 2/3/4) still requires an explicit owner go-ahead. Recording this plan
  does not authorize go-live.
- Because DONE is defined by an end-to-end run through VIGIL plus a signed record,
  progress cannot be overstated: a slice that compiles, or whose engine is
  installed, reads as "implemented but not validated" until its record exists
  (the five states, plan §13.7).
- The completion bar is uniform across engines and paths, so operations, isolation
  and fairness are first-class acceptance criteria rather than later hardening.

## References

- Plan §0.1 (E1), §0.2 (scope reshaping), §13.1/§13.4 (DONE and the E1 bar),
  §13.7 (states), §14.3 (external prerequisites).
- ADR 0002 (platform), ADR 0003 (engines), ADR 0005 (evidence model).
- `../AEGIS-DESIGN-RESEARCH.md`, `../AEGIS-DOCTRINE-CRITIQUE.md`.
