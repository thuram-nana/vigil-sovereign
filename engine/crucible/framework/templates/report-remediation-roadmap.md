# Remediation Roadmap — `<target-name>`

**Engagement window:** `<start>` — `<end>`
**Version:** `1.0`
**Audience:** tech lead, project planner, engineering manager

---

## How to read this

Findings are sorted on two axes: **business impact** (severity +
context) and **engineering effort** (complexity to fix correctly).
The recommended sequencing puts **high-impact / low-effort** first
("quick wins") before tackling **high-impact / high-effort**
("strategic fixes").

Effort sizes:
- **S** (small): one-line code change, config change, or one-file
  edit. Hours.
- **M** (medium): refactor a controller, add middleware, change a
  schema. Days.
- **L** (large): structural change (auth layer, payment integration
  redesign, framework upgrade). Weeks.
- **XL** (extra-large): cross-team or external-dependency. Quarter+.

---

## Sequencing — recommended order

### Tier 0 — Stop the bleeding (within 7 days)

| # | Finding | Severity | Effort | Reason |
|---|---------|----------|--------|--------|
| 1 | 003 — Webhook signature missing | Critical | S | Direct money flow; one-line fix |
| 2 | 007 — Admin default credentials | Critical | S | Public exposure; config change |
| 3 | 022 — No login rate limit | High | S | Active threat (users complaining of ATO) |

### Tier 1 — Close the most-likely attack paths (within 30 days)

| # | Finding | Severity | Effort | Reason |
|---|---------|----------|--------|--------|
| 4 | 014 — IDOR on /order/{id} | High | M | Cross-user data leak; needs middleware |
| 5 | 029 — Race on balance deduction | High | M | Money flow; needs DB lock or transaction redesign |
| 6 | 031 — Mass-assignment on profile update | High | S | One-line allowlist |
| 7 | 035 — Stored XSS in support tickets | Medium | M | Output-encoding pass + WAF rule |

### Tier 2 — Hardening (within 90 days)

| # | Finding | Severity | Effort | Reason |
|---|---------|----------|--------|--------|
| 8 | 044 — Password reset token entropy | Medium | S | CSPRNG swap |
| 9 | 048 — Verbose error messages | Low | S | Error-handler config |
| 10 | 052 — Outdated framework version | Low | M | Framework upgrade |
| 11 | 057 — Missing HSTS preload | Info | S | Header + preload submission |

### Tier 3 — Strategic / structural (12 months)

| # | Finding | Severity | Effort | Reason |
|---|---------|----------|--------|--------|
| 12 | Multiple authz findings → centralize authorization | (cross-cutting) | L | Eliminate the class |
| 13 | Multiple webhook findings → unified verifier | (cross-cutting) | M | Eliminate the class |
| 14 | Output-encoding audit and migration | (cross-cutting) | L | Eliminate XSS class |

---

## Quick wins (high impact, low effort)

These are the fixes the operator should ship first; small code
changes with disproportionate impact.

1. **003 — Webhook signature**: 6 lines of code in one controller.
2. **007 — Admin default credentials**: change credentials, force
   reset, allowlist admin path by IP.
3. **022 — Login rate limit**: enable framework rate-limit
   middleware on `/login`.
4. **031 — Mass-assignment**: add `$fillable` allowlist on User
   model.
5. **044 — Reset token entropy**: replace `mt_rand` /
   `random_string` with `random_bytes(32)`.

## Strategic fixes (high impact, large effort)

These are the structural changes that eliminate entire bug classes
rather than individual instances. The operator may want to schedule
them in parallel with feature work over months, not as one big
project.

1. **Centralize authorization**: introduce a policy / abilities
   layer; every controller goes through it. Eliminates IDOR /
   BOLA / BFLA at the architectural level.
2. **DB invariants for money**: `CHECK` constraints + `UNIQUE`
   constraints + transactional wrapping. Defends against entire
   classes of business-logic bugs at the data layer.
3. **Output-encoding audit**: audit and replace every `{!! !!}` /
   raw output. Lift template engine's auto-escape coverage.
4. **Logging / alerting platform**: centralized audit log +
   alerting on suspicious patterns. Defends against the class of
   "we wouldn't have noticed."
5. **CI/CD hardening**: OIDC federation, SBOM, signed artifacts,
   pinned deps, dependency confusion guardrails.

## Dependencies between fixes

| Depends on | Then |
|------------|------|
| 003 (webhook signature) | 029 (race on balance) — webhook fix changes balance-flow surface |
| Centralized authz layer | 014, 027, 033 (IDORs) become trivial to fix once layer exists |
| DB invariants on deposits | Any future webhook / payment integration is defended by default |

## Defensive recommendations beyond fixes

In addition to fixing findings, the operator should:

- **Logging**: ensure every privileged action is auditable. Today
  much is silent.
- **Monitoring**: alert on credential-stuffing patterns, unusual
  admin activity, mass-data exports, failed-webhook patterns.
- **Backup / DR**: confirm backups exist, are tested for
  restoration, and aren't reachable from compromise of the live
  app.
- **Continuous testing**: cadence per playbook 25.
- **Threat-model review**: when major features are added.

## Risk-accepted items

| Finding | Operator's reasoning | Compensating controls | Re-evaluate |
|---------|---------------------|----------------------|-------------|
| 058 — Outdated CDN dependency | Vendor planned upgrade in Q2 | WAF rule blocks known exploit | After Q2 release |

## Will-not-fix items

| Finding | Operator's reasoning |
|---------|---------------------|
| 062 — `Server` header version disclosure | Considered low risk vs. ops cost |

---

## Summary

| Tier | Count | Total effort | Window |
|------|-------|--------------|--------|
| 0 (stop bleeding) | 3 | 1–2 dev-days | 7 days |
| 1 (close paths) | 4 | 5–10 dev-days | 30 days |
| 2 (hardening) | 4 | 4–8 dev-days | 90 days |
| 3 (strategic) | 3 | 6–12 dev-weeks | 12 months |
| **Total** | **14** | | |

The operator's investment per tier is roughly an order of magnitude
lower than the prevented loss the tier represents.
