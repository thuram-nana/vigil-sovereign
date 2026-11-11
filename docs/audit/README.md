# docs/audit — Assurance dossiers

Auditor- and reviewer-facing assurance documents. Each dossier states a claim, names the code/test/command
that proves it, and states its residuals plainly — no claim the code does not enforce.

- [**Claim 6 — Enforced Multi-User RBAC: Audit Dossier**](claim-6-rbac-dossier.md) — the RBAC model, the
  per-user command-UI boundary, the protected-domain guard (a global fail-safe-on toggle), the operational
  integrity delivered alongside it, and an independent-verification checklist. Companion runbook:
  [`docs/pilot/claim-6-pilot-runbook.md`](../pilot/claim-6-pilot-runbook.md).
- [**CodeQL triage — 2026-11-10 (CQ-1)**](CODEQL-TRIAGE.md) — how every critical and every non-path high CodeQL
  result was handled: what was fixed, what is by design (with a checkable rationale for an owner "won't fix"
  dismissal), which deliberately-vulnerable benchmark fixtures await an owner scope decision, and what is not
  yet triaged in depth.
