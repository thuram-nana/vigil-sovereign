# docs/pilot — Pilot runbooks

Operator-facing runbooks for controlled pilots. Each phase has a goal, the commands, and the expected result
that constitutes a pass — grounded in the actual CLI verbs so it cannot drift.

- [**Claim 6 — Multi-User Pilot Runbook**](claim-6-pilot-runbook.md) — provision accounts/roles, bring up
  the shareable command UI, exercise the RBAC boundary, run a governed engagement, take an off-host backup +
  recovery drill, and revoke/kill. Maps each result back to the
  [audit dossier](../audit/claim-6-rbac-dossier.md). Requires a filled-in
  [charter](../../targets/_template/charter.md) for any live engagement phase.
