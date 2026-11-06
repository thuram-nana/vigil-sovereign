# AEGIS-SaaS flag hold

**Status: HOLD. Both flags stay OFF. This runbook does not flip anything.** It records what the flags gate
and the criteria that must all be met, with evidence, before an owner flips one in a governed deployment.

## The flags

| Flag | Default | Plane | Gates |
|---|---|---|---|
| `VIGIL_CUSTOMER_MONITORING_ENABLED` | OFF | sovereign (sigil) | tenant-facing monitoring authorize/revoke/list (and the events read) via `Provisioner.monitor_*` and `/api/customer/monitoring*` |
| `VIGIL_AEGIS_SAAS_ENFORCE` | OFF | tenant gateway | hard blocking by a tenant-bound gateway. With it OFF a BLOCK grant still only observes |

A tenant gateway hard-blocks only when **all** of these hold for the request: a verified BLOCK-mode monitoring
authority for (tenant, the gateway's fixed protected host), `VIGIL_AEGIS_SAAS_ENFORCE` on, gateway mode
`enforce`, the `AEGIS_RESPOND` entitlement, an untripped kill-switch, and a confirmed certificate verdict.
If there is no valid authority, the request passes through uninspected.

## Flip criteria for `VIGIL_CUSTOMER_MONITORING_ENABLED` (observe only)

1. `integration/tests/test_aegis_saas_acceptance.py` passes in the CI offense leg (it is listed there) with
   no skips (`-rs` output names none for this file).
2. AE-0..AE-6 suites are green on the release commit: the sovereign registry, provisioner monitoring, and
   monitoring-spool drainer suites, plus the aegis gateway suites (`framework/v2/aegis/tests`).
3. Monitoring billing (AE-5) is live: `monitor_authorize` refuses without an active plan with a free host slot.
4. A managed deployment (AE-6) has run in staging with the report secret loaded from a 0600 file and the
   drain verb run on schedule. Drained events show up only under the owning tenant.
5. Red-pen review of the end-to-end path shows 0 open HIGH/MED findings.
6. The owner signs off in writing. The flip is recorded as a deployment change and can be rolled back by
   unsetting the variable.

## Additional flip criteria for `VIGIL_AEGIS_SAAS_ENFORCE` (blocking)

Only after the monitoring flag has been ON in production, and in addition to everything above:

1. Observe-mode false-positive review: over a sustained production observation period, every confirmed
   verdict that would have blocked was reviewed and found to be a true positive.
2. Kill-switch drill: tripping the kill-switch turns blocking into pass-through on a live gateway, with the
   result recorded.
3. Revoke drill: after `monitor_revoke`, the next request passes through uninspected, with the result recorded.
4. Block grants need a plan tier that includes respond (AE-5), and enforcement is checked against that tier.
5. Enable it per deployment, never fleet-wide in one step. Each tenant's admin must have explicitly granted
   `mode=block`.

## Rollback

Unset the flag and restart the affected service. Revoking a grant (`monitor_revoke`) unpublishes the
authority, so the gateway stops inspecting that host on the next request with no restart needed.
