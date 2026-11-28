# AEGIS AS-34 - production rollout procedure

The staged, health-gated procedure for bringing the AEGIS production platform
(`infra/aws/aegis-production/*.cfn.yaml`) to a live, serving state. It is the production counterpart of the
AS-26 staging bringup (`infra/aws/aegis-staging/README.md`), and it is an **operator runbook**, not a CI
step: there is no live production AWS account in the merge pipeline, so every step below is a production
operator action. The invariants it rests on are proven offline (the `aegis-infra` advisory job and the P5
integration job); this document says how to apply them for real without an outage and without ever opening
an origin that is not provably healthy.

No step here creates or calls a real AWS resource from CI. The templates are declarations; applying them is
owner work.

## 0. Preconditions (all must hold before stack apply)

1. **Staging is green.** AS-26 staging is applied and the AS-1b TT-STG acceptance has a signed record
   (`engine/crucible/framework/v2/evidence/aegis_tt_run.py`). Production never leads staging.
2. **Licence / ledger gate is green.** The AS-7a deploy-time licence/ledger check passes for the target
   tenants. The `aegis-production-ledger-check-failed` alarm (template 30) pages and holds the rollout if
   it ever flips during the run.
3. **Owner and release roots are provisioned with hardware MFA.** The `owner` and `release` KMS roots
   (template 10) are created and their admin paths are reachable only with a hardware MFA device. The
   templates *require* MFA; the sign-in is this step.
4. **Images are pinned by digest.** The bringup SSM document (`aegis-production-bringup`) accepts a
   `sha256:...` image digest only (AS-28 `Dockerfile.saas`), pinned by the reconciler.

## 1. Apply the platform stacks in order (00 -> 10 -> 20 -> 30)

The four templates are independent stacks wired by parameters. Apply them in order, feeding each stack's
outputs into the next stack's parameters:

| Order | Stack | Key outputs to carry forward |
|---|---|---|
| 1 | `00-network-zones` | `VpcId`, `Z2ESubnets` (for the ALB), the disjoint EIP sets |
| 2 | `10-keys-roles-ssm` | `OwnerKeyArn`, `ReleaseKeyArn`, `ImdsV2LaunchTemplateId`, `ZoneRoleBoundaryArn` |
| 3 | `20-edge-cloudfront` | `Tenant*DistributionId`, `OriginHopCAArn`, `ProductionHostedZoneId` (takes `VpcId` + `AlbSubnetIds` from stack 00; set `ViewerCertificateArn` to the real ACM cert) |
| 4 | `30-ops-relay-paging-drift` | `PagingTopicArn`, `Z3RRelayRoleArn`, `ProductionDeployRoleArn` (set `ExistingOIDCProviderArn` to enable CD) |

After stack 00, run a live **Reachability-Analyzer** path check to confirm Z4 has **no** network path into
the defense zones (B-5). After stack 30, turn the AWS Config recorder on and run a **CloudFormation
drift-detection** pass to set a clean baseline; the `aegis-production-cfn-stack-drift` rule then routes any
later drift to paging.

## 2. Arm paging and drift BEFORE any traffic

Confirm the `aegis-production-paging` SNS topic has a live subscription, the relay-staleness and
ledger-check alarms are in OK state, and the drift rule is COMPLIANT against the just-set baseline. A manual
edge change from here on pages (T-INS). Do not proceed to a health-gated rollout with paging dark.

## 3. Health-gated worker rollout (AS-6a placement, AS-6e rolling)

Workers are converged by the AEGIS fleet reconciler, never by hand:

1. The AS-6a placement/reconciler compiles the desired FleetState (grants x placement) and drives each
   worker through the `aegis-production-bringup` SSM document (SSM-only; no SSH).
2. The AS-6e **rolling** reconcile (`VIGIL_AEGIS_FLEET_ROLLING`) converges the fleet in deterministic
   `max_surge` batches, admitting the next batch only once the prior batch's workers report **HEALTHY**.
   A batch that does not land healthy halts the roll; it does not proceed and does not retire the prior
   workers.

## 4. Bind the edge only at HEALTHY units (AS-6c edge reconciler)

The per-tenant CloudFront distributions are bound to live origins by the AS-6c `EdgeReconciler`
(`VIGIL_AEGIS_EDGE`), over the FleetState from step 3. For each tenant, in canary order:

1. The reconciler provisions/rotates the per-(org,host) edge secret (template 20) and binds the tenant
   distribution's origin to the gateway unit AS-6a has proven HEALTHY. An unproven or unhealthy backing
   unit **refuses** the bind; a secret that cannot be provisioned **refuses** the open (fail-closed, the
   origin is never opened without a provisioned secret).
2. A rollout binds the **new** origin before draining the old; a retire drains the old before teardown. The
   ALB connection draining makes the swap graceless-free.

Promote one canary tenant, confirm the delivered edge page over the real CloudFront -> VPC origin -> ALB
path, confirm a direct-to-origin request (no edge secret) is refused at the front, then promote the rest.

## 5. Enable production CD (optional, last)

Set `ExistingOIDCProviderArn` on stack 30 and the production deploy variables to wire the
`ProductionDeployRole` (GitHub-OIDC, scoped to `ssm:SendCommand` against the production bringup document
only; no SSH, no long-lived keys). Until then CD is inert
(`LIMIT-aegis-production-cd-inert`).

## Rollback and break-glass

- **A batch fails to land healthy.** AS-6e has already halted; the prior workers are untouched and still
  serving. Re-pin the previous image digest and re-run the batch, or hold.
- **The edge is misbehaving.** The AS-6c reconciler re-binds the tenant distribution's origin to the last
  HEALTHY unit (new-before-drain), so a bad origin is swapped out without dropping the viewer path.
- **Containment.** The AS-27a break-glass cuts enforcement to a safe state; it is an owner act, logged and
  paged.
- **Drift.** A live edge change outside the templates pages via the drift -> paging route; reconcile the
  stack back to its template (the recorded baseline) before continuing.

## What stays deploy-gated (owner work, not this slice)

The live apply, the MFA hardware sign-in, the delivered edge page, the live drift detection and the
production CD are owner-provisioned and are registered honestly in `docs/limitations/inventory.json`
(`LIMIT-aegis-production-stack-not-applied`, `LIMIT-aegis-production-cd-inert`). This slice ships the IaC
and this procedure, proven in-repo by the CFN analyzers and the offline posture/relay tests; the deployed
unit guarantee is the operator's.
