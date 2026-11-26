# AEGIS AS-26 (OPS-1) — staging infrastructure

This directory holds the AEGIS staging CloudFormation templates and is the operator guide for applying
them. It is **staging-only** and, like the rest of AS-26, ships **merged but not applied**: the templates
are deployment *declarations* that are analyzer-clean and posture-checked offline, but there is no live
staging AWS account in the merge pipeline, so CI never applies them. Applying the stack, and the live
checks that only a running stack can prove, is a staging operator action.

## What is OFFLINE-tested (in the `aegis-infra` advisory job and the P5 integration job)

- **cfn-lint clean** over every template here and `../github-oidc-deploy-role.cfn.yaml`.
- **AS-26 CFN posture** (`integration/vigil_integration/aegis_infra_lint.py`): IMDSv2 enforced on the
  launch template; the defense and `z4-offense` EIP sets are disjoint (B-5); the test owner and test
  release KMS roots deny admin without MFA; the Z3R relay role denies `kms:Decrypt` /
  `secretsmanager:GetSecretValue` (keyless, R3); no security group opens `0.0.0.0/0`; paging (SNS, D32) and
  CloudFormation drift detection (the AWS Config managed rule) are present; each tenant CloudFront
  distribution fronts the ALB through a VPC origin and injects the per-tenant edge secret.
- **Z3R relay guards** (`integration/vigil_integration/aegis_relay_guard.py`, tested in
  `integration/tests/test_aegis_relay_guard.py`): relay EACCES on the vault; hostile file names cannot
  escape the landing dir; an unauthenticated transport is refused; a CloudFront bypass (direct-to-origin)
  is refused.

## What is DEPLOY-GATED (a live staging apply, not verified in CI)

Registered honestly in `docs/limitations/inventory.json`
(`LIMIT-aegis-staging-stack-not-applied`, `LIMIT-aegis-staging-cd-inert`):

- **MFA console sign-in** with a hardware MFA device against the test owner / test release roots. The
  templates *require* MFA (the offline posture proxy); the sign-in itself needs the live account.
- **The delivered edge page** over the real CloudFront -> VPC origin -> ALB path, Shield association, and
  live viewer-TLS termination with AWS-custody keys.
- **Live CloudFront-bypass refusal at the edge** (the front verifying the edge secret, the ALB SG admitting
  only the VPC origin). The guard logic is offline-tested; the live enforcement needs the running stack.
- **Live CloudFormation drift detection** and the drift -> paging route (the AWS Config recorder must be on
  in the account).
- **Staging CD**: `StagingDeployRole` is inert until the operator sets the OIDC provider ARN and the
  staging deploy variables; the TT-STG staging deploy runs are AS-1b's.

## Templates

| File | Contents |
|---|---|
| `00-network-zones.cfn.yaml` | VPC, per-zone subnets + SGs (Z2E/Z2W/Z2X/Z3/Z4), **disjoint EIP sets** (defense NAT vs Z4), route tables, IAM Access Analyzer. |
| `10-keys-roles-ssm.cfn.yaml` | Per-zone KMS keys, **test owner** + **test release** roots (MFA-gated), permission-bounded zone roles, **IMDSv2** launch template, SSM bringup document. |
| `20-edge-cloudfront.cfn.yaml` | Route 53 **test** zone, keyless origin-hop cert issuer (ACM PCA), per-(org,host) edge secrets, internal ALB + target groups, **VPC origin**, 2 tenant **CloudFront + Shield** distributions, origin-request policy (Host + CloudFront-Viewer-Address). |
| `30-ops-relay-paging-drift.cfn.yaml` | **Z3R keyless relay** role, egress-broker denylist pin, **SNS paging** (D32), CloudWatch alarms (relay staleness, ledger check), **AWS Config drift** detection routed to paging, **staging-only CD** OIDC role. |

## Applying it (staging operator)

The templates are independent stacks wired by parameters; apply in order (00 -> 10 -> 20 -> 30), feeding
each stack's outputs as the next stack's parameters. All intrinsics are long-form so the repo's `check-yaml`
hook parses the templates as plain YAML. After apply, run a live Reachability-Analyzer path check to confirm
Z4 has no network path into the defense zones (B-5), and a CloudFormation drift-detection run.

The relay (`tools/z3r/z3r-relay.sh`) is pinned-rsync, `--no-links`, fixed landing dirs, keyless; it calls the
guard module before moving a byte. Run it on the Z3 relay host with an ssh identity + pinned known_hosts.
