# ADR 0002 — One AWS platform: zones, orchestration and placement (E2)

**Status:** Accepted

## Context

AEGIS runs as the defensive section of the one VIGIL platform. The owner's decision
E2 settles how it is hosted: one unified platform on AWS, with isolation handled
internally rather than by shipping separate products. An earlier hosting memo had
drafted the control plane onto EKS; E2 supersedes that for this program. This ADR
records the platform shape — the zone model, the orchestration substrate, and how
units are placed — and fixes the status of the kernel-isolation question (H1/D7).

## Decision

**E2 — one unified VIGIL platform on AWS.** One control plane, tenant model, RBAC,
billing, customer interface and deployment. Isolation is internal, by zones. No
Kubernetes, streaming platform or graph database without a measured need; services
are long-lived systemd units or containers.

**Zones (plan §4.1).** Each zone gets its own subnets/security groups, a
permission-bounded IAM role, its own KMS key and its own egress:

| Zone | Role | Holds |
|------|------|-------|
| Z1 — AWS edge | Shield + CloudFront, one distribution tenant per host | viewer certs (AWS custody); per-`(org,host)` edge secret |
| Z2E — enforcement | the unit: front + gateway (an HA pair across AZs for Defend); a per-host egress broker; a keyless, payload-free origin prover | that tenant's report/pseudonym/origin credentials via `LoadCredential`; **no viewer keys, no cloud credentials** |
| Z2W — workers | ingest receiver, connector pollers, detection jobs | short-lived broker credentials |
| Z2X — actuation | credential broker, defensive executor | KMS-sealed provider credentials (Z2X role only) |
| Z3 — control plane | provisioner, spine, drains, folds, reconciler, placement, billing, RBAC, verifier judge | the owner key (vault + KMS KEK) |
| Z3R — relay | keyless file relay | nothing |
| Z4 — offensive sandbox | all payload-bearing probes (may sit behind its own account) | offense credentials; egress disjoint from defense |

The control plane never has traffic initiated into it from the enforcement zones; it
pulls and pushes through the keyless relay with regular files only. Payload-bearing
probes originate only in Z4. TT-STG uses the same layout in a separate staging
account — environment separation, not a product split.

**Request path (plan §5).** viewer → Shield/CloudFront → VPC origin → internal cell
ALB → unit front (verifies the per-tenant edge secret) → unix socket (`SO_PEERCRED`)
→ gateway → per-host egress broker → locked origin. Edge and the unit see plaintext;
this is stated plainly in the trust statement.

**Orchestration.** EC2 with systemd units (or containers) plus a reconciler,
reusing the existing unit file and OIDC/SSM pattern. The new orchestration code is
stated, not hidden. ECS/Fargate is carried as the measured alternative under D7.
Delivery is CloudFormation; staging auto-deploys; production is owner-dispatched in
a protected environment.

**Placement.** A new record class reuses the proven `shard_assignment.py` mechanics;
the existing v1 assignment record stays frozen (`extra="forbid"`, one per tenant).
Routes to units are compiled from grants × placement into per-`instance_id` target
groups. Storage is a file spool, one signed event spine and a per-tenant key locker
— no streaming or graph database.

**Kernel isolation is an R1-gate analysis item, not a build dependency (D7).** The
choice between a shared hardened kernel with a host cap and patch SLA, an
ECS/Fargate task per unit, and a dedicated host is decided by analysis at the R1
gate. H1 records TT-STG start time, p99 latency, cost and new-code size to inform
it. Co-location of tenant units is therefore gated at R1; it is not a prerequisite
for the isolation and enforcement slices, which stand on per-unit uids, read-only
mounts and broker-mediated egress regardless of the kernel decision.

## Consequences

- The EKS control-plane draft is superseded; the memo's sandbox, egress and custody
  design remains the Z4 reference.
- One key per zone, disjoint egress per zone and one customer interface are now
  invariants that acceptance checks (analyzer scans, EIP-set disjointness) enforce.
- Orchestration, placement and the reconciler are net-new code; they are declared
  and tested rather than folded silently into existing modules.
- The R1 kernel decision can change the co-location story without reopening the
  enforcement design.

## References

- Plan §0.1 (E2), §4.1 (zones), §5 (hosted architecture), §14.2 (D7).
- ADR 0001 (scope), ADR 0005 (evidence).
