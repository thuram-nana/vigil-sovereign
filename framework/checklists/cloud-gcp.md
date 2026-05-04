# GCP Engagement Checklist

For testing applications hosted on Google Cloud Platform. Pairs with `13-cloud-native.md`.

> **Authorization gate:** GCP does not require advance notification for
> testing your own infrastructure (no permission form, unlike AWS).
> However, abusing shared services (G Suite/Workspace, Google's own
> infrastructure) is out of scope. Confirm in `charter.md`.

## Pre-Test

- [ ] GCP project ID(s) for target documented in `scope.md`
- [ ] Organization / Folder / Project hierarchy understood
- [ ] Service Account JSON key OR `gcloud auth login` provisioned for posture-assessment
- [ ] Source IP recorded
- [ ] Cloud Audit Logs enabled (so engagement is auditable)

## Identity & Access (Cloud IAM)

### IAM Bindings
- [ ] No bindings with `roles/owner` outside intended admins
- [ ] No bindings with `roles/editor` (overly broad on most resources)
- [ ] No `allAuthenticatedUsers` or `allUsers` principals on sensitive resources
- [ ] No service accounts with primitive (Owner/Editor/Viewer) roles
- [ ] No user accounts directly granted resource-level permissions (use groups)

### Service Accounts
- [ ] List service accounts (`gcloud iam service-accounts list`)
- [ ] No legacy keys (created before 2020 — no key creation timestamp visible can mean ancient)
- [ ] Default service accounts (`-compute@developer.gserviceaccount.com`) have minimal scope or are disabled
- [ ] Service account keys rotated — flag keys older than 90 days
- [ ] Service account key creation **disallowed by org policy** (best practice; modern SA usage prefers Workload Identity Federation)
- [ ] Service accounts attached to Compute instances reviewed (instance compromise → SA token theft)

### Privesc Patterns (GCP analog of AWS privesc paths)
- [ ] `iam.serviceAccounts.actAs` on privileged SA + `iam.serviceAccountKeys.create` → escalate via key creation
- [ ] `iam.serviceAccounts.actAs` + `cloudfunctions.functions.create` → execute as privileged SA
- [ ] `iam.serviceAccounts.actAs` + `compute.instances.create` → boot instance as privileged SA
- [ ] `iam.serviceAccounts.implicitDelegation` chains
- [ ] `iam.serviceAccounts.getAccessToken` on privileged SA
- [ ] `cloudbuild.builds.create` with privileged build SA
- [ ] `dataproc.clusters.create` with privileged SA
- [ ] `deploymentmanager.deployments.create` with privileged Deployment Manager SA

## Compute Engine

- [ ] **Metadata server access:** every VM accepts `Metadata-Flavor: Google` requests; check apps for SSRF that can reach `169.254.169.254` or `metadata.google.internal`
- [ ] Metadata service v1 reachable from instance code? (No protection like AWS IMDSv2 token requirement, just header check)
- [ ] No SSH keys at project metadata level (use OS Login or per-instance keys)
- [ ] OS Login enabled (centralized identity)
- [ ] No instances with public IPs unless justified
- [ ] Shielded VM enabled
- [ ] Disks encrypted (CMEK preferred over Google-managed for sensitive)
- [ ] Snapshots not shared publicly
- [ ] No instances with `compute.serviceAccounts.actAs` user role assigned to all SAs

## Networking (VPC)

### Firewall Rules
- [ ] No rules with `0.0.0.0/0` source on ports other than 80/443
- [ ] No rules with `0.0.0.0/0` on 22 (SSH)
- [ ] No rules with `0.0.0.0/0` on databases (3306, 5432, 27017, 6379)
- [ ] No rules with `0.0.0.0/0` on internal services (8080, 9090, 27017 for MongoDB, etc.)
- [ ] Rules use service accounts as targets (preferred over network tags for sensitive workloads)
- [ ] Implicit deny rules confirmed (last-rule deny vs. relying on absence)

### VPC Configuration
- [ ] No default VPC in use for production
- [ ] VPC Flow Logs enabled
- [ ] Private Google Access enabled on private subnets
- [ ] Cloud NAT used for outbound (vs. public IPs on instances)
- [ ] Shared VPC structure documented (host vs. service projects)

## Cloud Storage (GCS)

- [ ] **No public buckets** unless explicitly intentional
- [ ] No bindings to `allUsers` or `allAuthenticatedUsers` outside justified buckets
- [ ] Uniform Bucket-Level Access enabled (disables ACLs)
- [ ] Default encryption: CMEK preferred over Google-managed for sensitive
- [ ] Bucket logging / object access logging enabled
- [ ] Versioning enabled on critical buckets
- [ ] Retention policies configured per data class
- [ ] **Bucket name enumeration:** check `<project>-{backups,assets,logs,exports,functions-source,build}.storage.googleapis.com`
- [ ] Signed URLs reviewed (expiration, scope)
- [ ] No buckets with sensitive default object permissions

## Cloud SQL

- [ ] No instances with `0.0.0.0/0` authorized network
- [ ] Public IP disabled where private IP suffices
- [ ] SSL/TLS connections required
- [ ] Backup automated with retention
- [ ] Default users (`postgres`, `root`) have strong passwords
- [ ] Cloud SQL Auth Proxy used for app connections (avoids direct IP exposure)

## BigQuery

- [ ] Datasets not granted to `allAuthenticatedUsers`
- [ ] Authorized views used to restrict columns
- [ ] CMEK on sensitive datasets
- [ ] Audit logs reviewed for data exfiltration patterns

## Cloud Functions / Cloud Run

- [ ] Cloud Functions: ingress restricted (`internal-only` or `internal-and-load-balancer` where appropriate)
- [ ] Cloud Functions: invoker permissions minimal (no `allUsers` invoker unless intentional)
- [ ] Cloud Run: ingress restricted similarly
- [ ] Cloud Run: invoker `allUsers` only on intentionally-public services
- [ ] Cloud Functions: env vars don't contain plaintext secrets (use Secret Manager)
- [ ] VPC connector configured for internal access only

## Secret Manager

- [ ] Secrets exist (vs. hardcoded in app config / env vars / source code)
- [ ] Access bindings minimal
- [ ] Rotation configured
- [ ] CMEK enabled for high-sensitivity secrets

## GKE — see `cloud-kubernetes.md`

- [ ] GKE clusters audited via dedicated K8s checklist
- [ ] Workload Identity enabled (no node SA usage)
- [ ] Private cluster preferred (no public master endpoint)
- [ ] Network policy enabled
- [ ] Binary Authorization for image provenance

## Cloud Audit Logs

- [ ] Admin Activity logs always-on (cannot be disabled — but check no log routing diversions)
- [ ] Data Access logs enabled for sensitive services
- [ ] Logs exported to a separate logging project (immutability)
- [ ] Sink to BigQuery / Cloud Storage with retention policy

## Identity-Aware Proxy (IAP)

- [ ] IAP used for internal app access (vs. open VPN / public IP)
- [ ] IAP TCP forwarding for SSH instead of public SSH
- [ ] OAuth client configured per workload

## Organization Policies

- [ ] `iam.disableServiceAccountKeyCreation` enforced (or documented exception)
- [ ] `iam.disableServiceAccountKeyUpload` enforced
- [ ] `compute.requireOsLogin` enforced
- [ ] `compute.skipDefaultNetworkCreation` enforced
- [ ] `compute.disableSerialPortAccess` enforced
- [ ] `storage.publicAccessPrevention` enforced (org-wide block on public buckets)
- [ ] `storage.uniformBucketLevelAccess` enforced

## Run Scanners

- [ ] `scoutsuite gcp --service-account key.json`
- [ ] `prowler gcp --project-ids <project>`
- [ ] Manual: `gcloud projects get-iam-policy <project>` and review
- [ ] Custom: query Asset Inventory for sensitive resource types

## Cleanup

- [ ] Test resources tagged with `OBSIDIAN-TEST-<engagement>`
- [ ] Test resources removed at engagement end
- [ ] Test service accounts deleted

---

## Decision Tree: GCP-Specific Findings

1. **Workload Identity vs. Service Account Key:** missing Workload
   Identity in GKE deserves a high-priority finding even with no
   active exploitation, because it enables key-theft-as-cluster-takeover.

2. **Metadata service unprotected:** unlike AWS IMDSv2, GCP has no
   token-based protection. The defense is application-layer
   (block `Metadata-Flavor: Google` headers in proxy / WAF, prevent
   SSRF). If SSRF is found, metadata-service exploitation is
   essentially guaranteed.

3. **Project boundary as security boundary:** GCP IAM crosses projects
   easily via cross-project bindings. Confirm whether bindings stay
   within "project = blast radius" or extend across organization.
