# Playbook 13 — Cloud-native

**Goal:** assess the application's cloud security posture — IAM,
storage, compute, secrets management, logging, network controls.

Applicable when target is hosted on AWS / GCP / Azure / Oracle Cloud /
DigitalOcean / Linode. The operator usually has read-only console
access; the agent reviews configurations through that lens.

If the operator gives the agent **read-only API keys / service
account / managed identity** for the cloud account, this playbook
runs against the cloud itself. Without those, it relies on what the
app's behavior reveals externally.

---

## 13.1 Identify the cloud and the IAM principal

External identification:
- IP ranges in AWS / GCP / Azure published lists.
- Reverse DNS hints (`compute-1.amazonaws.com`,
  `googleusercontent.com`).
- Headers / cookies revealing CDN (`x-served-by`, `x-amz-cf-id`).
- Cloud-specific CDN (CloudFront, Cloud CDN, Azure Front Door).

Internal (with creds):
```bash
# AWS
aws sts get-caller-identity
aws iam list-account-aliases

# GCP
gcloud auth list
gcloud config get-value project

# Azure
az account show
```

---

## 13.2 IAM — the most-impactful cloud risk

### 13.2.1 AWS

```bash
# Enumerate principals, policies, role trust
aws iam list-users
aws iam list-roles
aws iam list-policies --scope Local
aws iam get-account-authorization-details > iam.json

# Tools
prowler -p aws -M json > prowler-aws.json
scoutsuite aws --report-dir scout-aws/
```

Findings:
- Wildcard `Action: *` or `Resource: *` in attached policies.
- `iam:PassRole` on `Resource: *`.
- AssumeRole trust to `*` or unrelated accounts.
- Long-lived access keys (>90 days).
- MFA not enforced for IAM users.
- Root account used for routine operations.
- Inline policies (drift).
- Service-linked role overlap.
- Cross-account roles trusting unknown accounts.

### 13.2.2 GCP

```bash
gcloud projects get-iam-policy <project>
gcloud iam service-accounts list
gcloud iam service-accounts keys list --iam-account=<sa>
```

Findings:
- Owner / Editor on Workforce identities (use Viewer / specific
  roles).
- Service-account keys (avoid; use Workload Identity instead).
- `allUsers` / `allAuthenticatedUsers` granted any role.
- Cross-project bindings to external orgs.

### 13.2.3 Azure

```bash
az role assignment list --all
az ad app list
az ad sp list --filter "tags/any(t:t eq 'WindowsAzureActiveDirectoryIntegratedApp')"
```

Findings:
- Owner / Contributor at subscription scope.
- App registrations with broad Graph API permissions.
- Conditional access not enforced.

---

## 13.3 Storage — the most-leaked service

### 13.3.1 S3 (AWS)

```bash
# Public bucket sweep
aws s3 ls
aws s3api get-bucket-policy --bucket <name>
aws s3api get-bucket-acl --bucket <name>

# External check
curl -sI "https://<bucket>.s3.amazonaws.com/"
curl -sI "https://s3.amazonaws.com/<bucket>/"
```

Findings:
- Bucket public-readable (`s3:GetObject` to `*`).
- Bucket public-writable (`s3:PutObject` to `*`).
- Bucket policy with broad principal.
- ACLs allowing AuthenticatedUsers (any AWS user reads).
- Versioning off (no recovery from ransomware).
- MFA delete off.
- Default encryption off.
- Logging off.
- Public access block disabled.

### 13.3.2 GCS (GCP)

```bash
gcloud storage ls
gsutil iam get gs://<bucket>

# External
curl -sI "https://storage.googleapis.com/<bucket>"
```

Findings: `allUsers` reader/writer, no uniform bucket access, no
versioning.

### 13.3.3 Azure Blob

```bash
az storage account list
az storage container list --account-name <acct>
```

Findings: anonymous container access, no encryption.

### 13.3.4 Public bucket discovery from outside

```bash
# Common name patterns
for prefix in "<orgname>" "<appname>"; do
  for suffix in "" "-prod" "-dev" "-staging" "-backup" "-data" "-logs" "-private"; do
    curl -sI "https://${prefix}${suffix}.s3.amazonaws.com/" -o /dev/null \
      -w "${prefix}${suffix}: %{http_code}\n"
  done
done
```

Use `slurp`, `bucket_finder`, `s3scanner`, `cloudenum` for systematic
sweeps.

---

## 13.4 Compute / serverless

### 13.4.1 EC2 / VMs

- Instance metadata service v2 (IMDSv2) enforced (mitigates SSRF →
  cred theft)?
- Public-facing instances minimized?
- SSH key rotation policy?
- Patch level (re-check via banner if exposed)?
- Security groups: 0.0.0.0/0 on management ports?

### 13.4.2 Lambda / Cloud Functions / Azure Functions

- Function permissions (over-broad role)?
- Resource-based policies open?
- Environment variables containing secrets (use Secrets Manager
  instead).
- Function URLs (public Lambda URLs) without auth.
- Outdated runtime versions (Node 12, Python 3.7, etc.).

### 13.4.3 ECS / EKS / Cloud Run / AKS — see playbook 14

---

## 13.5 Networking

- VPC default security group restrictive?
- NACL gaps?
- VPC peering / Transit Gateway routes to unexpected accounts?
- VPN endpoints exposed?
- VPC flow logs on?

---

## 13.6 Secrets management

- Secrets in env vars (visible to anyone with read on the resource).
- Secrets in CI/CD logs (GitHub Actions, CodeBuild) — see playbook 15.
- Secrets in code (gitleaks — see playbook 11 §11.6).
- Secrets in S3 (an old `terraform.tfvars` in a bucket).
- Use of dedicated services: AWS Secrets Manager, GCP Secret
  Manager, Azure Key Vault, HashiCorp Vault. Rotation enabled?

---

## 13.7 Logging and audit

- CloudTrail / Audit Log / Activity Log enabled across all regions /
  projects / subscriptions?
- Log integrity (immutable, separate account)?
- Alerting on root login, IAM changes, security group changes?
- Logs retained per compliance requirement?

---

## 13.8 Encryption at rest

- EBS / persistent disks encrypted by default?
- RDS / Cloud SQL / Azure DB encryption?
- KMS / KMS key access policies?
- Customer-managed keys vs provider-managed?

---

## 13.9 Continuous compliance scanners

```bash
# AWS
prowler -p aws -M json
scoutsuite aws

# GCP
prowler -p gcp
scoutsuite gcp

# Azure
prowler -p azure
scoutsuite azure

# Multi-cloud
cloudsploit scan --config config.json
```

Output JSON / HTML reports. Triage with the operator: many findings
are non-applicable; some are real and important.

---

## 13.10 Cloud-specific exploit chains

Common chains:

- SSRF in app → IMDSv1 metadata → temp credentials → broad IAM →
  cross-service abuse.
- IAM user with `iam:PassRole` + `lambda:CreateFunction` →
  privilege escalation.
- Public S3 bucket → backups / logs / sensitive data → escalation.
- Subdomain takeover of `<sub>.cloudfront.net` → JS injection in
  authenticated context.

---

## 13.11 Output

Findings filed. Phase summary:
- Cloud(s) in use.
- IAM posture (especially for the app's runtime principal).
- Storage exposure findings.
- Network exposure.
- Secrets management posture.
- Audit / log status.
