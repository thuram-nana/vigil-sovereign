# AWS Engagement Checklist

For testing applications hosted on AWS. Pairs with `13-cloud-native.md`.

> **Authorization gate:** AWS allows pentesting of *eight* services
> without prior approval (EC2, RDS, CloudFront, Aurora, API Gateway,
> Lambda, Lightsail, Elastic Beanstalk environments) within their
> [customer support policy for penetration testing]. Anything else,
> or simulated DoS, requires a request via the AWS Vulnerability and
> Penetration Testing form. Confirm scope before starting.

## Pre-Test

- [ ] AWS account ID(s) for target documented in `scope.md`
- [ ] Regions in scope listed
- [ ] Services in scope listed (and verified within AWS pentest allowlist)
- [ ] Read-only IAM credentials provisioned for posture-assessment phase
- [ ] Source IP for testing recorded
- [ ] CloudTrail enabled in target account (so engagement is auditable)

## Identity & Access

### IAM Users
- [ ] List all users (`aws iam list-users`); flag stale (`PasswordLastUsed` > 90 days)
- [ ] List access keys per user (`aws iam list-access-keys`); flag old (>90 days)
- [ ] Console MFA enabled on all human users
- [ ] No root account access keys exist
- [ ] Root account MFA enabled
- [ ] Login profiles vs. access keys differentiated (programmatic vs. console)

### IAM Policies
- [ ] No policies with `*:*` wildcard (full admin) outside of intentional admin groups
- [ ] No policies allowing `iam:PassRole` to `*`
- [ ] No policies with `NotAction` patterns (commonly miswritten allow-all)
- [ ] No policies allowing privilege-escalation pairs (cloudsplaining catalog):
  - [ ] `iam:CreateAccessKey` for arbitrary user
  - [ ] `iam:CreatePolicyVersion` + `iam:SetDefaultPolicyVersion`
  - [ ] `iam:UpdateAssumeRolePolicy`
  - [ ] `iam:AttachUserPolicy` / `iam:AttachRolePolicy`
  - [ ] `iam:PutUserPolicy` / `iam:PutRolePolicy`
  - [ ] `lambda:UpdateFunctionCode` (existing privileged function)
  - [ ] `cloudformation:UpdateStack` with privileged role
  - [ ] `ec2:RunInstances` + `iam:PassRole` of privileged role
- [ ] Run `cloudsplaining scan --input-file <auth.json>` — review high-priority findings
- [ ] Run `pacu` `iam__privesc_scan` against test creds (with permission)

### IAM Roles
- [ ] Trust policies don't allow `Principal: "*"` without conditions
- [ ] Cross-account trust roles have ExternalId condition (the [confused deputy] mitigation)
- [ ] Service roles have minimum-necessary scope (no `*:*` for Lambda execution roles, etc.)
- [ ] EC2 instance roles minimal (especially when IMDSv1 is enabled — credential theft → role abuse)

### IAM Groups
- [ ] Group memberships mapped to expected role
- [ ] No "all-users" admin group

## EC2 / Networking

### Security Groups
- [ ] No SG with `0.0.0.0/0` to ports other than 80/443 (or VPN-justified)
- [ ] No SG with `0.0.0.0/0` on 22 (SSH) or 3389 (RDP)
- [ ] No SG with `0.0.0.0/0` on databases (3306, 5432, 27017, 6379, 9200, etc.)
- [ ] No SG with `0.0.0.0/0` on internal ports (etcd, kubelet, docker, etc.)
- [ ] SG rule sources documented (CIDR comments / Description)
- [ ] No SG references to deleted SGs (broken refs)

### EC2 Instances
- [ ] **IMDSv2 enforced** on all instances (HttpTokens=required); IMDSv1 is the SSRF-to-cred-theft vector
- [ ] Public-facing instances justified (most should be behind ALB/CloudFront)
- [ ] EBS volumes encrypted
- [ ] Snapshots encrypted, not public
- [ ] AMIs not shared publicly
- [ ] Termination protection on production instances

### VPC
- [ ] VPC Flow Logs enabled
- [ ] No default VPC in use for production
- [ ] Public subnets / private subnets cleanly separated
- [ ] NAT Gateway / Internet Gateway placement reviewed
- [ ] VPC peering connections audited (no over-broad routes)
- [ ] VPC endpoints used for AWS service traffic (avoids data over public internet)

## S3

- [ ] **No public buckets** unless explicitly intentional (static site hosting)
- [ ] Bucket policies don't grant `Principal: "*"` outside justified buckets
- [ ] ACLs not used (deprecated, error-prone) — `BucketOwnerEnforced` set
- [ ] Block Public Access enabled at account level
- [ ] Versioning enabled on critical buckets (forensic preservation)
- [ ] Default encryption enabled (`AES256` minimum, `aws:kms` better)
- [ ] Bucket logging enabled
- [ ] Lifecycle policies configured (cost + minimization)
- [ ] No buckets with predictable names (e.g., `<companyname>-backups`) — enumerable
- [ ] Pre-signed URL policies reviewed (long expiry, broad permissions)
- [ ] Cross-region replication targets audited
- [ ] **Bucket name enumeration:** check `<company>-{backups,archive,logs,assets,uploads,internal}.s3.amazonaws.com`

## RDS / Aurora

- [ ] No public-facing DB instances unless justified
- [ ] Encryption at rest enabled
- [ ] Encryption in transit enforced (parameter group)
- [ ] Auto-minor-version upgrade enabled
- [ ] Backup retention >= 7 days
- [ ] Default master username changed (not `admin` / `postgres` / `root`)
- [ ] IAM database authentication enabled where possible
- [ ] Performance Insights / Audit logging enabled
- [ ] Parameter group reviewed for `log_statement = all` (sensitive in logs)

## Lambda

- [ ] Execution roles minimal (no `*:*`)
- [ ] Environment variables don't contain plaintext secrets (use Secrets Manager / SSM Parameter Store)
- [ ] Function URL auth set to AWS_IAM (not NONE) unless intentional public
- [ ] VPC configuration justified (avoid unnecessary public function access)
- [ ] Layers audited for known-vulnerable versions
- [ ] Concurrency limit set (cost + DoS resilience)
- [ ] Dead-letter queue configured for async invocations

## API Gateway

- [ ] Authorizer set on every method (none open without intent)
- [ ] Resource policies restrict source IPs / VPC where appropriate
- [ ] Throttling configured (rate + burst)
- [ ] Stage logging enabled
- [ ] WAF associated where exposed publicly

## Secrets Manager / SSM Parameter Store

- [ ] Resource policies restrict access to specific roles
- [ ] KMS CMK used (not the default AWS-managed key) for sensitive secrets
- [ ] Rotation enabled where supported (RDS, Redshift, etc.)
- [ ] No secrets duplicated as plain SSM strings

## CloudTrail / Logging

- [ ] CloudTrail enabled in **all regions** (multi-region trail)
- [ ] CloudTrail log file integrity validation enabled
- [ ] CloudTrail logs to dedicated logging-account bucket
- [ ] Log bucket has MFA-delete on
- [ ] Log bucket lifecycle moves old logs to Glacier
- [ ] CloudTrail data events enabled for sensitive S3 buckets / Lambda functions

## CloudFront / WAF

- [ ] Origin restrictions: requests to ALB/S3 only via CloudFront (signed origin secret / OAC)
- [ ] WAF rules: Core Rule Set / managed rules attached
- [ ] WAF geo-restrictions justified
- [ ] CloudFront cache behaviors don't bypass auth (e.g., `/api/*` not cached)
- [ ] HTTPS-only viewer policy

## ECS / EKS / Containers

- [ ] Task definitions don't expose privileged: true
- [ ] Task roles scoped tightly
- [ ] Container images scanned (`trivy`, ECR scanning)
- [ ] No `:latest` tags in production task definitions
- [ ] Secrets via Secrets Manager / SSM, not env vars in task def
- [ ] EKS: see `cloud-kubernetes.md`

## Cost / Configuration Drift

- [ ] AWS Config enabled
- [ ] AWS Config rules: required-tags, encrypted-volumes, mfa-enabled-for-iam-console-access, etc.
- [ ] Cost anomalies / unused resources identified (out of pentest scope but useful flag)

## Run Scanners

- [ ] `prowler aws --severities high,critical`
- [ ] `scoutsuite aws --profile pentest`
- [ ] `cloudsplaining scan` against IAM authorization data
- [ ] Specific spot checks: bucket enumeration, IMDSv2 audit, SG audit

## Cleanup

- [ ] Test resources tagged with `OBSIDIAN-TEST-<engagement>`
- [ ] Test resources removed at engagement end
- [ ] Test IAM users / keys deleted
- [ ] CloudTrail evidence preserved for engagement report

---

## Decision Tree: AWS-Specific Findings

When you find a misconfiguration, before reporting:

1. **Is it exploitable from current attacker position?** A public S3 bucket
   with public objects is L2 exploitable. A public bucket with no
   listable / readable objects is L1 (informational + future-risk).

2. **Does it chain to a higher-impact finding?** SG `0.0.0.0/0:5432` +
   weak DB credentials is far more severe than either alone.

3. **What's the blast radius?** A privesc path from low-priv IAM user to
   admin is critical regardless of credential scarcity.

4. **What's the detection probability?** A finding the client would
   never see in CloudTrail (e.g., metadata theft) deserves explicit
   detection-recommendation in the report.
