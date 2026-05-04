# Azure Engagement Checklist

For testing applications hosted on Microsoft Azure. Pairs with `13-cloud-native.md`.

> **Authorization gate:** Azure penetration testing is permitted on
> your own resources without prior approval per the Microsoft Cloud
> Unified Penetration Testing Rules of Engagement. Confirm scope —
> attacks against shared infrastructure, other tenants, and Microsoft's
> own services are out of scope.

## Pre-Test

- [ ] Azure subscription ID(s) and tenant ID documented in `scope.md`
- [ ] Resource Groups in scope listed
- [ ] Service Principal OR `az login` provisioned for posture-assessment (Reader at minimum)
- [ ] Source IP recorded
- [ ] Activity Log / Diagnostic Settings forwarding enabled (engagement auditable)

## Identity & Access (Azure AD / Entra ID)

### Users & Groups
- [ ] Privileged user accounts: count, MFA status (Conditional Access policies)
- [ ] Global Administrators count: should be 2-5; more is an anti-pattern
- [ ] Privileged Identity Management (PIM) used for just-in-time elevation
- [ ] No user accounts with Directory Synchronization Accounts role outside ADConnect
- [ ] Guest users: enumerated, justified, restricted (Conditional Access for guests)
- [ ] Legacy authentication blocked (Conditional Access policy)
- [ ] No users with `User Access Administrator` outside intended

### Service Principals & App Registrations
- [ ] Service Principal credentials: client secrets vs. certificates (certs preferred)
- [ ] Client secret rotation: flag any older than 1 year
- [ ] App registrations with `User.ReadWrite.All` / `Directory.ReadWrite.All` Graph permissions reviewed
- [ ] Service Principals with `Owner` or `Contributor` at subscription level reviewed
- [ ] Workload Identity Federation used where possible (avoids long-lived secrets)
- [ ] No app registrations with `Allow public client flows` enabled unless justified

### RBAC
- [ ] No `Owner` role assignments outside subscription-owner / RG-owner intent
- [ ] No `Contributor` at subscription scope unless justified
- [ ] No `User Access Administrator` (privesc-equivalent) outside intent
- [ ] Custom roles reviewed for over-broad `actions`
- [ ] Role assignments at management group level reviewed (cascade widely)
- [ ] No principals with `*` action permissions outside reserved roles

### Privesc Patterns (Azure analog)
- [ ] `Microsoft.Authorization/roleAssignments/write` → can grant self any role
- [ ] `Microsoft.Authorization/roleDefinitions/write` → can modify role definitions
- [ ] `Microsoft.ManagedIdentity/userAssignedIdentities/*/assign/action` + Compute privileges
- [ ] `Microsoft.Compute/virtualMachines/runCommand/action` (RCE on any VM)
- [ ] `Microsoft.Web/sites/publish/Action` (function/web app deploy → RCE)
- [ ] `Microsoft.KeyVault/vaults/accessPolicies/write` → grant self KV access
- [ ] `microsoft.directory/applications/credentials/update` (in Entra ID) → modify app secrets

## Conditional Access

- [ ] Block-legacy-auth policy in effect
- [ ] MFA-for-admins policy enforced
- [ ] MFA-for-all-users (or risk-based) where appropriate
- [ ] Sign-in risk policy configured
- [ ] User risk policy configured
- [ ] Country/region restrictions where applicable
- [ ] Compliant device requirement for privileged admins
- [ ] Emergency-access (break-glass) accounts: 2 minimum, excluded from MFA but with strict monitoring + long random passwords

## Virtual Machines

- [ ] **Instance Metadata Service (IMDS):** Azure IMDS at `169.254.169.254` requires `Metadata: true` header — but check for SSRF that can set arbitrary headers
- [ ] Managed Identity attached: scope reviewed (system-assigned vs. user-assigned)
- [ ] Public IPs justified (most should be behind LB / Application Gateway)
- [ ] OS managed updates enabled
- [ ] Disk encryption enabled (Azure Disk Encryption or platform-managed)
- [ ] Just-In-Time VM Access for management
- [ ] No serial console access enabled
- [ ] Boot diagnostics storage account scoped

## Networking

### Network Security Groups
- [ ] No NSG with source `*` or `Internet` on management ports (22, 3389)
- [ ] No NSG with source `Internet` on databases (3306, 5432, 1433, 6379, 27017)
- [ ] No NSG with `Allow * Any` rules
- [ ] Default deny verified at end of rule set
- [ ] DDoS Protection Standard on internet-facing resources
- [ ] Application Security Groups used (vs. raw IP/CIDR rules)

### Virtual Networks
- [ ] No accidental peering to other tenants
- [ ] VNet Flow Logs enabled
- [ ] Private Endpoints used for PaaS services (Storage, SQL, Key Vault)
- [ ] Service Endpoints used where Private Endpoints unavailable

### Load Balancers / Application Gateway
- [ ] WAF enabled on Application Gateway / Front Door (with rules tuned)
- [ ] HTTPS-only listeners
- [ ] TLS minimum version 1.2

## Storage Accounts

- [ ] **Public blob access disabled** at account level unless justified
- [ ] No containers set to "Container" or "Blob" public access unless intentional
- [ ] Shared Key access disabled (use Entra auth)
- [ ] Storage account firewall: restrict to specific VNet / IP ranges
- [ ] Soft delete enabled (containers, blobs)
- [ ] Versioning enabled on critical accounts
- [ ] Encryption: CMK preferred over Microsoft-managed
- [ ] Diagnostic logs to dedicated logging account
- [ ] **Container enumeration:** Azure storage URLs are predictable: `https://<storage-account>.blob.core.windows.net/<container>` — try common names (`backups`, `logs`, `assets`, `internal`)
- [ ] Storage account names: enumerate by company name patterns
- [ ] SAS tokens: review expiration (long-lived = high-risk), permissions, IP restrictions

## Azure SQL / Cosmos DB

### Azure SQL
- [ ] Public network access: disabled or firewall-restricted
- [ ] No `0.0.0.0` in firewall rules
- [ ] Azure AD authentication enabled (not just SQL auth)
- [ ] Transparent Data Encryption enabled
- [ ] Auditing enabled with retention
- [ ] Threat Detection / Defender for SQL enabled
- [ ] No `sa` or default admin with weak password

### Cosmos DB
- [ ] Public network access disabled or restricted
- [ ] Local auth (key-based) disabled in favor of Entra auth where supported
- [ ] Network firewall configured
- [ ] Backup retention configured
- [ ] Customer-Managed Keys for sensitive data

## Key Vault

- [ ] Soft delete enabled
- [ ] Purge protection enabled
- [ ] Network access restricted (Private Endpoint or vault firewall)
- [ ] RBAC permission model preferred over Vault Access Policies
- [ ] Diagnostic logs enabled (KV access is high-value telemetry)
- [ ] Secrets / keys / certificates rotated regularly
- [ ] No app's KV access policies overly broad (avoid `All` permissions)

## App Service / Functions

- [ ] HTTPS-only enforced
- [ ] TLS minimum version 1.2
- [ ] FTP/FTPS deployment disabled (use Git/CI/CD)
- [ ] App settings (env vars): no plaintext secrets — use Key Vault references
- [ ] Authentication enabled (App Service auth) for non-public apps
- [ ] Diagnostic logs forwarded to Log Analytics
- [ ] Identity (system-assigned MI) used for downstream service auth
- [ ] No Kudu / SCM endpoint accessible publicly
- [ ] Network restrictions / VNet integration where appropriate

## Container Services (AKS — see `cloud-kubernetes.md`)

- [ ] AKS clusters audited via K8s checklist
- [ ] Azure RBAC integration enabled
- [ ] Private cluster preferred
- [ ] Workload Identity enabled
- [ ] Defender for Containers enabled

## Logging & Monitoring

- [ ] Activity Log forwarded to Log Analytics workspace
- [ ] Diagnostic Settings on critical resources (KV, SQL, NSGs, App Service)
- [ ] Log Analytics workspace in dedicated subscription / RG
- [ ] Microsoft Defender for Cloud enabled (free tier minimum, Standard for sensitive)
- [ ] Alerts configured for high-risk events (role assignments, KV access denials, NSG changes)

## Run Scanners

- [ ] `scoutsuite azure --cli` (after `az login`)
- [ ] `prowler azure -a "*"`
- [ ] Manual: `az ad role assignment list --all` + review
- [ ] Manual: storage account enumeration with hostname guessing
- [ ] [BloodHound for Entra ID](https://github.com/dirkjanm/ROADtools) — `roadrecon` for Entra ID enumeration

## Cleanup

- [ ] Test resources tagged with `OBSIDIAN-TEST-<engagement>`
- [ ] Test resources removed at engagement end
- [ ] Test service principals deleted
- [ ] Test users deleted from Entra ID

---

## Decision Tree: Azure-Specific Findings

1. **Entra ID is the new perimeter.** Many Azure-app compromise paths
   start at Entra ID (consent phishing, app registration abuse, guest
   user privilege creep). Findings here have organization-wide blast
   radius.

2. **Managed Identity scope creep:** a system-assigned identity on a
   compromised VM grants attackers whatever Azure RBAC the identity
   has. Audit MI assignments as carefully as user roles.

3. **Storage account enumeration is cheap.** Try `<companyname>*` /
   `<projectname>*` / `<env>*` against `*.blob.core.windows.net` —
   often finds backup buckets without auth controls.

4. **Conditional Access gaps are subtle.** A policy that's "Report
   Only" instead of "Enforce" is a finding — it has no protective
   effect. Test by trying to perform the gated action.
