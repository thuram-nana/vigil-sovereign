# `<Target>` — Scope definition

**Document version:** `1.0`
**Effective:** `<YYYY-MM-DD>`
**Authorising party:** `<full legal name>` (owner / authorised representative)
**Tester:** OBSIDIAN
**Charter reference:** `targets/<target>/charter.md` v`<N.N>`

This document narrows the engagement to a precise set of network, application,
and identity surfaces. It is the **single source of truth** for what may and may
not be tested. The Charter is the legal authority; this is the technical
boundary. Anything not explicitly listed as in-scope is out-of-scope.

---

## 1. Engagement type

- [ ] **Black-box** — no internal access, public-facing only
- [ ] **Grey-box** — limited credentials provided
- [ ] **White-box** — source, infrastructure access, design docs

Selected: `<one>`
Rationale: `<why this depth was chosen>`

---

## 2. In-scope assets

### 2.1 Web applications (URL-level)

| # | Asset | URL / Host | Notes |
|---|-------|------------|-------|
| 1 | `<name>` | `https://<host>` | `<purpose>` |
| 2 | `<name>` | `https://<host>` | `<purpose>` |

### 2.2 APIs

| # | API | Base URL | Auth | Spec available |
|---|-----|----------|------|----------------|
| 1 | `<name>` | `https://api.<host>/v1` | `<bearer / cookie / mTLS>` | `<openapi / postman / none>` |

### 2.3 Hosts / IPs / CIDR ranges

| # | Host / range | Owned by | Hosting | Notes |
|---|--------------|----------|---------|-------|
| 1 | `<x.x.x.x/y>` | `<owner>` | `<provider>` | `<notes>` |

### 2.4 Mobile applications

| # | Platform | Package / bundle ID | Source | Notes |
|---|----------|---------------------|--------|-------|
| 1 | `<Android / iOS>` | `<com.example.app>` | `<store / apk>` | |

### 2.5 Cloud accounts / projects

| # | Provider | Account ID / Project | Roles available | Notes |
|---|----------|----------------------|-----------------|-------|
| 1 | `<AWS / GCP / Azure>` | `<id>` | `<read-only audit / none>` | |

### 2.6 Source repositories

| # | Repo | Branch | Access | Notes |
|---|------|--------|--------|-------|
| 1 | `<url>` | `<main>` | `<read>` | |

### 2.7 Test accounts / credentials

| # | System | Identifier | Role | Notes |
|---|--------|------------|------|-------|
| 1 | `<app>` | `OBSIDIAN-TEST-A@<domain>` | `<user>` | seeded by client |

> All OBSIDIAN-controlled accounts MUST follow the `OBSIDIAN-TEST-*` naming
> convention so they are trivially identifiable in logs and can be cleaned up
> after the engagement.

---

## 3. Out-of-scope assets

Explicitly excluded. Touching any of these is a charter breach.

| # | Asset | Reason |
|---|-------|--------|
| 1 | `<host / system>` | `<contractual / third-party / production-only>` |
| 2 | Any host not enumerated in §2 | by default |
| 3 | `<vendor>` infrastructure (e.g. CDN edge nodes, payment processor) | third-party |
| 4 | Customer / end-user accounts | only OBSIDIAN-TEST-* may be exercised |
| 5 | Production payment flows that move real money | use sandbox or stop |

---

## 4. Surface-level rules

### 4.1 Allowed

- HTTP(S) request inspection, header / body manipulation
- Authentication probing using OBSIDIAN-TEST-* accounts
- Authorisation testing across OBSIDIAN-TEST-* tenants
- Input fuzzing within rate limits below
- Subdomain enumeration via passive sources (Certificate Transparency, DNS)
- Source code review (if §2.6 grants access)
- Static analysis of mobile binaries (if §2.4 grants access)
- Read-only cloud enumeration via provided audit credentials (if §2.5)

### 4.2 Conditional (require explicit approval per occurrence)

- Active port scanning above well-known ports
- Sustained traffic that may impact availability
- Exploitation of authentication bypass beyond proof-of-concept
- Any request that could cause data loss
- Pivoting from one in-scope asset into another distinct system
- Use of credentials beyond OBSIDIAN-TEST-* (e.g. discovered creds)

### 4.3 Forbidden

- DDoS, volumetric attacks, resource exhaustion as goal
- Social engineering of staff, customers, or third parties
- Physical access attempts
- Modification or deletion of customer data
- Exfiltration of PII or payment data beyond minimum-necessary PoC
- Persisting access (web shells, cron jobs, scheduled tasks, backdoor accounts)
- Pivoting outside §2 ranges
- Credential brute-force against accounts not owned by OBSIDIAN
- Public disclosure prior to remediation window

---

## 5. Rate and traffic limits

| Surface | Max RPS | Max concurrent | Notes |
|---------|---------|----------------|-------|
| Web app (per host) | `<10>` | `<5>` | back off on 429 / 503 |
| API | `<5>` | `<3>` | |
| Auth endpoints | `<2>` | `<1>` | avoid lockout cascade |

If any surface returns 5xx for `<60>` seconds, **STOP** and notify §6 contacts.

---

## 6. Communication

| Role | Name | Channel | When |
|------|------|---------|------|
| Primary contact | `<name>` | `<email / phone>` | business hours |
| Out-of-hours | `<name>` | `<phone>` | critical findings |
| Incident contact | `<name>` | `<phone>` | suspected breach during testing |

Incident definition: anything that could be confused with a real attack
(unexpected service degradation, suspected data exposure, third-party alert).
Stop testing immediately, log timestamps, and contact incident channel.

---

## 7. Test windows

| Window | Days | Hours (local TZ `<TZ>`) | Notes |
|--------|------|--------------------------|-------|
| Recon (passive) | any | any | low impact |
| Active testing | `<Mon–Fri>` | `<09:00–18:00>` | |
| Heavy / risky testing | `<by request>` | `<by request>` | requires §6 approval |

Outside test windows: NO active probing. Passive analysis of already-collected
data is permitted.

---

## 8. Data-handling

- Findings, evidence, and recon data live under `targets/<target>/`.
- PII discovered incidentally MUST be redacted in evidence (`█████`) unless
  required for proof of impact, in which case minimum-necessary is captured.
- Loot (credentials, tokens, files) lives in `targets/<target>/loot/` and is
  **never** committed to source control (see `.gitignore`).
- After engagement close: all loot purged within `<14>` days of remediation
  acceptance, evidence retained for `<1 year>` for re-test reference.

---

## 9. Approvals

| Field | Value |
|-------|-------|
| Scope authored | `<YYYY-MM-DD>` |
| Approved by client | `<name>` on `<YYYY-MM-DD>` |
| Approved by tester | OBSIDIAN on `<YYYY-MM-DD>` |
| Next review | `<YYYY-MM-DD>` or on material change |

**Material change** (any of which require re-approval): new asset added,
asset transferred to third party, charter modification, change of authorising
representative, expansion to a different cloud account.

---

## 10. Change log

| Version | Date | Change | Approver |
|---------|------|--------|----------|
| 1.0 | `<YYYY-MM-DD>` | initial | `<name>` |
