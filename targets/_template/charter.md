# Engagement charter — `<target-name>`

**Version:** 1.0
**Status:** Draft → Final (operator-confirmed)
**Date:** YYYY-MM-DD
**Last updated:** YYYY-MM-DD

This is the binding authorization document for the engagement against
`<target-name>`. OBSIDIAN reads this at the start of every session
and refuses to test outside its limits.

When this document is updated mid-engagement (re-scope, additional
authorization, removal of a target), increment the version and note
the change in the engagement log.

---

## 1. Operator attestation

I, **`<operator name>`**, attest:

- I am the legal owner / authorized representative for the systems
  listed in § 2 below.
- I have the authority to authorize a security assessment of those
  systems.
- I have read and understood the OBSIDIAN constitution
  (`CLAUDE.md`) and the OPSEC discipline
  (`framework/cognitive/opsec-discipline.md`).
- I authorize OBSIDIAN to perform the activities described in this
  charter, within the limits stated.

Signed: `<name>`     Date: `__________`

---

## 2. In-scope systems

| Host / Surface | Notes | Auth required for testing |
|----------------|-------|---------------------------|
| `<primary-domain>` | Primary web app | Yes (test accounts at § 5) |
| `*.<primary-domain>` | All subdomains discovered during recon | Yes |
| `api.<primary-domain>` | Public API | Yes |
| `<staging-domain>` (if any) | Staging environment | Yes |
| `<mobile package id>` (if any) | iOS / Android app and its API | Yes |

Unlisted subdomains discovered during recon are **conditionally in
scope**: agent surfaces them and waits for operator confirmation
before testing.

## 3. Out of scope (explicit)

These systems are not authorized for testing regardless of how the
agent reaches them:

- `<list third parties: payment processors, upstream APIs, hosting infra, IdPs, email/SMS providers, CDNs, WAFs>`
- `<sister sites the operator owns but did not include>`
- `<shared-infrastructure that other operators rely on>`

Findings that *reach* these systems via in-scope flaws (SSRF,
webhook forgery, OAuth token leak) are valuable and should be
reported, but the third-party system itself is not to be exploited
beyond minimum proof.

## 4. Hard limits — never violated

- No DoS testing (resource-exhaustion, connection flooding, fork
  bombs).
- No real-money payment movement beyond `$<X>` total cap.
- No real-user contact (no password resets to real customer
  emails, no notifications/SMS to real users).
- No data exfiltration of real user PII beyond minimum needed to
  demonstrate impact (max `<N>` records, redacted in evidence).
- No persistence on production beyond proof (and removed within
  the same session).
- No third-party attack.
- No proxy chains, Tor, or rotating residential IPs (unless EMULATE
  posture explicitly authorized).
- No bulk data deletion.
- No modification of admin settings on production without explicit
  confirmation per change.

## 5. Test accounts

The operator has created the following test accounts. Credentials
are in `targets/<name>/loot/credentials.md` (gitignored).

| Role | Username/handle | Purpose |
|------|----------------|---------|
| Anonymous | (none) | Baseline external |
| User A (low-priv) | `OBSIDIAN-TEST-userA` | Standard authenticated tests |
| User B (low-priv) | `OBSIDIAN-TEST-userB` | Horizontal IDOR / tenant isolation |
| Reseller / child tenant (if applicable) | `OBSIDIAN-TEST-reseller` | Cross-tenant tests |
| Admin (staging only) | `OBSIDIAN-TEST-admin` | Admin-side flows on staging |

All test accounts and artifacts are tagged with the prefix
`OBSIDIAN-TEST-` (or `<custom-prefix>` if the platform's username
rules don't allow that). The operator can grep for this prefix in
any DB column to identify test artifacts.

## 6. Soft limits

- **Off-peak window** for heavy scans: `<HH:MM–HH:MM TZ>`.
- **Default scan concurrency**: 5–10 threads. Higher requires
  per-action approval.
- **Rate-limit posture**: respect 429 responses; back off
  exponentially. Do not attempt to bypass rate limits except as a
  documented test of the rate limit itself (one attempt per
  endpoint).
- **Heavy scanners** (`nuclei -t cves/`, `sqlmap`, `ffuf` over
  large lists): operator notified before run; off-peak preferred.
- **Single-IP source**: `<operator-confirmed source IP>`. Operator
  can grep their access logs for this IP to correlate scan
  traffic.
- **User-Agent**: `OBSIDIAN/1.0 (authorized owner-test <YYYY-MM-DD>)`
  on automated tools.

## 7. Posture

- [ ] **TEST** (default): identifiable, throttled, tagged. Operator
       expects to correlate scan traffic.
- [ ] **AUDIT**: compliance-focused, control-mapped, slower.
- [ ] **EMULATE**: adversary emulation. Requires explicit reason
       and additional limits (still no real harm).

Selected: `<TEST | AUDIT | EMULATE>`.
Reason for non-default: `<if not TEST>`.

## 8. Objectives

What would a successful engagement look like?

- `<example: have confidence the panel survives credential-stuffing at scale>`
- `<example: confirm payment integrations cannot be forged>`
- `<example: identify and remediate any prior compromise indicators>`
- `<example: bring the platform to OWASP ASVS Level 2 compliance>`
- `<example: ...>`

Objectives are not "find all bugs" — that's the methodology. They
are the operator's outcome goals.

## 9. Stop conditions

OBSIDIAN halts and surfaces immediately if:

- A test causes 5xx storms, sustained latency, or production
  degradation signs.
- Evidence of prior compromise is found (artifacts in webroot,
  unknown admin accounts, modified core files, suspicious
  cron/services). Pivot to playbook 26.
- A test allows reading real user PII, real payment data, or real
  credentials. Do not bulk-collect; surface and ask.
- Authorization becomes unclear (in-scope / out-of-scope ambiguity
  surfaces during testing).
- Operator says stop.

## 10. Communication plan

| Channel | Use | Response time expected |
|---------|-----|------------------------|
| `<channel>` | Day-to-day questions | `<within 4 hours>` |
| `<channel>` | Critical findings | `<within 1 hour>` |
| `<channel>` | Emergency stop | `<immediate, ack required>` |

Operator's secondary contact (if primary unreachable):
`<name and channel>`.

## 11. Source code delivery

- [ ] Source code will be delivered at start of stage 7. Method:
       `<repo access | tarball drop in loot/source/ | other>`.
- [ ] Source code will not be delivered (black-box only).

If delivered: scope of source delivery (full monorepo, single repo,
specific services), and whether build / runtime config will be
included.

## 12. Continuous testing intent

- [ ] One-shot engagement.
- [ ] Quarterly self-driven re-engagement using this same
       framework.
- [ ] Monthly smoke tests on selected playbooks.
- [ ] Continuous monitoring (subdomain takeover, cert expiry,
       leaked secrets) — semi-automated.
- [ ] External pentest cadence: `<annual / biannual / triggered>`.

This drives playbook 25 (Continuous testing) at engagement close.

## 13. Reporting

Deliverables (see playbook 24):
- [ ] Executive summary (`reports/executive.md`).
- [ ] Technical report (`reports/technical.md`).
- [ ] Remediation roadmap (`reports/remediation-roadmap.md`).
- [ ] Threat model document (`reports/threat-model.md`).
- [ ] Retest report (`reports/retest.md`).

Format: Markdown source of truth; PDF/DOCX on request via pandoc.

## 14. Re-scope and amendments

Any expansion of scope, added systems, modified limits, or posture
shift requires:

1. The operator updates this charter (new section / modified item).
2. Version increment and date update.
3. Engagement log entry noting the change and authorization.
4. Operator's confirmation in the chat / channel.

OBSIDIAN does not assume an expansion was authorized just because
the operator mentioned a related system. Charter is the source of
truth.

## 15. Engagement closure

The engagement is closed when:

- All charter objectives are addressed.
- All findings have a final status (Verified Fixed / Risk Accepted
  / Will Not Fix / Bypassed-still-open).
- All test artifacts are cleaned up (`notes/test-artifacts.md`
  reviewed and confirmed).
- All credentials shared during the engagement are rotated.
- Reports delivered and signed off.
- Continuous-testing plan agreed (per § 12).

Final sign-off:
- Operator: `<name>` — date: ____________
- Tester (OBSIDIAN, on behalf of operator): date: ____________
