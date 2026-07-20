# Engagement charter — `mrbeanpanel.com`

**Version:** 1.0-DRAFT
**Status:** UNSIGNED — operator must move and sign this file as `charter.md`.
**Date:** 2026-05-04

> This file was drafted by UTI from a passive fingerprint of
> `https://mrbeanpanel.com`. It is **not** authoritative. The operator MUST
> review every section and replace the `<...>` placeholders before
> any further activity. Until then v2's ethics gate refuses active
> testing against this target.

---

## 1. Operator attestation

I, **`testbot`**, attest:

- I am the legal owner / authorized representative for the systems
  listed in § 2 below.
- I have the authority to authorize a security assessment of those
  systems.
- I have read and understood the OBSIDIAN constitution (`CLAUDE.md`)
  and the OPSEC discipline
  (`framework/cognitive/opsec-discipline.md`).
- I authorize OBSIDIAN to perform the activities described in this
  charter, within the limits stated.

Signed: `<name>`     Date: `__________`

---

## 2. In-scope systems

| Host / Surface | Notes | Auth required for testing |
|----------------|-------|---------------------------|
| `mrbeanpanel.com` | Primary host — fingerprinted as **PHP-Smarty SMM-panel fork** (php-smarty-smm-panel-fork) | Yes (test accounts at § 5) |
| `*.mrbeanpanel.com` | All subdomains discovered during recon | Yes |

Edit this table to add API hostnames, staging environments, or
sister hosts the operator owns. Subdomains discovered during recon
are conditionally in scope: agent surfaces them and waits for
operator confirmation before testing.

## 3. Out of scope (explicit)

These systems are not authorized for testing regardless of how the
agent reaches them:

- The hosting provider's control plane and shared infrastructure.
- Any CDN / WAF / payment / IdP / mail provider — third parties.
- Any system owned by a different legal entity.

Findings that *reach* these systems via in-scope flaws (SSRF,
webhook forgery, OAuth token leak) are valuable and should be
reported, but the third-party system itself is not to be exploited
beyond minimum proof.

## 4. Hard limits — never violated

- No DoS testing.
- No real-money payment movement beyond `$<X>` total cap.
- No real-user contact (no password resets / SMS / notifications to
  real customer addresses).
- No data exfiltration of real user PII beyond minimum needed to
  demonstrate impact (max `<N>` records, redacted in evidence).
- No persistence on production beyond proof (and removed within
  the same session).
- No third-party attack.
- No proxy chains, Tor, or rotating residential IPs.
- No bulk data deletion.
- No modification of admin settings on production without explicit
  confirmation per change.

## 5. Test accounts

The operator must create test accounts before active testing begins.
Tag each with the prefix `OBSIDIAN-TEST-` (or operator-chosen prefix)
so the operator can grep their DB for test artefacts.

| Role | Username/handle | Purpose |
|------|----------------|---------|
| Anonymous | (none) | Baseline external |
| User A (low-priv) | `OBSIDIAN-TEST-userA` | Standard authenticated tests |
| User B (low-priv) | `OBSIDIAN-TEST-userB` | Horizontal IDOR / tenant isolation |

## 6. Soft limits

- Off-peak window for heavy scans: `<HH:MM–HH:MM TZ>`.
- Default scan concurrency: 5–10 threads. Higher requires per-action approval.
- Rate-limit posture: respect 429 responses; back off exponentially.
- Single-IP source: `<operator-confirmed source IP>`.
- User-Agent: `OBSIDIAN/2.0 (authorized owner-test 2026-05-04)`.

## 7. Posture

- [ ] **TEST** (default)
- [ ] **AUDIT**
- [ ] **EMULATE**

Selected: `<TEST | AUDIT | EMULATE>`.

## 8. Objectives

SMM (Social Media Marketing) reseller panel. ~44k users, ~967k orders. Multi-PSP balance topup. Operator reports active account-takeover incidents.

## 9. Stop conditions

OBSIDIAN halts and surfaces immediately if:

- A test causes 5xx storms, sustained latency, or production degradation.
- Evidence of prior compromise is found (artifacts in webroot, unknown
  admin accounts, modified core files, suspicious cron/services).
- A test allows reading real user PII, real payment data, or real
  credentials. Do not bulk-collect; surface and ask.
- Authorization becomes unclear (in-scope / out-of-scope ambiguity).
- Operator says stop.

## 10. Communication plan

| Channel | Use | Response time expected |
|---------|-----|------------------------|
| `<channel>` | Day-to-day questions | `<within 4 hours>` |
| `<channel>` | Critical findings | `<within 1 hour>` |
| `<channel>` | Emergency stop | `<immediate, ack required>` |

## 11. Source code delivery

- [ ] Source code will be delivered at start of stage 7. Method: `<repo access | tarball | other>`.
- [ ] Source code will not be delivered (black-box only).

## 12. Continuous testing intent

- [ ] One-shot engagement.
- [ ] Quarterly self-driven re-engagement.
- [ ] Continuous monitoring of public-facing surface.

## 13. Reporting

Deliverables (per playbook 24):
- [ ] Executive summary (`reports/executive.md`).
- [ ] Technical report (`reports/technical.md`).
- [ ] Remediation roadmap (`reports/remediation-roadmap.md`).

## 14. Re-scope and amendments

Any expansion of scope, added systems, modified limits, or posture
shift requires operator update + version increment + engagement-log
entry + operator's confirmation in chat.

---

## Appendix — UTI fingerprint snapshot

This is what UTI saw on intake. It is not an exhaustive recon report;
it is the minimum signal needed to draft this charter. Refresh after
real recon.

```json
{
  "target_url": "https://mrbeanpanel.com",
  "request_count": 9,
  "primary_archetype": {
    "slug": "php-smarty-smm-panel-fork",
    "name": "PHP-Smarty SMM-panel fork",
    "score": 0.7454500000000001
  },
  "best_per_category": {
    "server": {
      "label": "nginx",
      "confidence": 1.0
    },
    "framework": {
      "label": "perfect-panel",
      "confidence": 0.99
    },
    "cms": {
      "label": "perfect-panel",
      "confidence": 0.997
    },
    "auth": {
      "label": "php-session",
      "confidence": 0.978
    },
    "api": {
      "label": "rest",
      "confidence": 0.7
    },
    "cdn_waf": {
      "label": "hsts",
      "confidence": 1.0
    }
  },
  "security_headers_present": [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options"
  ],
  "runners_up": [
    {
      "slug": "rails-monolith",
      "score": 0.3675
    },
    {
      "slug": "wordpress-cms",
      "score": 0.365
    }
  ]
}
```
