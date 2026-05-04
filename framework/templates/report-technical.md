# Technical Penetration Test Report — `<target-name>`

**Engagement window:** `<start>` — `<end>`
**Tester:** OBSIDIAN (operator-driven, owner-test)
**Report version:** `1.0`
**Status:** `Draft | Final`
**Audience:** engineering team

---

## 1. Engagement summary

One page. Reader is the operator's engineering team.

- **Scope**: see `charter.md` § 2.
- **Methodology**: see `framework/playbooks/` and `CLAUDE.md`. Phases
  0 (charter), 1 (threat model), 2 (recon), 3 (mapping), 4 (vuln-
  hunt by domain), 5 (exploitation / chaining), 6 (post-exploit, if
  authorized), 7 (source-code review), 8 (this report), 9 (retest).
- **Posture**: `TEST | AUDIT | EMULATE`.
- **Limitations**: `<production-only testing? throttling?
  source-availability?>`.
- **Standards mapping**: OWASP WSTG v4.2, ASVS v4.0, API Top 10
  2023, MITRE ATT&CK Enterprise, CWE, CVSS 3.1.

## 2. Findings overview

Sorted by severity then ID.

| ID | Title | Severity | Status |
|----|-------|----------|--------|
| 003 | Webhook callback accepts forged deposits without signature | Critical | Verified Fixed |
| 007 | Admin panel reachable with default credentials | Critical | Verified Fixed |
| 014 | IDOR on /order/{id} returns cross-user order data | High | Fix in progress |
| 022 | No rate limit on /login endpoint | High | Verified Fixed |
| ... | ... | ... | ... |

### Severity distribution

```
Critical: <N>
High:     <N>
Medium:   <N>
Low:      <N>
Info:     <N>
```

### Status distribution

```
Verified Fixed:    <N>
Fix in progress:   <N>
Open:              <N>
Bypassed:          <N>
Risk Accepted:     <N>
Will Not Fix:      <N>
```

## 3. Chains

For chained findings (composite attacks crossing multiple
findings), summarize:

| Chain ID | Constituent findings | Severity (composite) | Description |
|----------|---------------------|----------------------|-------------|
| CHAIN-001 | 003 + 022 | Critical | Webhook forgery + no rate limit → automated balance theft at scale |
| CHAIN-002 | 014 + 029 | High | IDOR + verbose errors → user enumeration with sensitive data |

## 4. Findings detail

For each finding, embed the content from
`findings/NNN-slug.md` verbatim, ordered by severity then ID.

### 4.1 Finding 003 — Webhook callback accepts forged deposits

`[insert content of findings/003-*.md]`

### 4.2 Finding 007 — Admin default credentials

`[insert content of findings/007-*.md]`

`...`

## 5. Cross-cutting recommendations

Patterns the tester observed across multiple findings — fix once,
close many bugs.

### 5.1 Centralize authorization

If many IDOR / authz findings exist: recommend an authorization
layer (policy classes / middleware / authz framework) rather than
per-controller manual checks.

### 5.2 Webhook signature verification helper

If multiple payment / external integrations are present: a single
verified-signature helper used by all integrations, not per-
provider implementations.

### 5.3 Output encoding by default

If multiple stored XSS findings exist: ensure templates auto-
escape; audit any `{!! !!}` / `raw` / `dangerouslySetInnerHTML`
usage.

### 5.4 Database-layer constraints for money invariants

`CHECK (balance >= 0)`, `UNIQUE (provider, tx_id)` on deposits,
`UNIQUE (order_id, leg)` on refunds. The DB enforces what app
logic forgets.

### 5.5 Logging and alerting

Log: failed logins, password resets, balance changes, webhook
auth failures, API auth failures, admin actions, file uploads,
configuration changes.
Alert on: >N failed logins per IP/hour, any rejected webhook,
any negative-balance attempt, sudden privilege change, large
data exports, off-hours admin access.

### 5.6 Test cadence

Continuous testing as outlined in playbook 25.

## 6. Methodology and tools

Brief description of the framework. Links into the framework
documents for engineers who want to dig in.

- Cognitive framework: `framework/cognitive/`
- Playbooks: `framework/playbooks/`
- Knowledge base: `framework/knowledge-base/`
- Tools used: `framework/tools/tool-catalog.md`

## 7. Appendices

### A. Endpoint inventory

Paste from `recon/enum/inventory.md`.

### B. Role / authorization matrix

Paste from `recon/enum/role-matrix.md`.

### C. Test artifacts created and cleanup status

Paste from `notes/test-artifacts.md`.

### D. Command log excerpt

Selected entries from `notes/command-log.md` covering the most
significant commands. Sanitize: redact any captured credentials.

### E. Standards mapping

Per finding, the mapped standard codes:
- OWASP WSTG ID
- OWASP ASVS requirement
- MITRE ATT&CK technique
- CWE
- CVSS vector

### F. Glossary

- **IDOR** — Insecure Direct Object Reference.
- **CSRF** — Cross-Site Request Forgery.
- **SSRF** — Server-Side Request Forgery.
- **SSTI** — Server-Side Template Injection.
- **XXE** — XML External Entity.
- **TOCTOU** — Time-of-Check-to-Time-of-Use.
- **MFA / 2FA** — Multi-Factor / Two-Factor Authentication.
- **CSP** — Content Security Policy.
- **HSTS** — HTTP Strict Transport Security.
- **CVSS** — Common Vulnerability Scoring System.
- **CWE** — Common Weakness Enumeration.
- **PKCE** — Proof Key for Code Exchange.
- **JWT** — JSON Web Token.
- **OIDC** — OpenID Connect.
- **SAML** — Security Assertion Markup Language.
- **BOLA** — Broken Object-Level Authorization (OWASP API Top 10).
- **BFLA** — Broken Function-Level Authorization (OWASP API Top
  10).
