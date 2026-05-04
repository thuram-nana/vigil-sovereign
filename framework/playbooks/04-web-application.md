# Playbook 04 — Web application

**Goal:** comprehensive web-application security testing, mapping to
OWASP WSTG v4.2 and OWASP ASVS v4.0. This playbook ensures you cover
the standard web vuln classes that apply across nearly every web
target. Domain-specific testing (auth, authz, injection, business
logic, etc.) gets deeper treatment in playbooks 06–11.

**Stage in lifecycle:** 4.

This is the umbrella playbook. Use it as a coverage map; drill into
the focused playbooks when a class of issue looks present.

---

## 4.1 Information gathering (WSTG-INFO)

Already largely done in Stages 2–3. Re-verify:

- **INFO-01** Search-engine reconnaissance — see playbook 01 §1.3.
- **INFO-02** Fingerprint web server — playbook 02 §2.4.
- **INFO-03** Webserver metafiles for info leakage — playbook 02
  §2.6 (robots.txt, sitemap, security.txt).
- **INFO-04** Enumerate applications on webserver — playbook 02 §2.1
  (subdomains, vhosts).
- **INFO-05** Webpage content for info leakage — playbook 03 §3.4
  (JS bundle mining).
- **INFO-06** Identify entry points — playbook 03 §3.1, §3.10.
- **INFO-07** Map execution paths — playbook 03 §3.12 (data flow).
- **INFO-08/09** Fingerprint framework — playbook 02 §2.4.
- **INFO-10** Map architecture — threat model document.

If any are skipped, return and complete.

---

## 4.2 Configuration and deployment (WSTG-CONF)

| WSTG | Test | Notes |
|------|------|-------|
| CONF-01 | Network configuration | Playbook 12 §1 (network) |
| CONF-02 | Application platform configuration | Default credentials, default landing pages, dev tools, debug enabled |
| CONF-03 | File extensions handling | `.php`, `.asp`, `.bak`, `.old`, `.tar`, `.swp`, `.~`, `.orig`, `.LCK` |
| CONF-04 | Old / backup / unreferenced files | Playbook 02 §2.7 |
| CONF-05 | Enumerate admin interfaces | `/admin`, `/administrator`, `/manage`, `/manager`, `/console`, `/wp-admin`, `/cms`, `/cp`, `/_admin`, `/admin.php`, separate vhosts |
| CONF-06 | HTTP methods | Playbook 03 §3.6 |
| CONF-07 | HSTS | `Strict-Transport-Security` present, includeSubDomains, preload |
| CONF-08 | Cross-domain policy | `crossdomain.xml`, `clientaccesspolicy.xml` (Flash legacy, but seen) |
| CONF-09 | File permission | Externally-checkable cases: directory listing, executable files in upload dir |
| CONF-10 | Subdomain takeover | Playbook 09 §9.4 |
| CONF-11 | Cloud storage | `<bucket>.s3.amazonaws.com` listable; same for GCS, Azure Blob |
| CONF-12 | Content security policy | Playbook 09 §9.5 |

---

## 4.3 Identity (WSTG-IDNT) — see playbook 06

Account provisioning, registration process, account enumeration,
weak username policy. Deep dive in `06-authentication-identity.md`.

## 4.4 Authentication (WSTG-ATHN) — see playbook 06

Default credentials, lockout, auth bypass, remember-me, browser
cache, weak password policy, security questions, password reset,
weaker auth in alt channel.

## 4.5 Authorization (WSTG-ATHZ) — see playbook 07

Directory traversal / file include, bypass authz schema, privilege
escalation, IDOR, OAuth weakness.

## 4.6 Session management (WSTG-SESS) — see playbook 06 §6.5

Session schema, cookie attributes, fixation, exposed session
variables, CSRF, logout, timeout, session puzzling, hijacking.

## 4.7 Input validation (WSTG-INPV) — see playbook 08

Reflected/stored/DOM XSS, all injection forms, HTTP smuggling, format
string, overflow, host header, SSRF.

## 4.8 Error handling (WSTG-ERRH)

```bash
# Trigger various error paths
curl -sk "https://<target>/orders/999999999"           # not found
curl -sk "https://<target>/orders/abc"                 # type confusion
curl -sk "https://<target>/orders/'"                   # quote injection
curl -sk "https://<target>/__error__/throw"            # not real, but hits 404 path
curl -sk -X PROPFIND "https://<target>/"               # unusual method
curl -sk -H "Content-Length: 100" -X POST -d '' "https://<target>/api"  # malformed
```

Look at error responses for:
- Stack traces with filenames, line numbers, framework version.
- DB error messages disclosing schema.
- Internal paths (`/var/www/html/...`).
- Library versions in stack traces.
- Verbose JSON error objects.

If errors expose internals, that's an Info / Low finding individually,
but the disclosure often **enables other findings** (e.g. confirming
the framework version unlocks targeted CVE testing).

## 4.9 Cryptography (WSTG-CRYP) — see playbook 11

Transport-layer security, padding oracle, sensitive info on
encrypted channels, weak crypto.

## 4.10 Business logic (WSTG-BUSL) — see playbook 10

Data validation, request forgery, integrity checks, process timing,
function-call frequency, workflow circumvention, application misuse,
file upload abuse.

## 4.11 Client-side (WSTG-CLNT) — see playbook 09

DOM XSS, JS execution, HTML injection, client-side redirect, CSS
injection, resource manipulation, CORS, clickjacking, WebSockets,
postMessage, browser storage.

## 4.12 API testing (WSTG-APIT) — see playbook 05

GraphQL specifically, plus general API security from OWASP API Top 10.

---

## 4.13 The "thirteen quick checks" pass

After domain playbooks, a fast sweep for common findings often
overlooked:

1. **Open redirect** in `?redirect=`, `?next=`, `?return_to=`,
   `?url=`, `?continue=`, `?dest=`, `?goto=`.
   Test: `?next=//evil.com`, `?next=https:evil.com`, `?next=/\evil.com`.
2. **HTML injection** in error messages (less than full XSS, but
   still defacement).
3. **Verbose 500s** with stack traces.
4. **`/.git/` accessible** even when other obvious-leaks were
   blocked.
5. **CRLF injection** in `Location` headers, cookies, redirect targets.
6. **SSL certificate transparency monitoring** — an attacker can see
   when the operator's CA issues new certs (publicly logged).
   Operator should monitor too.
7. **Email spoofing** — DMARC `p=none` or absent.
8. **Mass-assignment in profile/settings updates** — playbook 07 §7.4.
9. **API rate limit per-key but not per-IP**, or vice versa.
10. **Sensitive data in URL parameters** (tokens, IDs, emails) leaking
    via Referer to third parties.
11. **No rate-limit on password reset** — flood test.
12. **No CAPTCHA / breach-list check on registration** — trivial
    bot signup.
13. **Caching of authenticated pages** — `Cache-Control: public` on
    `/account/*` letting CDN serve other users' content.

Each is a 5-minute test. Do them all once in a batch.

---

## 4.14 ASVS sanity check

OWASP ASVS v4.0 has 14 chapters (V1–V14). After domain playbooks,
walk the ASVS checklist (`framework/checklists/owasp-asvs.md`) and
ensure every applicable control has been verified or noted as out of
scope.

ASVS levels:
- **L1** (basic): every web app.
- **L2** (standard): apps that handle sensitive data — most operator
  apps.
- **L3** (advanced): high-value targets (payments, healthcare,
  defense).

Default to L2 unless the charter specifies higher.

---

## 4.15 Output

Findings into `targets/<name>/findings/NNN-*.md` as you confirm them.

Append to `notes/engagement-log.md` after this playbook:
- WSTG categories covered.
- ASVS controls verified at level L2 (or specified level).
- Quick-check sweep results.
- Domains where deeper drill-down is needed (typically auth, business
  logic, injection, API).
