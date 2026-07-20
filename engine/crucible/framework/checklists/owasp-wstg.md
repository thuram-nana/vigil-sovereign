# OWASP WSTG v4.2 Checklist

The OWASP Web Security Testing Guide is the canonical web-app testing
reference. This checklist is the section index, mapped to CRUCIBLE
playbooks. **Coverage** here means the *technique* is exercised against
the target where applicable, not that the section was read.

Do not treat this as a substitute for reasoning. Some sections are
inapplicable to a given target (no LDAP → skip LDAP injection); some
require multiple passes (input validation overlaps with every other
section). Mark `N/A — <reason>` rather than just unchecked when skipping.

---

## INFO — Information Gathering

- [ ] **WSTG-INFO-01** Conduct search engine reconnaissance → `01-passive-recon.md`
- [ ] **WSTG-INFO-02** Fingerprint web server → `01-passive-recon.md`, `02-active-recon.md`
- [ ] **WSTG-INFO-03** Review webserver metafiles (robots.txt, sitemap, security.txt) → `01-passive-recon.md`
- [ ] **WSTG-INFO-04** Enumerate applications on webserver → `02-active-recon.md`, `03-attack-surface-mapping.md`
- [ ] **WSTG-INFO-05** Review webpage content for information leakage → `01-passive-recon.md`, `04-web-application.md`
- [ ] **WSTG-INFO-06** Identify application entry points → `03-attack-surface-mapping.md`
- [ ] **WSTG-INFO-07** Map execution paths through application → `03-attack-surface-mapping.md`
- [ ] **WSTG-INFO-08** Fingerprint web application framework → `02-active-recon.md`
- [ ] **WSTG-INFO-09** Fingerprint web application → `02-active-recon.md`
- [ ] **WSTG-INFO-10** Map application architecture → `03-attack-surface-mapping.md`

## CONFIG — Configuration & Deployment Management

- [ ] **WSTG-CONF-01** Test network infrastructure configuration → `12-network-infrastructure.md`
- [ ] **WSTG-CONF-02** Test application platform configuration → `12-network-infrastructure.md`
- [ ] **WSTG-CONF-03** Test file extensions handling → `04-web-application.md`
- [ ] **WSTG-CONF-04** Review old, backup and unreferenced files → `02-active-recon.md`, `04-web-application.md`
- [ ] **WSTG-CONF-05** Enumerate infrastructure / application admin interfaces → `04-web-application.md`
- [ ] **WSTG-CONF-06** Test HTTP methods → `04-web-application.md`, `05-api-security.md`
- [ ] **WSTG-CONF-07** Test HSTS → `11-cryptography.md`
- [ ] **WSTG-CONF-08** Test RIA cross-domain policy → `09-client-side.md`
- [ ] **WSTG-CONF-09** Test file permissions → `12-network-infrastructure.md`
- [ ] **WSTG-CONF-10** Test for subdomain takeover → `01-passive-recon.md`, `recon/subdomain-takeover.sh`
- [ ] **WSTG-CONF-11** Test cloud storage → `13-cloud-native.md`
- [ ] **WSTG-CONF-12** Test for content security policy → `09-client-side.md`

## IDNT — Identity Management

- [ ] **WSTG-IDNT-01** Test role definitions → `06-authentication-identity.md`, `07-authorization.md`
- [ ] **WSTG-IDNT-02** Test user registration process → `06-authentication-identity.md`
- [ ] **WSTG-IDNT-03** Test account provisioning process → `06-authentication-identity.md`
- [ ] **WSTG-IDNT-04** Test for account enumeration & guessable user accounts → `06-authentication-identity.md`
- [ ] **WSTG-IDNT-05** Test for weak / unenforced username policy → `06-authentication-identity.md`

## ATHN — Authentication

- [ ] **WSTG-ATHN-01** Test for credentials transported over encrypted channel → `11-cryptography.md`
- [ ] **WSTG-ATHN-02** Test for default credentials → `06-authentication-identity.md`, `default-credentials.md`
- [ ] **WSTG-ATHN-03** Test for weak lock-out mechanism → `06-authentication-identity.md`
- [ ] **WSTG-ATHN-04** Test for bypassing authentication schema → `06-authentication-identity.md`
- [ ] **WSTG-ATHN-05** Test remember-password functionality → `06-authentication-identity.md`
- [ ] **WSTG-ATHN-06** Test browser cache weaknesses → `09-client-side.md`
- [ ] **WSTG-ATHN-07** Test for weak password policy → `06-authentication-identity.md`
- [ ] **WSTG-ATHN-08** Test for weak security question / answer → `06-authentication-identity.md`
- [ ] **WSTG-ATHN-09** Test for weak password change / reset → `06-authentication-identity.md`
- [ ] **WSTG-ATHN-10** Test for weaker authentication in alternative channel → `06-authentication-identity.md`
- [ ] **WSTG-ATHN-11** Test multi-factor authentication → `06-authentication-identity.md`

## ATHZ — Authorization

- [ ] **WSTG-ATHZ-01** Test directory traversal / file include → `08-injection.md`
- [ ] **WSTG-ATHZ-02** Test for bypassing authorization schema → `07-authorization.md`
- [ ] **WSTG-ATHZ-03** Test for privilege escalation → `07-authorization.md`
- [ ] **WSTG-ATHZ-04** Test for IDOR → `07-authorization.md`, `auth/idor-sweep.py`
- [ ] **WSTG-ATHZ-05** Test for OAuth weaknesses → `19-sso-federated.md`

## SESS — Session Management

- [ ] **WSTG-SESS-01** Test for session management schema → `06-authentication-identity.md`
- [ ] **WSTG-SESS-02** Test for cookie attributes → `06-authentication-identity.md`, `09-client-side.md`
- [ ] **WSTG-SESS-03** Test for session fixation → `06-authentication-identity.md`
- [ ] **WSTG-SESS-04** Test for exposed session variables → `04-web-application.md`
- [ ] **WSTG-SESS-05** Test for CSRF → `09-client-side.md`
- [ ] **WSTG-SESS-06** Test for logout functionality → `06-authentication-identity.md`
- [ ] **WSTG-SESS-07** Test session timeout → `06-authentication-identity.md`
- [ ] **WSTG-SESS-08** Test for session puzzling → `06-authentication-identity.md`
- [ ] **WSTG-SESS-09** Test for session hijacking → `06-authentication-identity.md`
- [ ] **WSTG-SESS-10** Test JSON Web Tokens → `06-authentication-identity.md`, `api/jwt-attack.py`

## INPV — Input Validation

- [ ] **WSTG-INPV-01** Reflected XSS → `09-client-side.md`
- [ ] **WSTG-INPV-02** Stored XSS → `09-client-side.md`
- [ ] **WSTG-INPV-03** HTTP verb tampering → `04-web-application.md`
- [ ] **WSTG-INPV-04** HTTP parameter pollution → `08-injection.md`
- [ ] **WSTG-INPV-05** SQL injection → `08-injection.md`
- [ ] **WSTG-INPV-06** LDAP injection → `08-injection.md`
- [ ] **WSTG-INPV-07** XML injection → `08-injection.md`
- [ ] **WSTG-INPV-08** SSI injection → `08-injection.md`
- [ ] **WSTG-INPV-09** XPath injection → `08-injection.md`
- [ ] **WSTG-INPV-10** IMAP/SMTP injection → `08-injection.md`
- [ ] **WSTG-INPV-11** Code injection (LFI/RFI) → `08-injection.md`
- [ ] **WSTG-INPV-12** Command injection → `08-injection.md`
- [ ] **WSTG-INPV-13** Format string → `08-injection.md` (rare in web apps)
- [ ] **WSTG-INPV-14** Incubated vulnerabilities → `04-web-application.md`
- [ ] **WSTG-INPV-15** HTTP splitting / smuggling → `04-web-application.md`, `12-network-infrastructure.md`
- [ ] **WSTG-INPV-16** Incoming HTTP request smuggling → `04-web-application.md`
- [ ] **WSTG-INPV-17** Host header injection → `04-web-application.md`
- [ ] **WSTG-INPV-18** SSTI → `08-injection.md`
- [ ] **WSTG-INPV-19** SSRF → `08-injection.md`, `api/ssrf-probe.py`

## ERRH — Error Handling

- [ ] **WSTG-ERRH-01** Improper error handling → `04-web-application.md`
- [ ] **WSTG-ERRH-02** Stack traces → `04-web-application.md`

## CRYP — Cryptography

- [ ] **WSTG-CRYP-01** Weak transport layer → `11-cryptography.md`
- [ ] **WSTG-CRYP-02** Padding oracle → `11-cryptography.md`
- [ ] **WSTG-CRYP-03** Sensitive info sent via unencrypted channels → `11-cryptography.md`
- [ ] **WSTG-CRYP-04** Weak encryption → `11-cryptography.md`

## BUSL — Business Logic

- [ ] **WSTG-BUSL-01** Business logic data validation → `10-business-logic.md`
- [ ] **WSTG-BUSL-02** Ability to forge requests → `10-business-logic.md`
- [ ] **WSTG-BUSL-03** Integrity checks → `10-business-logic.md`
- [ ] **WSTG-BUSL-04** Process timing → `10-business-logic.md`
- [ ] **WSTG-BUSL-05** Number of times a function can be used → `10-business-logic.md`
- [ ] **WSTG-BUSL-06** Circumvention of workflows → `10-business-logic.md`
- [ ] **WSTG-BUSL-07** Defenses against application misuse → `10-business-logic.md`
- [ ] **WSTG-BUSL-08** Upload of unexpected file types → `04-web-application.md`, `08-injection.md`
- [ ] **WSTG-BUSL-09** Upload of malicious files → `04-web-application.md`

## CLNT — Client-Side

- [ ] **WSTG-CLNT-01** DOM-based XSS → `09-client-side.md`
- [ ] **WSTG-CLNT-02** JavaScript execution → `09-client-side.md`
- [ ] **WSTG-CLNT-03** HTML injection → `09-client-side.md`
- [ ] **WSTG-CLNT-04** Client-side URL redirect → `09-client-side.md`
- [ ] **WSTG-CLNT-05** CSS injection → `09-client-side.md`
- [ ] **WSTG-CLNT-06** Client-side resource manipulation → `09-client-side.md`
- [ ] **WSTG-CLNT-07** CORS → `09-client-side.md`
- [ ] **WSTG-CLNT-08** Cross-site flashing → `09-client-side.md` (deprecated tech)
- [ ] **WSTG-CLNT-09** Clickjacking → `09-client-side.md`
- [ ] **WSTG-CLNT-10** WebSockets → `05-api-security.md`, `09-client-side.md`
- [ ] **WSTG-CLNT-11** Web messaging (postMessage) → `09-client-side.md`
- [ ] **WSTG-CLNT-12** Browser storage → `09-client-side.md`
- [ ] **WSTG-CLNT-13** Cross Origin Resource Inclusion → `09-client-side.md`

## API — API Testing (added in WSTG v4.2)

- [ ] **WSTG-APIT-01** GraphQL testing → `05-api-security.md`

---

## Coverage Notes

For each section above:
- ✓ = exercised, finding or no finding logged
- ⊘ = not applicable (note reason)
- ⚠ = partially exercised (note gap)
- ✗ = skipped without justification (resolve before report)

After all WSTG sections are addressed, run `framework/cognitive/self-critique.md`
phase critique to check for blind spots before declaring web-app coverage
complete.
