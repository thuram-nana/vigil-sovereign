# Standards mapping reference

Cross-reference for OBSIDIAN to map findings, controls, and tactics
across the major industry standards. Use this when:

- Writing finding metadata that needs OWASP / CWE / CVE / ATT&CK refs.
- Producing a compliance-mapped technical-report appendix.
- Translating a finding into language a defender's monitoring team
  understands.

---

## OWASP Web Security Testing Guide v4.2

| Category | ID prefix | Playbook |
|----------|-----------|----------|
| Information Gathering | WSTG-INFO | 01–03 |
| Configuration & Deployment | WSTG-CONF | 02, 04 |
| Identity Management | WSTG-IDNT | 06 |
| Authentication | WSTG-ATHN | 06 |
| Authorization | WSTG-ATHZ | 07 |
| Session Management | WSTG-SESS | 06 |
| Input Validation | WSTG-INPV | 08, 09 |
| Error Handling | WSTG-ERRH | 04 |
| Cryptography | WSTG-CRYP | 11 |
| Business Logic | WSTG-BUSL | 10 |
| Client-Side | WSTG-CLNT | 09 |
| API | WSTG-APIT | 05 |

Full ID-by-ID checklist: `framework/checklists/owasp-wstg.md`.

---

## OWASP ASVS v4.0

14 chapters. Default to L2 unless charter specifies higher.

| V | Chapter | Notes |
|---|---------|-------|
| V1 | Architecture, Design, Threat Modeling | Charter + threat model docs |
| V2 | Authentication | Playbook 06 |
| V3 | Session Management | Playbook 06 |
| V4 | Access Control | Playbook 07 |
| V5 | Validation, Sanitization, Encoding | Playbook 08, 09 |
| V6 | Stored Cryptography | Playbook 11 |
| V7 | Error Handling and Logging | Playbook 04 |
| V8 | Data Protection | Playbook 22 |
| V9 | Communications | Playbook 11 |
| V10 | Malicious Code | Source review |
| V11 | Business Logic | Playbook 10 |
| V12 | Files and Resources | Playbook 08 |
| V13 | API and Web Service | Playbook 05 |
| V14 | Configuration | Playbook 02, 04 |

---

## OWASP API Security Top 10 (2023)

| # | Risk | Playbook section |
|---|------|------------------|
| API1:2023 | Broken Object Level Authorization | 05 §5.3, 07 §7.3 |
| API2:2023 | Broken Authentication | 05 §5.4, 06 |
| API3:2023 | Broken Object Property Level Authorization | 05 §5.5, 07 §7.4 |
| API4:2023 | Unrestricted Resource Consumption | 05 §5.6 |
| API5:2023 | Broken Function Level Authorization | 05 §5.7, 07 §7.2 |
| API6:2023 | Unrestricted Access to Sensitive Business Flows | 05 §5.8, 10 |
| API7:2023 | Server-Side Request Forgery | 08 §8.4 |
| API8:2023 | Security Misconfiguration | 05 §5.9 |
| API9:2023 | Improper Inventory Management | 05 §5.10 |
| API10:2023 | Unsafe Consumption of APIs | 05 §5.11 |

---

## OWASP Top 10 for LLM (2025)

| # | Risk | Playbook 18 section |
|---|------|---------------------|
| LLM01 | Prompt injection | §18.4 |
| LLM02 | Sensitive information disclosure | §18.5 |
| LLM03 | Supply chain | §18.6 |
| LLM04 | Data and model poisoning | §18.7 |
| LLM05 | Improper output handling | §18.8 |
| LLM06 | Excessive agency | §18.9 |
| LLM07 | System prompt leakage | §18.10 |
| LLM08 | Vector and embedding weaknesses | §18.11 |
| LLM09 | Misinformation | §18.12 |
| LLM10 | Unbounded consumption | §18.13 |

---

## OWASP MASVS v2.0 (Mobile)

| Group | Coverage |
|-------|----------|
| MASVS-STORAGE | Local data storage |
| MASVS-CRYPTO | Cryptography |
| MASVS-AUTH | Authentication and authorization |
| MASVS-NETWORK | Network communications |
| MASVS-PLATFORM | Platform interaction |
| MASVS-CODE | Code quality |
| MASVS-RESILIENCE | Resilience to reverse engineering |
| MASVS-PRIVACY | Privacy |

Playbook 17.

---

## MITRE ATT&CK Enterprise — tactics

14 tactics; key ones for web-app context:

| ID | Tactic | Web-app relevance |
|----|--------|-------------------|
| TA0043 | Reconnaissance | Stages 2, 3 |
| TA0001 | Initial Access | Auth bypass, exposed admin, public exploit |
| TA0002 | Execution | RCE via SSTI / deserialization / cmd inject |
| TA0003 | Persistence | Webshells, scheduled tasks |
| TA0004 | Privilege Escalation | App role escalation; OS PE if shell |
| TA0005 | Defense Evasion | Log tampering, WAF bypass |
| TA0006 | Credential Access | DB dump, JWT crack, hash crack |
| TA0007 | Discovery | Internal API enum, schema enum |
| TA0008 | Lateral Movement | SSRF to internal, internal API auth bypass |
| TA0009 | Collection | DB queries, IDOR enum, file reads |
| TA0010 | Exfiltration | DNS, HTTP, archive uploads |
| TA0040 | Impact | Data deletion, money movement |

Tag each finding with applicable tactic + technique IDs.

---

## CWE — Common Weakness Enumeration

Top 25 (2024):

| Rank | CWE | Title |
|------|-----|-------|
| 1 | CWE-79 | Cross-site scripting |
| 2 | CWE-787 | Out-of-bounds write |
| 3 | CWE-89 | SQL injection |
| 4 | CWE-352 | CSRF |
| 5 | CWE-22 | Path traversal |
| 6 | CWE-125 | Out-of-bounds read |
| 7 | CWE-78 | OS command injection |
| 8 | CWE-416 | Use after free |
| 9 | CWE-862 | Missing authorization |
| 10 | CWE-434 | Unrestricted file upload |
| 11 | CWE-94 | Code injection |
| 12 | CWE-20 | Improper input validation |
| 13 | CWE-77 | Command injection |
| 14 | CWE-287 | Improper authentication |
| 15 | CWE-269 | Improper privilege management |
| 16 | CWE-502 | Unsafe deserialization |
| 17 | CWE-200 | Information exposure |
| 18 | CWE-863 | Incorrect authorization |
| 19 | CWE-918 | SSRF |
| 20 | CWE-119 | Improper memory bounds |
| 21 | CWE-476 | NULL pointer dereference |
| 22 | CWE-798 | Hardcoded credentials |
| 23 | CWE-190 | Integer overflow |
| 24 | CWE-400 | Resource exhaustion |
| 25 | CWE-306 | Missing authentication |

Each finding gets a CWE ID for root cause; this also threads it
into industry research and tooling.

---

## CVSS 3.1 — severity baseline

Vector format: `CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_`.

| Score | Label |
|-------|-------|
| 9.0–10.0 | Critical |
| 7.0–8.9 | High |
| 4.0–6.9 | Medium |
| 0.1–3.9 | Low |
| 0.0 | None / Info |

Always pair base score with **contextual adjustment** explaining
why it's higher/lower for this specific product. See
`framework/cognitive/decision-frameworks.md`.

---

## PTES (Penetration Testing Execution Standard)

Seven phases:
1. Pre-engagement Interactions
2. Intelligence Gathering
3. Threat Modeling
4. Vulnerability Analysis
5. Exploitation
6. Post Exploitation
7. Reporting

Maps directly to engagement lifecycle (`ENGAGEMENT-LIFECYCLE.md`).

---

## NIST SP 800-115

Technical Guide to Information Security Testing and Assessment.
Useful for defining methodology in the executive report when the
operator needs gov-style references.

---

## PASTA (Process for Attack Simulation and Threat Analysis)

Seven-stage threat modeling. Heavier than STRIDE; reach for it on
engagements where governance / partner review demands defensible
threat-model artifacts.

See `framework/cognitive/threat-modeling.md` §8.

---

## Compliance frameworks (operator-specific)

When applicable to operator's regulatory context:

- **PCI-DSS v4.0** (payment card data).
- **SOC 2 Type 2** (service organization controls).
- **ISO 27001 / 27002** (ISMS).
- **HIPAA Security Rule** (US health).
- **GDPR / CCPA / state privacy laws**.
- **FedRAMP** (US federal cloud).
- **CIS Benchmarks** (cloud / OS hardening — applicable per stack).

Map findings to control IDs in the technical-report appendix when
relevant.
