# OWASP ASVS v4.0.3 — L2 Coverage Checklist

The Application Security Verification Standard provides three levels:
- **L1**: opportunistic — checks anything testable from outside.
- **L2**: standard — what most apps containing sensitive data need.
- **L3**: high-assurance — for systems requiring rigorous security.

CRUCIBLE engagements default to **L2** coverage. L3 items are tested
when applicable to the target's risk profile (financial, healthcare,
identity, infrastructure).

This checklist is the section index, not the full requirement text.
Refer to ASVS source for verbatim requirements. Each section maps to
playbooks that exercise it.

---

## V1 — Architecture, Design, Threat Modeling

- [ ] V1.1 Secure Software Development Lifecycle → `00-pre-engagement.md`, `targets/<n>/threat-model.md`
- [ ] V1.2 Authentication Architecture → `06-authentication-identity.md`
- [ ] V1.4 Access Control Architecture → `07-authorization.md`
- [ ] V1.5 Input and Output Architecture → `08-injection.md`, `09-client-side.md`
- [ ] V1.6 Cryptographic Architecture → `11-cryptography.md`
- [ ] V1.7 Errors, Logging Architecture → `04-web-application.md`
- [ ] V1.8 Data Protection Architecture → `22-data-exfiltration-impact.md`
- [ ] V1.9 Communications Architecture → `11-cryptography.md`, `12-network-infrastructure.md`
- [ ] V1.10 Malicious Software Architecture → `15-cicd-supply-chain.md`
- [ ] V1.11 Business Logic Architecture → `10-business-logic.md`
- [ ] V1.12 Secure File Upload Architecture → `04-web-application.md`
- [ ] V1.14 Configuration Architecture → `13-cloud-native.md`, `14-container-kubernetes.md`

## V2 — Authentication

- [ ] V2.1 Password Security → `06-authentication-identity.md` § 1
- [ ] V2.2 General Authenticator Security → `06-authentication-identity.md`
- [ ] V2.3 Authenticator Lifecycle → `06-authentication-identity.md`
- [ ] V2.4 Credential Storage → `06-authentication-identity.md`, `20-source-code-review.md`
- [ ] V2.5 Credential Recovery → `06-authentication-identity.md` § 5
- [ ] V2.6 Look-up Secret Verifier → `06-authentication-identity.md` (MFA backup codes)
- [ ] V2.7 Out of Band Verifier → `06-authentication-identity.md` § 6 (MFA)
- [ ] V2.8 Single or Multi Factor One Time Verifier → `06-authentication-identity.md`
- [ ] V2.9 Cryptographic Software and Devices Verifier → `06-authentication-identity.md`
- [ ] V2.10 Service Authentication → `05-api-security.md`, `06-authentication-identity.md`

## V3 — Session Management

- [ ] V3.1 Fundamental Session Management → `06-authentication-identity.md` § 7
- [ ] V3.2 Session Binding → `06-authentication-identity.md`
- [ ] V3.3 Session Logout and Timeout → `06-authentication-identity.md`
- [ ] V3.4 Cookie-based Session Management → `06-authentication-identity.md`, `09-client-side.md`
- [ ] V3.5 Token-based Session Management → `06-authentication-identity.md` (JWT)
- [ ] V3.6 Federated Re-authentication → `19-sso-federated.md`
- [ ] V3.7 Defenses Against Session Management Exploits → `06-authentication-identity.md`

## V4 — Access Control

- [ ] V4.1 General Access Control Design → `07-authorization.md`
- [ ] V4.2 Operation Level Access Control → `07-authorization.md` § 2
- [ ] V4.3 Other Access Control Considerations → `07-authorization.md`

## V5 — Validation, Sanitization, Encoding

- [ ] V5.1 Input Validation → `08-injection.md`, `09-client-side.md`
- [ ] V5.2 Sanitization and Sandboxing → `09-client-side.md`
- [ ] V5.3 Output Encoding and Injection Prevention → `08-injection.md`, `09-client-side.md`
- [ ] V5.4 Memory, String, and Unmanaged Code → `20-source-code-review.md`
- [ ] V5.5 Deserialization Prevention → `08-injection.md`, `20-source-code-review.md`

## V6 — Stored Cryptography

- [ ] V6.1 Data Classification → `targets/<n>/threat-model.md`
- [ ] V6.2 Algorithms → `11-cryptography.md` § 4
- [ ] V6.3 Random Values → `11-cryptography.md`, `auth/token-entropy.py`
- [ ] V6.4 Secret Management → `15-cicd-supply-chain.md`, `20-source-code-review.md`

## V7 — Error Handling and Logging

- [ ] V7.1 Log Content → `04-web-application.md`, `21-post-exploitation.md`
- [ ] V7.2 Log Processing → `12-network-infrastructure.md`
- [ ] V7.3 Log Protection → `12-network-infrastructure.md`
- [ ] V7.4 Error Handling → `04-web-application.md`

## V8 — Data Protection

- [ ] V8.1 General Data Protection → `22-data-exfiltration-impact.md`
- [ ] V8.2 Client-side Data Protection → `09-client-side.md`
- [ ] V8.3 Sensitive Private Data → `04-web-application.md`, `07-authorization.md`

## V9 — Communications

- [ ] V9.1 Client Communications Security → `11-cryptography.md`
- [ ] V9.2 Server Communications Security → `11-cryptography.md`, `12-network-infrastructure.md`

## V10 — Malicious Code

- [ ] V10.1 Code Integrity → `15-cicd-supply-chain.md`
- [ ] V10.2 Malicious Code Search → `20-source-code-review.md`
- [ ] V10.3 Application Integrity → `15-cicd-supply-chain.md`

## V11 — Business Logic

- [ ] V11.1 Business Logic Security → `10-business-logic.md`

## V12 — Files and Resources

- [ ] V12.1 File Upload → `04-web-application.md`
- [ ] V12.2 File Integrity → `04-web-application.md`
- [ ] V12.3 File Execution → `04-web-application.md`, `08-injection.md`
- [ ] V12.4 File Storage → `04-web-application.md`, `13-cloud-native.md`
- [ ] V12.5 File Download → `04-web-application.md`, `07-authorization.md`
- [ ] V12.6 SSRF Protection → `08-injection.md` § 3

## V13 — API and Web Service

- [ ] V13.1 Generic Web Service Security → `05-api-security.md`
- [ ] V13.2 RESTful Web Service → `05-api-security.md`
- [ ] V13.3 SOAP Web Service → `05-api-security.md`
- [ ] V13.4 GraphQL → `05-api-security.md` § 5

## V14 — Configuration

- [ ] V14.1 Build → `15-cicd-supply-chain.md`
- [ ] V14.2 Dependency → `15-cicd-supply-chain.md`, `20-source-code-review.md`
- [ ] V14.3 Unintended Security Disclosure → `04-web-application.md`
- [ ] V14.4 HTTP Security Headers → `04-web-application.md`, `09-client-side.md`
- [ ] V14.5 HTTP Request Header → `04-web-application.md`

---

## Coverage Notes

ASVS items often overlap WSTG and OWASP API Top 10. Avoid retesting —
mark this checklist by *cross-referencing* the same evidence used to
satisfy WSTG/API Top 10 items where they overlap.

For L3 escalation, additional items become testable that L2 only
*requires*. Identify those for high-risk targets.
