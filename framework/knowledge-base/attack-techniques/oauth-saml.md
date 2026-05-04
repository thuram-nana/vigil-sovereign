# OAuth / SAML / OIDC — technique reference

## 1. Mental model

Federated auth introduces a third party (Identity Provider) into the trust
boundary. The attack surface is the **integration**: how the Service Provider
(SP) talks to the IdP, how it validates assertions/tokens, and how it binds
identity to local accounts.

Most bugs are not in the IdP or in the libraries; they are in **glue code**
on the SP side: missing audience checks, permissive `redirect_uri`,
unsigned-assertion acceptance, account-linking races.

## 2. OAuth 2.0 / OIDC

### 2.1 Flow recap

| Flow | When | Risk |
|------|------|------|
| Authorization code (with PKCE) | server-side web apps, SPAs | safest; defaults |
| Authorization code (no PKCE) | older server apps | code leakage if `redirect_uri` permissive |
| Implicit | legacy SPA | tokens in URL fragment, leaks via referer / history; deprecated |
| Resource owner password credential | legacy / native | requires user creds; deprecated |
| Client credentials | machine-to-machine | no user identity |
| Device code | TVs, CLIs | phishing-prone; check user-binding |

### 2.2 redirect_uri attacks

The single most common OAuth bug class.

| Bug | Test |
|-----|------|
| Wildcard / suffix match | `redirect_uri=https://app.victim.tld.attacker.tld` accepted? |
| Open redirect on registered URI | `redirect_uri=https://app.victim.tld/redirect?to=https://attacker.tld` — chain with open redirect to leak code |
| Path traversal | `redirect_uri=https://app.victim.tld/../callback@attacker.tld` |
| Fragment in user-info | `https://attacker.tld#@app.victim.tld/cb` |
| Multiple values | some servers honour first match against allowlist but redirect to last value |
| Mismatch between request & token endpoint | `redirect_uri` differs at /authorize vs /token — should fail, sometimes doesn't |
| Localhost port permissive | `http://127.0.0.1:1` to `http://127.0.0.1:65535` all valid → registered loopback can be hijacked by app on host |

If you control where the code lands → ATO via account-linking on attacker account.

### 2.3 State / nonce / PKCE

- Missing `state` → CSRF on auth flow (attacker pre-authorises their own
  account to be linked to victim's logged-in session).
- Missing `nonce` (OIDC) → token replay.
- Missing PKCE for public clients → code interception in mobile / SPA.

### 2.4 Token attacks

- **Access token leaked** in referer header, JS bundle, log files. Tokens
  used in URL = guaranteed leakage.
- **id_token signature bypass** — see `jwt.md` (alg confusion, jku injection).
- **id_token audience confusion** — token issued for client A used at
  service B which accepts any token from same IdP.
- **`aud` claim is array** — service must check itself is included; some
  parse only first element.
- **Refresh token never rotated** — long-lived; revocation absent.

### 2.5 Account linking abuse

User has local account `victim@x.tld`. SSO with same email creates new account
or links to existing? Test:

- IdP claims unverified email → attacker's IdP (own provider) issues
  `email=victim@x.tld unverified` and SP links it to victim's account
  without verification → ATO.
- Race: register local account `victim@x.tld` while SSO user signs in for
  first time — winner controls account.

### 2.6 Discovery / DCR abuse

- `.well-known/openid-configuration` exposes endpoints, supported algs,
  signing keys (`jwks_uri`).
- Dynamic Client Registration (DCR) — if open, attacker registers client and
  can impersonate flows; rare.

### 2.7 Common injection points

- `client_id` — confusion attack (use legit client's ID, attacker's
  redirect)
- `scope` — request elevated scopes; SP may grant if user pre-consented
- `response_type` — switch from `code` to `token` (implicit) to leak via
  fragment
- `prompt` — `prompt=none` for silent re-auth → if SP doesn't validate
  identity continuity, can issue tokens for wrong user

## 3. SAML 2.0

### 3.1 Flow recap

User → SP, SP redirects to IdP with `SAMLRequest`, user authenticates at IdP,
IdP POSTs `SAMLResponse` (XML, signed) to SP's ACS endpoint. SP validates
signature, issuer, audience, conditions, then logs user in based on
`<Subject>`.

### 3.2 XML Signature Wrapping (XSW)

SAML signs only part of the document. By restructuring, attacker can have
SP read attacker-controlled subject while signature is verified over original
content. Many variants (XSW1–XSW8). Tools: SAMLRaider (Burp extension),
SAML Magic.

### 3.3 Signature exclusion

Strip the `<ds:Signature>` element entirely; if SP doesn't fail on missing
signature, accepts arbitrary assertion. Test against every assertion-receiving
endpoint.

### 3.4 Signature verification with attacker's key

Some implementations extract verifying key from `<ds:KeyInfo>` inside the
response (rather than configured trust). Embed your own cert, sign with
your key, accepted.

### 3.5 XXE in SAML parser

SAML responses are XML; parser may resolve external entities. Inject:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<samlp:Response>...&xxe;...</samlp:Response>
```

If SP echoes parse errors / data: file read; combined with SSRF: cloud
metadata.

### 3.6 Replay

Captured SAML response replayed to SP. Mitigations: `<Conditions
NotOnOrAfter>` enforcement, `<SubjectConfirmationData InResponseTo>`
enforcement, one-time-use tracking via `ID` attribute.

Test: capture legit response, replay 1h later, replay 24h later, replay
after logout.

### 3.7 IdP-initiated abuse

In IdP-initiated SSO, the IdP POSTs an unsolicited assertion to SP. If SP
doesn't track which assertions it requested (`InResponseTo`), attacker
captures any valid assertion and replays it from victim's browser.

### 3.8 RelayState

Untrusted parameter; treat as an open-redirect vector. Test: arbitrary URL,
javascript:, data:.

## 4. OIDC-specific

OIDC = OAuth + identity layer. JWT-based. Most OAuth bugs apply, plus:

- **`iss` mismatch** — token from wrong issuer accepted
- **`aud` not validated** — token issued for client X used at client Y
- **`azp` ignored** — when `aud` is array, `azp` (authorised party) should
  match client; often not checked
- **`acr` / `amr` claim trust** — SP trusts "MFA happened" without
  enforcing it
- **`sub` non-unique across IdPs** — using sub alone for identity is unsafe
  in multi-IdP deployments
- **userinfo endpoint pivot** — token meant only to sign in used to fetch
  PII via userinfo with no scope checks

## 5. Test plan (per integration)

For each SP–IdP integration:

- [ ] `redirect_uri` allowlist exact-match enforced?
- [ ] `state` required, validated, single-use?
- [ ] PKCE required for public clients?
- [ ] Authorization code single-use, time-bound (≤10min)?
- [ ] Token endpoint requires same `redirect_uri` and `client_id`?
- [ ] ID token signature verified (no `none`, alg pinned)?
- [ ] `iss`, `aud`, `azp`, `exp`, `iat`, `nbf`, `nonce` validated?
- [ ] SAML signature required, validated against pinned cert (not in-message
      cert)?
- [ ] SAML signature exclusion → reject?
- [ ] SAML XSW variants 1–8 → reject?
- [ ] SAML `Conditions` enforced?
- [ ] SAML one-time-use tracking?
- [ ] XXE in SAML parser disabled?
- [ ] RelayState validated?
- [ ] `prompt=none` doesn't permit identity swap?
- [ ] IdP-initiated SSO requires prior `InResponseTo`?
- [ ] Account linking requires verified email?
- [ ] Race on first-time SSO sign-in vs local registration?

## 6. Tools

- **SAMLRaider** — Burp extension; XSW automation, signature manipulation
- **EsPReSSO** — Burp extension; SAML / OAuth / OIDC inspection
- **OAuth-2.0-Burp-extension** — flow inspection
- **jwt_tool** — token forging
- **mitmproxy** — flow capture & replay
- **opensaml** / **lxml** — manual SAML manipulation in Python

## 7. CWE / standards mapping

- CWE-287, CWE-345, CWE-347 (auth, integrity, signature)
- CWE-918 — SSRF (often achieved via SAML XXE or OIDC discovery)
- OWASP ASVS V2.7 (federated identity)
- OWASP WSTG WSTG-IDNT-* and WSTG-ATHN-*
- OAuth 2.0 Security BCP RFC 8252, RFC 9700
- SAML 2.0 Security Considerations (OASIS)

## 8. Defenses (for remediation)

1. **Use libraries** — don't roll your own SAML or JWT verification.
2. **Validate everything** — issuer, audience, signature, expiry, nonce,
   subject confirmation, conditions.
3. **Allowlist, not regex** for `redirect_uri`.
4. **Disable XXE** — `defusedxml` or equivalent everywhere.
5. **Pin signing keys** — don't extract from messages; configure trust.
6. **PKCE for all clients**, including server-side (no harm).
7. **Verified email** required for account linking.
8. **Single-use auth codes & SAML responses**.
9. **No tokens in URLs**.
10. **Audit and alert** on cross-tenant or cross-IdP anomalies.
