# Authentication bypass — technique reference

## 1. Mental model

Authentication answers *"is the requester who they claim?"*. Failures fall
into a few buckets:

1. **No authentication required** when there should be (forgotten endpoint).
2. **Weak factor** — guessable secret, no rate limiting, no lockout.
3. **Bypass via parallel paths** — alternative login endpoints with weaker
   protections (admin-only login page that's actually exposed; mobile API
   with looser checks; legacy SOAP service still on).
4. **State machine flaws** — pre-auth endpoints leak post-auth data;
   half-authenticated sessions accept full-authenticated actions.
5. **Token / credential abuse** — token replay, session fixation, predictable
   tokens, leaked tokens.
6. **Recovery-flow abuse** — password reset, email change, MFA disable
   pathways trusted too much.
7. **Federated-auth misconfig** — OAuth/SAML/OIDC where assertions are not
   validated, audiences mismatch, account binding races.
8. **Implicit trust signals** — IP allowlist, cookie presence (without
   integrity), header presence (`X-Forwarded-For`, `X-Internal: true`).

## 2. Surface inventory

For every target, list every authentication-related endpoint:

- `/login`, `/signin`, `/auth`, `/oauth/token`, `/api/v1/login`, `/wp-login.php`
- `/admin/login`, `/dashboard/login`, `/staff/login`
- `/register`, `/signup`
- `/forgot-password`, `/reset-password`, `/password/reset`
- `/verify-email`, `/confirm`
- `/mfa`, `/totp/verify`, `/2fa/setup`, `/u2f/`, `/webauthn/`
- `/oauth/authorize`, `/oauth/callback`, `/.well-known/openid-configuration`
- `/saml/metadata`, `/saml/acs`, `/saml/sls`
- `/api-keys`, `/personal-access-tokens`
- `/impersonate`, `/su`, `/switch-user`
- Mobile API equivalents (often `/api/v1/...` with looser protections)

## 3. Login-form attacks

### 3.1 Username enumeration

If wrong-password and wrong-username produce **distinguishable responses**
(text, status, timing, header), attacker enumerates valid users.

Test: `wrong:wrong` vs `<known-good-user>:wrong`. Compare:

- HTTP status (401 vs 403 vs 200)
- Response body content / length
- Response time (database lookup vs constant fail path)
- Response headers (`Set-Cookie` only on real user)
- Subsequent challenges (CAPTCHA presented for valid user)

Other endpoints that enumerate: registration ("email already taken"), forgot
password ("we sent an email" vs "user not found"), invitation flows.

### 3.2 No / weak rate limiting

Test 100 requests rapidly with same source IP, same UA, same form. If all
accepted: no rate limit. Test bypass vectors:

- Rotating `X-Forwarded-For`, `X-Real-IP`, `Forwarded`
- Rotating User-Agent
- Adding random query string parameter (cache-buster confuses some WAFs)
- Username variations (`user`, `User`, `USER`, `user@x.com`, `user+1@x.com`)
- Distributed source IPs (proxy chain) — usually scope-out unless explicitly
  permitted
- HTTP/2 multiplexing — many requests one connection
- Different endpoint variant (mobile API vs web)

### 3.3 Account lockout — bug or feature?

If lockout exists, it's also a denial-of-service vector — attacker locks
out victims. Test: 5 failed attempts on victim's account → can victim still
log in? Soft lockout (CAPTCHA) preferred; hard lockout (account disabled
30min) is itself a bug if attacker-triggerable.

### 3.4 Password policy

Try `password`, `123456`, `qwerty`, `Pa$$w0rd!`. If accepted: weak policy.
Document for executive summary; not a finding by itself unless leadership
classifies as such, but raises attack viability for credential stuffing.

### 3.5 Credential stuffing window

If breached-corpus credentials work (have-i-been-pwned via email match), the
auth surface is exposed. Test only with credentials YOU own (don't try
random users' breach data — see opsec).

### 3.6 SQLi / NoSQLi in login

Always test:

```
admin' --
admin' OR '1'='1
{"$ne":null}            # NoSQL — submitted as JSON value
{"$gt":""}
admin'/*
admin' OR sleep(5)#
```

## 4. Session / token attacks

### 4.1 Session fixation

App accepts session ID from URL or pre-login cookie, doesn't rotate after
auth. Test: set cookie to known value, log in, observe cookie unchanged →
attacker can pre-set victim's cookie.

### 4.2 Token predictability

If session token has structure (timestamp + counter, base64 of user ID +
random), entropy may be insufficient. Sample 200 tokens, run through ent /
dieharder, look for structure.

### 4.3 Token leakage

- Logged in URL → server logs, browser history, referrer headers
- Sent over HTTP → MITM
- Stored in localStorage → XSS-readable
- Echoed in error pages
- Returned in CORS-permissive endpoints to attacker origin

### 4.4 Cookie attribute audit

`Secure`, `HttpOnly`, `SameSite=Strict|Lax`, `Path`, `Domain`, `Expires`/
`Max-Age`, prefix `__Host-`, `__Secure-`. Missing flags = additional risk.

### 4.5 Session never expires

Capture session cookie, leave for 30 days, reuse. If still valid: missing
absolute timeout.

### 4.6 Concurrent sessions

Some apps require single-session enforcement (banks); some don't. Test
behavior per spec — if spec says single, but two sessions coexist, it's a
finding.

## 5. Recovery flow attacks

### 5.1 Password reset

Attack matrix:

| Vector | Test |
|--------|------|
| Token predictability | request resets, examine token entropy / format |
| Token expiration | use token after long delay (1h, 24h, 7d) |
| Token reuse | use token, then use it again |
| Token via email-injection | `email=victim@x.tld%0aBcc:attacker@y.tld` |
| Host header injection | reset email contains attacker-controlled host in link |
| Account-binding bypass | reset token for user A used to set user B's pw via parameter swap |
| User enumeration via reset | "we sent email" vs "user not found" |
| Race on consume | use token in 20 parallel requests — set N different passwords |

### 5.2 Email change

Often weaker than password reset:

- Confirms only at new address (attacker confirms their own email)
- Old-email notification missing → silent takeover
- No re-auth required mid-session
- Bypass MFA by changing email then triggering reset

### 5.3 Account recovery via support / OOB

Out-of-scope for most engagements but document the path: if support resets
password without identity proof, social engineering is the bug.

## 6. MFA bypass

| Bug | Test |
|-----|------|
| Skip step | log in, drop MFA request, jump straight to /dashboard |
| Status flag | request `MFA-Verified: true` header returned in JSON, edit and resubmit |
| OTP brute-force without rate limit | try 100 codes |
| OTP reuse | use same code twice — should fail second time |
| OTP race | submit same code in parallel sessions |
| Backup code abuse | request many sets, accumulate; rate-limit on use? |
| TOTP time-window too wide | acceptable codes for ±5 minutes — replay window |
| Forgot-MFA flow | "lost my device" path is often weaker than primary auth |
| MFA enrollment hijack | attacker enrolls their device on victim's account during login flow |
| WebAuthn attestation skipped | client sends arbitrary attestation, accepted |
| Push-notification fatigue | repeated push prompts until victim accepts |
| OAuth path skips MFA | google login bypasses local MFA setting |

## 7. Header-based "auth"

Apps that trust headers from "internal" callers but expose them to web:

```
X-User: admin
X-Internal: true
X-Forwarded-User: alice@x.tld
Authorization: Bearer service-key   # if service token leaked / hardcoded
X-Admin-Secret: ...
```

Test by sending these on regular endpoints. If admin paths accept
`X-User: admin`: critical bypass.

## 8. Pre-auth → post-auth leakage

Endpoints meant for logged-in users sometimes work without session, returning
data based on parameter:

```
GET /api/me         (no cookie)        -> 401  (good)
GET /api/users/123  (no cookie)        -> data (bad — public IDOR)
GET /api/orders     (no cookie)        -> empty list (ok-ish)
GET /api/orders/1   (no cookie)        -> order data (bad)
```

Test every endpoint with no auth, expired auth, and other-user auth.

## 9. Federated SSO bugs

Cross-reference `oauth-saml.md` (separate file). Quick hits:

- OAuth `redirect_uri` allowlist permissive (`redirect_uri=https://attacker.tld`)
- Implicit-flow leaks token via fragment
- SAML XML signature wrapping (XSW)
- IdP-initiated SSO accepts arbitrary identity assertions
- Account-binding race: signup with email matching SSO claim before SSO user signs in → attacker controls account

## 10. Source code review

```
grep -rEn "skip_authentication|skipAuth|allowAll|permitAll" --include='*.java' --include='*.cs' --include='*.rb'
grep -rEn "@PreAuthorize|@Secured|@RolesAllowed" --include='*.java'  # what's NOT decorated
grep -rEn "before_action.*authenticate" --include='*.rb'              # missing "skip" exceptions
grep -rEn "request\.headers\['X-User'\]"                              # header trust
grep -rEn "verify=False|verify_signature\s*=\s*False"
grep -rEn "bcrypt\.compare|password\s*==|crypt\("                     # plain ==
grep -rEn "request\.session\[:user_id\]\s*=" --include='*.rb'         # set without challenge
```

## 11. Defenses (for remediation)

1. **Allowlist auth** — every endpoint denied by default, explicit allow
   for public ones.
2. **Rate-limit auth endpoints** with per-account and per-IP buckets, plus
   global anomaly detection.
3. **Generic responses** — same message for "user doesn't exist" and "wrong
   password".
4. **Strong password policy** + breached-password check (HIBP API or local
   list).
5. **MFA mandatory** for admin and high-value accounts; soft-prompt for all.
6. **Session rotation** on auth; absolute + idle timeout; revocation list.
7. **Strict cookie flags** — `Secure`, `HttpOnly`, `SameSite`, `__Host-`.
8. **Recovery flows** — single-use, time-bound tokens, both-address
   notifications, re-authenticate before destructive changes.
9. **No header-based trust** for internal services; use mTLS or signed
   tokens.
10. **Audit logging** with anomaly alerting.

## 12. CWE / standards mapping

- CWE-287 — Improper authentication
- CWE-307 — Improper restriction of excessive auth attempts
- CWE-521 — Weak password requirements
- CWE-613 — Insufficient session expiration
- CWE-640 — Weak password recovery
- CWE-384 — Session fixation
- CWE-639 — Authorisation bypass through user-controlled key
- OWASP WSTG WSTG-ATHN-* (entire family), WSTG-SESS-*, WSTG-IDNT-*
- OWASP ASVS V2, V3
- OWASP API Top 10 2023 API2

## 13. Tools

- Burp Suite — Repeater, Intruder for auth manipulation
- AuthMatrix, Autorize — Burp extensions
- patator, hydra, medusa — credential brute-force (use sparingly, scope first)
- evilginx2 — phishing-proxy demonstration of MFA bypass on cookies (only in
  authorised social-engineering scope)
- jwt_tool — for JWT-based session attacks
