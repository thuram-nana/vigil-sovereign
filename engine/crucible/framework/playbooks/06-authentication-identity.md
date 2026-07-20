# Playbook 06 — Authentication and identity

**Goal:** find every way an attacker can log in as accounts they
don't own, register accounts with elevated privilege, or hijack
sessions.

This is the highest-priority playbook for any application where
users complain of being hacked. Spend disproportionate time here.

Aligned to OWASP WSTG-IDNT, WSTG-ATHN, WSTG-SESS, OWASP ASVS V2–V3.

---

## 6.1 Login — credential security

### 6.1.1 Rate limiting and lockout (per-user vs per-IP vs combined)

```bash
# scripts/auth/rate-limit-probe.sh in this framework
# Test per-account first:
for i in $(seq 1 50); do
  curl -sk -o /dev/null -w "%{http_code} %{time_total}\n" \
    -X POST "https://<target>/login" \
    -d "username=OBSIDIAN-TEST-userA&password=wrong-$i" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "User-Agent: OBSIDIAN/1.0 (authorized owner-test)"
  sleep 0.2
done
```

Then per-IP (50 different usernames, same IP), then combined
(credential stuffing simulation: many usernames, each with ~3 tries).

Findings:
- **No rate limit at all** → Critical.
- **Per-IP only** → bypassable via proxies; criminal-tier always has
  proxies.
- **Per-account only** → bypassable across many accounts.
- **Both, but lock the legitimate user out** → DoS via lockout
  flooding.
- **Lockout messages disclose username existence** → see §6.1.2.

### 6.1.2 Username enumeration

Compare error messages and timing on:
- Valid username + wrong password: "Invalid password"
- Invalid username + any password: "User does not exist"

Use `scripts/auth/auth-probe.py` to measure timing.

Both message and timing can disclose. Bcrypt validation takes
~250ms; missing-user error returns instantly. A reliable timing
delta of >75ms is enumerable.

Username enumeration also exists in:
- Registration ("username already taken").
- Password reset ("if the email exists, we sent a link" vs "we sent
  a link").
- Profile lookup endpoints.
- Forgot-username flow.

### 6.1.3 Credential stuffing protection

- CAPTCHA on login? When does it trigger?
- Have-I-Been-Pwned check on registration / change?
- Password complexity policy server-side enforced (not just client)?
- Breach list check on login (alert user that their password is in
  a known breach)?

### 6.1.4 Default credentials

- `admin / admin`, `admin / password`, `admin / 12345`, vendor-default.
- Lock out understanding before attempting.
- Per-vendor defaults documented in
  `framework/knowledge-base/default-credentials.md`.

### 6.1.5 SQL injection in login

Old but still found:
```
admin' --
admin'/*
admin' OR '1'='1
admin' OR '1'='1' --
```

Try in both username and password fields. With proper SQLi, returns
authenticated session. See playbook 08.

---

## 6.2 Registration

- **Email verification required?** Does an unverified account have
  any privileges?
- **Email/username collision**: register with email of existing user
  — does it overwrite, send takeover link, or reject?
- **HTML in fields** → stored XSS in admin panel (Critical if admin
  views user list).
- **Mass-assignment**: include `role=admin`, `is_admin=1`,
  `balance=99999`, `apiKey=xxx`, `tenant_id=<other tenant>` in
  registration body. (Playbook 07 §7.4.)
- **CAPTCHA** present and effective?
- **Rate limit per IP** to prevent bot mass-signup?
- **Disposable email check**? (low priority but worth noting).

```bash
# Mass-assignment test
curl -sk -X POST "https://<target>/register" \
  -d "username=OBSIDIAN-TEST-massassign&email=x@example.com&password=Aa1!aaaa&role=admin&is_admin=1&balance=999999&tenant_id=1" \
  -i | tee evidence/auth/mass-assign-register.txt
```

Then log in as that account and check whether `role=admin` took
effect.

---

## 6.3 Password reset — highest-risk flow

The most common ATO vector.

### 6.3.1 Token characteristics

Trigger reset on a self-controlled account. Capture token from email.
Inspect:

- **Length and charset**: 8-char numeric is brute-forceable in
  minutes; 16-char hex from `mt_rand()` may be predictable; 32-char
  hex/base64 from CSPRNG is fine.
- **Sequential / time-correlated?** Trigger 5–10 resets in
  succession. Sort tokens. Look for monotonic patterns.
- **JWT?** Decode (`jwt_tool <token>`). Check `alg`, signature,
  claims.

### 6.3.2 Token misuse

- **Reuse**: use it, use it again. Should fail second time.
- **Expiry**: wait 24h+, retry. Should fail.
- **Invalidate on password change** (without using token): trigger
  reset, ignore email, change password normally — does old token
  still work?
- **Invalidate on email change**: change email after triggering
  reset; does old reset link still work for old email?
- **Cross-account use**: reset for user A, capture token, try to
  apply to user B by tampering identifier in reset POST.
- **Token leak via Referer**: does the reset page load any external
  resources (analytics, fonts, recaptcha)? Token in URL → leaks.
- **Host header injection**:
  ```bash
  curl -sk -X POST "https://<target>/forgot-password" \
    -H "Host: attacker.example.com" \
    -d "email=raven-test-userA@yourdomain.com"
  ```
  Email arrives pointing to attacker domain → ATO via cache-poisoning,
  typo-squatting, or recipient confusion.
- **X-Forwarded-Host injection** — same idea, different header.

### 6.3.3 Reset response indistinguishability

Successful and unsuccessful reset triggers should return the *same*
response. If they differ in body or timing, attacker can enumerate
which emails are registered.

### 6.3.4 The "race the email" vector

If attacker can predict / observe the token before the user reads
the email, they win. Predictability + Host injection both enable
this.

---

## 6.4 MFA / 2FA

If 2FA exists:

- **Bypass via response tampering**: intercept verify response, swap
  401 → 200 or `{verified: false}` → `true`.
- **Bypass via missing enforcement**: API endpoint accepts
  authentication via session cookie alone, bypassing the 2FA gate
  the UI enforces.
- **Bypass via parameter manipulation**: `2fa_required=false` in
  request body or session.
- **OTP brute force**: rate-limit per account on OTP submit?
- **OTP code reuse**: same valid code submitted twice still works?
- **Timing window**: is it 30s for TOTP or hours-long (large window
  = brute-forceable)?
- **Backup codes**: generated from CSPRNG? Single-use enforced?
- **Recovery flow**: way to disable 2FA without 2FA?
  ("contact support" + social engineering counts).
- **Enrolment without password re-confirm**: if attacker has
  session via XSS, can they bind their own 2FA secret without
  knowing the password?
- **SMS-based 2FA**: SIM swap is real but out-of-scope to test;
  document the dependency.

---

## 6.5 Session management

### 6.5.1 Cookie attribute audit

For every cookie set by the app:

| Cookie | Secure | HttpOnly | SameSite | Path | Domain | Notes |
|--------|--------|----------|----------|------|--------|-------|

- **Missing HttpOnly** on session → XSS reads session → ATO.
- **Missing Secure** → leaks over plaintext.
- **`SameSite=None`** without business reason → CSRF risk.
- **Domain `.example.com`** when only apex needs it → leaks to
  vulnerable subdomains.
- **Path too broad**.

### 6.5.2 Session ID quality

```bash
# Capture 30+ session IDs from successive logins
python3 framework/scripts/session/session-entropy.py \
  --login-url https://<target>/login \
  --user OBSIDIAN-TEST-userA --password 'pwd' \
  --cookie-name PHPSESSID --samples 50
```

Look for: sequential, time-correlated, low entropy, sub-128-bit, or
predictable per-position patterns.

For deeper analysis: Burp Sequencer, `dieharder`.

### 6.5.3 Lifecycle

| Event | Must session ID rotate? |
|-------|------------------------|
| Login | Yes |
| Logout | Server-side invalidate |
| Password change | Yes (other sessions too) |
| 2FA enabled / disabled | Yes |
| Email change | Yes |
| Privilege escalation (rare) | Yes |

### 6.5.4 Fixation

Visit `/login` while logged out → server sets cookie X. Log in →
does session cookie change to Y, or does X become authenticated?
If X persists, fixation is possible.

### 6.5.5 Concurrent sessions

- App allows N sessions per account?
- "Current sessions" UI for user to review and revoke?
- Notification on new login from new device/IP?

### 6.5.6 CSRF

For every state-changing action:
- CSRF token present?
- Token bound to session?
- Token validated server-side (some apps generate tokens that they
  then accept any of)?
- `SameSite=Lax` cookie as defense alone — covers most modern
  browsers but not all.
- API endpoints using `Authorization` header (not cookies) — CSRF-
  immune.

Test: HTML form on attacker domain auto-submitting to victim's
authenticated endpoint.

---

## 6.6 JWT specifics

If the app uses JWTs anywhere:

```bash
jwt_tool <token>                       # decode
jwt_tool <token> -X a                  # alg=none bypass
jwt_tool <token> -X k                  # kid injection
jwt_tool <token> -X i                  # null sig
jwt_tool <token> -C -d /usr/share/wordlists/rockyou.txt   # crack secret offline
```

Findings:
- `alg: none` accepted.
- Weak HS256 secret (cracked offline → forge any token).
- `kid` parameter SQL/file injection.
- No expiry (`exp` missing).
- `exp` far in future (1 year+).
- Sensitive data in claims that's trusted server-side (`role`,
  `user_id`, `balance`).
- JWT not bound to user fingerprint (any device with the token wins).
- `aud`/`iss`/`nbf` not validated.

Algorithm-confusion: HS256 token with the public key as secret
bypassing RS256 — playbook 11 §11.3.

---

## 6.7 OAuth / OIDC — see playbook 19

Federated identity has its own playbook. Key checks repeated here:
- `state` parameter present and verified (CSRF protection in OAuth
  flow).
- Redirect URI exactly matched, not prefix-matched.
- `code` single-use server-side.
- `id_token` signature verified, `iss`/`aud`/`nonce` checked.

---

## 6.8 "Login as user" support feature

Many apps have admin "impersonate user" for support. Test:
- Logged out of admin → does impersonation session persist?
- Audit log of impersonation events visible to operator?
- Can support-tier role impersonate admins?
- Re-auth required to enter impersonate mode?

---

## 6.9 Password change

- Old password required? If not, XSS → password change → ATO.
- Password change invalidates other sessions?
- Notification email on password change?
- Notification email on email change to *both* old and new addresses?
- Notification email contains "If this wasn't you, click here" undo
  link?

---

## 6.10 Account recovery / "forgot username"

- Self-service account recovery uses similarly-strong tokens to
  password reset.
- "Forgot username, given email" flow: returns existing username or
  identical "if exists, we sent..." regardless?
- Account merge / link: can attacker link their account to victim's?

---

## 6.11 Output

Findings filed individually in `findings/`. Phase summary in
`notes/engagement-log.md`:

- Rate-limit posture (per-account, per-IP, both, neither).
- Username enumeration: yes/no, where.
- Reset token entropy and lifecycle assessment.
- 2FA posture.
- Mass-assignment surfaces found.
- Cookie hygiene.
- CSRF posture.
- JWT posture.
- **Account-takeover viable yes/no** — direct answer to operator's
  most pressing question.

If ATO is viable, surface to operator immediately, don't wait for
phase end.
