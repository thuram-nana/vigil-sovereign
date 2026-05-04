# Attack tree — `mrbeanpanel`

**Version:** 1.0 (initial draft, pre-engagement)
**Date:** 2026-05-04

The attack tree decomposes the operator's worst-case outcomes into the
intermediate goals and leaf attacks that produce them. Reading down a
branch tells you "to achieve X, an attacker would need to achieve A,
B, or C." Reading across the leaves tells you "here are the concrete
things to test for."

This is an *initial* tree. As the engagement proceeds, leaves are
checked off (tested), pruned (ruled out), or added (new ideas
emerge). Each leaf cross-references hypotheses in
`notes/hypotheses.md` and findings in `findings/` once confirmed.

Notation:
- `[√]` confirmed exploitable in this environment.
- `[X]` ruled out (tested, not exploitable).
- `[?]` not yet tested (the default).
- `[~]` partially tested or only theoretically applicable.

---

## ROOT — Compromise the panel and its users

Three top-level goals, each its own subtree:

- **G1.** Take over a customer account.
- **G2.** Manipulate balance / orders without paying.
- **G3.** Take over the platform itself (admin, server, source, data).

These are not exclusive. Most full-impact compromise paths chain
across all three: customer takeover → escalation → platform takeover.

---

## G1 — Customer account takeover

This is the operator's stated #1 concern. It is also the most common
incident reported by SMM panel operators across the industry. Many
paths.

```
G1. Take over a customer account
├── G1.1 Credential-based
│   ├── [?] L1.1.1 Credential stuffing from breach data
│   │       Pre-conditions: no MFA, no per-IP rate limit on login,
│   │       no CAPTCHA, no anti-stuffing intel. Verifies S-2.
│   ├── [?] L1.1.2 Brute force / password spraying
│   │       Pre-conditions: no account-lockout, no rate limiting.
│   ├── [?] L1.1.3 Default / weak admin credentials on a forgotten
│   │       admin account inherited from the codebase install.
│   └── [?] L1.1.4 Password reuse across the platform's own subdomains
│           or on the sister site (if same identity backend).
│
├── G1.2 Password reset abuse
│   ├── [?] L1.2.1 Predictable / low-entropy reset token (timestamp,
│   │       seq, weak RNG).
│   ├── [?] L1.2.2 Reset token reusable / not bound to a single use.
│   ├── [?] L1.2.3 Reset token bound to email but the email field
│   │       is the attacker's; account-merge / email-change race.
│   ├── [?] L1.2.4 Host-header injection in reset email — link points
│   │       to attacker domain.
│   ├── [?] L1.2.5 Reset endpoint also accepts ?email= or ?id= and
│   │       does not validate ownership (sets new password directly).
│   ├── [?] L1.2.6 Reset token leaked via Referer when victim opens
│   │       the link and a third-party script captures it.
│   └── [?] L1.2.7 Reset link still valid after subsequent reset
│           or after password change.
│
├── G1.3 Session and token weaknesses
│   ├── [?] L1.3.1 Predictable session ID / weak RNG.
│   ├── [?] L1.3.2 Session fixation — accepts attacker-supplied
│   │       session token at login.
│   ├── [?] L1.3.3 Session not invalidated server-side on logout.
│   ├── [?] L1.3.4 Session not invalidated on password change.
│   ├── [?] L1.3.5 Long-lived "remember me" cookie with insufficient
│   │       binding.
│   ├── [?] L1.3.6 Session cookie missing HttpOnly → XSS reads it.
│   ├── [?] L1.3.7 Session cookie missing Secure → MitM on a non-TLS
│   │       subpath.
│   ├── [?] L1.3.8 SameSite missing → CSRF can ride the session.
│   └── [?] L1.3.9 API key (per-customer for v2 API) leaked, weakly
│           generated, or undocumented retrieval endpoint.
│
├── G1.4 XSS / browser-side abuse
│   ├── [?] L1.4.1 Stored XSS in support ticket body / subject;
│   │       admin views ticket → admin compromised.
│   ├── [?] L1.4.2 Stored XSS in profile fields / display name;
│   │       any user listing → compromise.
│   ├── [?] L1.4.3 Stored XSS in order notes / link / target URL;
│   │       admin order view → admin compromised.
│   ├── [?] L1.4.4 Reflected XSS in search / error messages.
│   ├── [?] L1.4.5 DOM XSS via `location.hash` / `postMessage`.
│   ├── [?] L1.4.6 SVG / image / file upload XSS (admin opens proof).
│   └── [?] L1.4.7 CSP missing or bypassable (script-src 'unsafe-inline'
│           or wildcard).
│
├── G1.5 CSRF leading to account takeover
│   ├── [?] L1.5.1 Email-change endpoint not CSRF-protected.
│   ├── [?] L1.5.2 Password-change endpoint not CSRF-protected
│   │       and accepts new password without current.
│   ├── [?] L1.5.3 2FA-disable endpoint not CSRF-protected.
│   └── [?] L1.5.4 Cross-site request forgery via JSON / GET when
│           server accepts content-type variation.
│
├── G1.6 OAuth / social-login misuse (if integrated)
│   ├── [?] L1.6.1 Missing `state` → login CSRF / account binding.
│   ├── [?] L1.6.2 Loose redirect URI matching → token exfil.
│   ├── [?] L1.6.3 Email returned by IdP trusted without verification
│   │       claim → account merge via unverified email.
│   └── [?] L1.6.4 PKCE not enforced for public clients.
│
├── G1.7 IDOR on identity-related endpoints
│   ├── [?] L1.7.1 Email-change endpoint accepts user_id parameter.
│   ├── [?] L1.7.2 Phone-update endpoint accepts user_id.
│   ├── [?] L1.7.3 2FA-management endpoint accepts user_id.
│   └── [?] L1.7.4 API-key reveal / regenerate accepts user_id.
│
└── G1.8 MFA bypass (if MFA exists)
    ├── [?] L1.8.1 MFA check skipped on a specific endpoint
    │       (login flow inconsistency).
    ├── [?] L1.8.2 Backup-code generation / use unauthenticated
    │       past first factor.
    ├── [?] L1.8.3 Recovery / "lost device" flow weaker than MFA.
    └── [?] L1.8.4 Brute force of TOTP digits without rate limiting.
```

---

## G2 — Manipulate balance / orders without paying

Direct financial fraud against the panel. Distinct from G1: even with
no account takeover, the attacker may credit themselves or escape paying
for ordered work.

```
G2. Manipulate balance / orders without paying
├── G2.1 Webhook forgery
│   ├── [?] L2.1.1 No HMAC verification on PSP webhooks.
│   ├── [?] L2.1.2 HMAC verified but key is hardcoded / leaked.
│   ├── [?] L2.1.3 HMAC verified but on body the attacker controls
│   │       (verification scope wrong — e.g. just signature header).
│   ├── [?] L2.1.4 Timestamp not checked → replay of a real webhook.
│   ├── [?] L2.1.5 Idempotency key not enforced → real webhook
│   │       processed multiple times.
│   ├── [?] L2.1.6 Webhook trusts a `user_id` field from request body
│   │       rather than mapping the PSP's reference to internal user.
│   └── [?] L2.1.7 Webhook is reachable on a path that also accepts
│           the ingest under a different content-type, bypassing
│           verification.
│
├── G2.2 Race conditions on credit / debit
│   ├── [?] L2.2.1 Refund + use race — refund issued for an order
│   │       that already debited; concurrent withdrawal exceeds balance.
│   ├── [?] L2.2.2 Top-up confirmation race — concurrent webhooks for
│   │       the same payment credit twice.
│   ├── [?] L2.2.3 Order place + cancel race — cancellation refunds
│   │       balance after upstream already accepted; net free order.
│   ├── [?] L2.2.4 Negative-amount / underflow on order place if
│   │       quantity * price overflows.
│   ├── [?] L2.2.5 Promo / coupon stacking — two simultaneous
│   │       requests apply the same single-use coupon.
│   └── [?] L2.2.6 Currency conversion race when balance is in
│           multiple currencies.
│
├── G2.3 Amount / currency manipulation in PSP redirect
│   ├── [?] L2.3.1 Amount sent to PSP is parameterized client-side
│   │       and not re-validated server-side on callback.
│   ├── [?] L2.3.2 Currency parameter in callback trusted, server
│   │       credits at higher-value currency.
│   ├── [?] L2.3.3 Successful-payment URL hit directly without
│   │       actually paying (server uses the redirect, not the
│   │       webhook, as the truth).
│   └── [?] L2.3.4 Crypto top-up: amount confirmed at sub-confirmation
│           threshold; chain reorg / RBF reverses the payment but
│           balance stays.
│
├── G2.4 Refund / chargeback abuse
│   ├── [?] L2.4.1 User-initiated refund flow accepts arbitrary amount
│   │       up to original.
│   ├── [?] L2.4.2 Refund flow runs even if the order's value has
│   │       been spent (refund creates negative-balance state silently).
│   └── [?] L2.4.3 Self-refund of own deposit while balance is in use.
│
├── G2.5 Coupon / referral fraud
│   ├── [?] L2.5.1 Self-referral — register, refer self via second
│   │       account, collect bonus, repeat.
│   ├── [?] L2.5.2 Coupon stacking outside intended composition rules.
│   └── [?] L2.5.3 Welcome bonus farming via account churning.
│
└── G2.6 Order manipulation post-creation
    ├── [?] L2.6.1 Edit order quantity / target after submission to
    │       upstream — server allows but doesn't reconcile cost.
    ├── [?] L2.6.2 Status manipulation — mark an order Completed /
    │       Refunded via direct API.
    └── [?] L2.6.3 Refill abuse — request unlimited refills for a
            non-refillable service.
```

---

## G3 — Take over the platform itself

Anything that lets the attacker reach admin, the database, the
filesystem, the source, or the network. The really bad outcomes.

```
G3. Take over the platform
├── G3.1 Vertical privilege escalation
│   ├── [?] L3.1.1 Admin endpoints reachable by URL guess; auth check
│   │       is "logged in" not "is admin."
│   ├── [?] L3.1.2 Mass assignment on profile update sets `role`
│   │       / `is_admin` field.
│   ├── [?] L3.1.3 Role / group ID guessable via IDOR; user assigns
│   │       themselves to an admin group.
│   ├── [?] L3.1.4 Forgotten staff account with default credentials.
│   ├── [?] L3.1.5 Staging admin reachable from public internet.
│   └── [?] L3.1.6 Impersonation feature accepts arbitrary user IDs
│           without being limited to admin.
│
├── G3.2 SQL injection
│   ├── [?] L3.2.1 In customer-facing search / sort / filter.
│   ├── [?] L3.2.2 In API v2 parameters (action, service, link).
│   ├── [?] L3.2.3 In admin-only surfaces (reachable post-G3.1).
│   ├── [?] L3.2.4 Second-order SQLi via stored fields rendered in
│   │       admin reports.
│   └── [?] L3.2.5 In legacy / forgotten endpoints surfaced via recon.
│
├── G3.3 Server-side request forgery
│   ├── [?] L3.3.1 Avatar / image fetch from user URL.
│   ├── [?] L3.3.2 Webhook tester / "test integration" that fetches
│   │       a user URL.
│   ├── [?] L3.3.3 Service-import endpoint that reads from an upstream
│   │       URL.
│   ├── [?] L3.3.4 Escalates to cloud-metadata read (AWS / GCP / Azure
│   │       / DO instance metadata).
│   ├── [?] L3.3.5 Escalates to internal admin via 127.0.0.1 / link-
│   │       local.
│   └── [?] L3.3.6 DNS rebinding bypass of validation.
│
├── G3.4 RCE
│   ├── [?] L3.4.1 File-upload to webroot with executable extension.
│   ├── [?] L3.4.2 Image library CVE (ImageMagick, GD, libvips,
│   │       phpThumb) on uploaded image.
│   ├── [?] L3.4.3 PHP `unserialize` on cookie / POST data
│   │       (deserialization).
│   ├── [?] L3.4.4 Template injection in a server-rendered template
│   │       (Twig / Smarty / similar).
│   ├── [?] L3.4.5 LFI → RCE via log file inclusion / session file
│   │       poisoning.
│   ├── [?] L3.4.6 Known CVE on the panel codebase if version
│   │       fingerprinted.
│   └── [?] L3.4.7 Known CVE on a dependency reachable from user input.
│
├── G3.5 Source / config disclosure
│   ├── [?] L3.5.1 `.git/` exposed under webroot.
│   ├── [?] L3.5.2 `.env` / `config.php` accessible via path tricks.
│   ├── [?] L3.5.3 Backup files (`config.php.bak`, `~`, `.swp`).
│   ├── [?] L3.5.4 phpinfo / debug page reachable.
│   ├── [?] L3.5.5 Staging / dev instance with display_errors and
│   │       debug enabled.
│   └── [?] L3.5.6 SourceMap / un-minified bundle disclosing logic.
│
├── G3.6 Subdomain takeover
│   ├── [?] L3.6.1 Stale CNAME to deprovisioned third-party
│   │       (S3, GitHub Pages, Heroku, Netlify, Azure web app).
│   └── [?] L3.6.2 Wildcard DNS to a host reachable as the attacker.
│
├── G3.7 Secret / key leak
│   ├── [?] L3.7.1 PSP key in client-side JS (front-end build leak).
│   ├── [?] L3.7.2 PSP key in a back-end response that should not
│   │       include it (admin-config endpoint without auth).
│   ├── [?] L3.7.3 Internal key in an error message at high verbosity.
│   ├── [?] L3.7.4 Key exposed in CSV / billing export.
│   └── [?] L3.7.5 Key committed to a public repo (Github dorks).
│
└── G3.8 Indicator of prior compromise
    ├── [?] L3.8.1 Unknown admin account.
    ├── [?] L3.8.2 Modified core file in webroot.
    ├── [?] L3.8.3 Suspicious cron / systemd service.
    ├── [?] L3.8.4 Outbound connections to unfamiliar destinations.
    └── [?] L3.8.5 Webshell at a guessable path (`/tmp.php`,
            `/uploads/<random>.php`).
```

---

## Cross-cutting branches

Some attacks don't sit cleanly under one root goal because they enable
many. They are in their own short trees here for completeness.

```
C1. Public reconnaissance leakage
├── [?] L4.1.1 GitHub dorks reveal old code / config of the panel.
├── [?] L4.1.2 Panel's own `robots.txt`, `sitemap.xml` reveal admin
│       routes.
├── [?] L4.1.3 JS source maps disclosed (if SPA).
└── [?] L4.1.4 Wayback Machine has older config / endpoints.

C2. Operational / infrastructure
├── [?] L4.2.1 SSH bruteforce surface (if SSH exposed publicly).
├── [?] L4.2.2 Out-of-date OS / runtime with exploitable CVE.
└── [?] L4.2.3 Backup endpoint / snapshot publicly accessible
        (S3 bucket, exposed `/backup/`).

C3. Customer-facing API (v2) abuse
├── [?] L4.3.1 No rate limit on `/api/v2` per API key.
├── [?] L4.3.2 API key disclosure via support / logs / referer.
├── [?] L4.3.3 IDOR on `status` action (read another user's order
│       by guessing order ID).
└── [?] L4.3.4 `add` action with manipulated price / quantity.
```

---

## Update log

| Date | Version | Change |
|------|---------|--------|
| 2026-05-04 | 1.0 | Initial pre-engagement draft. |
| | | (Updates as leaves are tested.) |
