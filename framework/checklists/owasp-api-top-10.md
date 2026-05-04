# OWASP API Security Top 10 (2023) Checklist

The 2023 revision. Each item maps to the playbook section that covers
the technique. Review each against every API surface (REST, GraphQL,
gRPC, SOAP, WebSocket).

---

## API1:2023 — Broken Object Level Authorization (BOLA / IDOR)

> The most consequential API vulnerability class — direct access to
> resources by ID without ownership check.

- [ ] All `GET /resource/{id}` style endpoints tested with attacker token vs. victim resource
- [ ] All `PUT/PATCH/DELETE /resource/{id}` tested for cross-tenant write
- [ ] UUID/random IDs tested via referrer / response leakage / known IDs
- [ ] Numeric IDs tested with sequential and adjacent values
- [ ] Nested resources tested (e.g., `/users/{u}/orders/{o}` — both IDs swappable)
- [ ] Bulk endpoints tested (single-id auth check; bulk-id check missing)
- [ ] Search/filter endpoints tested for unbounded result sets
- [ ] Run `framework/scripts/auth/idor-sweep.py` for systematic coverage
- **Playbook:** `07-authorization.md` § 1
- **Knowledge:** `attack-techniques/idor.md`

## API2:2023 — Broken Authentication

- [ ] Login: brute-force protection (account lockout, rate limit, CAPTCHA)
- [ ] Login: credential stuffing protection (compromised-password reject)
- [ ] Login: timing-safe credential comparison
- [ ] Password reset: token unguessable, single-use, time-bound, scope-bound
- [ ] Password reset: no host header injection on reset link
- [ ] MFA: enrollment flow not bypassable
- [ ] MFA: backup codes generated securely
- [ ] MFA: cannot be disabled without re-auth
- [ ] Session: cookies HttpOnly + Secure + SameSite
- [ ] Session: token rotation on auth state change
- [ ] Session: server-side invalidation on logout
- [ ] JWT: alg=none rejected, key confusion mitigated, weak secrets cracked-resistant
- [ ] JWT: kid traversal blocked, JWKS spoofing blocked
- [ ] OAuth: state parameter required, PKCE on public clients
- [ ] OAuth: redirect_uri strict-matched
- [ ] API keys: rotated, scoped, revocable
- **Playbook:** `06-authentication-identity.md`, `19-sso-federated.md`
- **Knowledge:** `attack-techniques/jwt.md`, `attack-techniques/oauth-saml.md`, `attack-techniques/authentication-bypass.md`

## API3:2023 — Broken Object Property Level Authorization (BOPLA)

> Mass assignment + excessive data exposure combined into one category.

- [ ] PATCH/PUT requests tested with extra fields (`role`, `is_admin`, `org_id`, `verified`, `balance`)
- [ ] Response bodies inspected for fields the client doesn't display (PII leakage)
- [ ] GraphQL queries inspected for over-fetching protected fields
- [ ] Nested objects: child object authorization checked separately from parent
- [ ] `/me` and `/profile` endpoints: writable fields enumerated
- [ ] Sensitive fields excluded from generic serializers (passwords, tokens, internal flags)
- **Playbook:** `07-authorization.md` § 3
- **Knowledge:** `attack-techniques/idor.md`

## API4:2023 — Unrestricted Resource Consumption

- [ ] Rate limits enforced per IP **and** per user (one without the other is bypassable)
- [ ] Login endpoint rate-limited
- [ ] Password reset rate-limited (avoid email-bomb / enumeration)
- [ ] Search/filter endpoints have `limit` cap server-side
- [ ] File upload size limited
- [ ] Image processing has dimension/size cap (avoid pixel-bombs)
- [ ] PDF/document parsing has memory cap (avoid zip-bomb-equivalents)
- [ ] GraphQL: query depth limited
- [ ] GraphQL: query complexity / cost analysis enforced
- [ ] GraphQL: alias overload / batching cap
- [ ] Outbound calls (SMS, email, webhooks) rate-limited per user
- [ ] Background job queues bounded (no infinite enqueue)
- **Playbook:** `05-api-security.md` § 4

## API5:2023 — Broken Function Level Authorization (BFLA)

- [ ] Admin endpoints (`/admin/*`) tested with non-admin token (expect 403)
- [ ] Admin endpoints tested with no token (expect 401, not 200)
- [ ] HTTP method tampering tested (`POST` → `GET` / `DELETE` / `PATCH`)
- [ ] Role-bypass via header injection (`X-Role`, `X-Admin`) tested
- [ ] Role-bypass via path traversal (`/api/v1/../admin/x`) tested
- [ ] Role-bypass via parameter injection (`?role=admin`, `?is_admin=true`) tested
- [ ] Tenant isolation: org A user accessing org B endpoint
- **Playbook:** `07-authorization.md` § 2

## API6:2023 — Unrestricted Access to Sensitive Business Flows

> New 2023 category — the "automated abuse" class.

- [ ] Account creation: bot-protected (CAPTCHA, behavioral analysis, email verification)
- [ ] Order/transaction flows: automation-resistant (CAPTCHA on suspicious patterns)
- [ ] Comment/review/posting flows: spam-resistant
- [ ] Coupon redemption: bulk-redemption blocked
- [ ] Referral programs: self-referral / synthetic-account farming blocked
- [ ] Limited inventory: scalping resistant (queue, fair-share, hold-cap)
- [ ] Pricing endpoints: scrape-resistant (rate limit, watermarking)
- [ ] Trial accounts: device fingerprinting / disposable-email blocking
- **Playbook:** `10-business-logic.md`

## API7:2023 — Server-Side Request Forgery (SSRF)

- [ ] Webhook URL fields tested with: `127.0.0.1`, `localhost`, `169.254.169.254`, `metadata.google.internal`, `[::1]`, `0.0.0.0`
- [ ] URL-fetching endpoints tested: PDF generators, screenshot services, OG tag fetchers, image proxies
- [ ] Bypass techniques: DNS rebinding, IP encoding (decimal, octal, hex), redirect chain
- [ ] Bypass techniques: alternate schemas (`gopher://`, `file://`, `dict://`, `ftp://`)
- [ ] Cloud metadata reachability tested (AWS IMDSv1/v2, GCP, Azure)
- [ ] Internal service enumeration via response timing / size diff
- [ ] Run `framework/scripts/api/ssrf-probe.py`
- **Playbook:** `08-injection.md` § 3
- **Knowledge:** `attack-techniques/ssrf.md`

## API8:2023 — Security Misconfiguration

- [ ] Debug endpoints disabled in production (`/debug`, `/__profiler__`, `/_status`)
- [ ] Error responses don't leak stack traces, internal IPs, framework versions
- [ ] CORS: `Access-Control-Allow-Origin` is not `*` for credentialed endpoints
- [ ] CORS: `Allow-Origin` is not reflected from request `Origin` (effectively wildcard)
- [ ] HTTP methods: `OPTIONS` / `TRACE` / `PUT` / `DELETE` not enabled where unnecessary
- [ ] Security headers present: HSTS, X-Content-Type-Options, X-Frame-Options/CSP frame-ancestors, Referrer-Policy
- [ ] Server / framework version banners stripped (`Server:`, `X-Powered-By:`)
- [ ] Default credentials changed (admin/admin, postgres/postgres, etc.)
- [ ] Default endpoints removed (Swagger UI in production, /actuator/* unauthenticated)
- [ ] TLS: 1.2+ only, weak ciphers disabled
- [ ] Out-of-date dependencies (CVE check via `dependency-check`, `snyk`, `pip-audit`)
- **Playbook:** `04-web-application.md`, `12-network-infrastructure.md`

## API9:2023 — Improper Inventory Management

- [ ] Old API versions (`/v1/`, `/v2/`) still reachable, fully enumerated
- [ ] Pre-prod environments (staging, dev, qa) accessible — and authentication identical to prod?
- [ ] Documentation (Swagger/OpenAPI/GraphQL schema) accessible: enumerated and used as a roadmap
- [ ] Deprecated endpoints checked for missing security controls (legacy auth, no rate limit)
- [ ] Hostname inventory cross-referenced with documented hostnames — undocumented hosts investigated
- [ ] Mobile/desktop client endpoints discovered (often a parallel API surface with weaker controls)
- **Playbook:** `01-passive-recon.md`, `02-active-recon.md`, `03-attack-surface-mapping.md`

## API10:2023 — Unsafe Consumption of APIs

> The application *as the consumer* of third-party APIs.

- [ ] Third-party API responses validated before deserialization
- [ ] Third-party API responses sanitized before returning to client (XSS via supplier)
- [ ] Third-party API timeouts set (avoid resource exhaustion)
- [ ] Third-party redirects not blindly followed (SSRF expansion)
- [ ] Third-party API errors handled (no stack trace leakage)
- [ ] Third-party API auth credentials stored securely (no hardcoded keys)
- [ ] Webhook *receivers* verify signatures (HMAC, timestamps)
- [ ] Webhook *receivers* enforce rate limits
- **Playbook:** `05-api-security.md` § 7

---

## Coverage Notes

After running through this checklist:
1. Confirm each endpoint inventoried in `targets/<name>/recon/` was
   evaluated against each applicable item.
2. Items marked "tested → no finding" must have evidence (request
   captures, response samples) under `targets/<name>/evidence/`.
3. Items marked "not applicable" must justify why (e.g., "no GraphQL
   surface").
4. Run final critique: would another tester, given this same surface,
   find something we did not?
