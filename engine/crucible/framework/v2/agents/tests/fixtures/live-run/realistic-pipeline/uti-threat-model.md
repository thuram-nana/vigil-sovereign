# Threat model — `fix-target.invalid`

**Status:** DRAFT (UTI-generated). Archetype: **PHP-Smarty SMM-panel fork** (`php-smarty-smm-panel-fork`).

> Drafted by URK from a live LLM call. Refresh after recon as you discover new components and refute assumptions.

## 1. Business context

Synthetic SMM (Social Media Marketing) panel fork on PHP-Smarty with perfect-panel CMS, OIDC authentication, REST API, and cryptomus payment processing. Users purchase and resell social media engagement services (followers, likes, comments). Core business model: collect user funds via crypto payments, execute orders to deliver services, process refunds. High-value targets: user account balances (direct theft), payment processor keys (system takeover), admin panel (full control).

## 2. Assets

| ID | Asset | Conf | Integ | Avail | Priority | Rationale |
|----|-------|------|-------|-------|----------|-----------|
| A1 | Cryptomus payment processor API keys | critical | critical | critical | P0 | Master keys controlling fund movement. Compromise enables attacker to drain all customer deposits, issue fraudulent credits, or redirect transactions. |
| A2 | Admin panel access and superuser privileges | critical | critical | high | P0 | Root control over system. Admin account compromise enables user data theft, balance manipulation, credential reset, audit log falsification, configuration changes. |
| A3 | User account balances and service credits | low | critical | low | P1 | Direct theft target. User credits represent real monetary value held in the system. Balance manipulation is core adversary objective. |
| A4 | User login credentials and sessions | high | high | low | P1 | Account takeover enabler. Stolen credentials or hijacked sessions allow attacker to impersonate users, withdraw funds, place orders. |
| A5 | OIDC provider keys and token validation logic | critical | critical | high | P1 | Authentication bypass vector. Compromise of OIDC configuration or token signing keys allows arbitrary user impersonation. |
| A6 | Multi-tenant data isolation boundaries | medium | critical | medium | P1 | Cross-tenant exposure. Broken isolation allows user-A to view/modify user-B balances, orders, and social media targets. |
| A7 | Service order history and audit logs | medium | high | low | P2 | Forensic evidence and operational data. Compromise enables attacker to hide tracks, forge transaction history, or analyze customer patterns. |
| A8 | User-supplied social media target accounts | high | medium | low | P2 | Customer intelligence. Leaked targets reveal which social media accounts customers are boosting (competitive intel, sabotage leads). |

## 3. Actors

- **T1 Script kiddie with automated scanners** — Find and exploit low-hanging vulnerabilities (CVE, default creds, obvious XSS) (skill: novice; motivation: opportunistic)
- **T2 Financially motivated cybercriminal** — Monetize: steal payment keys, ATO for balance theft, resell credentials, exploit refund loops (skill: journeyman; motivation: motivated)
- **T3 Competitor SMM panel operator** — Steal customer lists, sabotage service reputation, poach users (skill: journeyman; motivation: motivated)
- **T4 Insider: disgruntled employee or compromised affiliate** — Direct balance theft, system sabotage, credential theft (skill: expert; motivation: motivated)
- **T5 Fraudster: service arbitrageur and refund-loop abuser** — Exploit business logic: negative balances, refund loops, code stacking, price manipulation (skill: novice; motivation: opportunistic)

## 4. Trust boundaries

- **B1: Anonymous browser → web app (login/registration)** — data: HTTP request (credentials, CSRF token, login form data); auth: Username/password validation against user table; session token issuance; failure: Weak password hashing, brute-force-able endpoints, user enumeration via timing, XSS on login form
- **B2: Authenticated user browser → web app (dashboard, API)** — data: HTTP request with session cookie/bearer token; response includes user balance, order history, targets; auth: Session validity, token expiration, CSRF token on state-changing requests, optional CORS checks; failure: Session fixation, CSRF bypass, cookie theft (not HttpOnly), token validation logic bugs, missing CORS preflight
- **B3: User-A → User-B (multi-tenant isolation)** — data: API calls to /api/user/{id}/balance, /api/orders/{id}, /api/targets/{id}; auth: Object ownership verification (does session user own the requested resource?); failure: IDOR: missing ownership check, predictable IDs, reference parameter not validated (A.id == session.id check omitted)
- **B4: User → admin (privilege boundary)** — data: Request to /admin/* endpoints; responses include all users' data, payment keys, system settings; auth: Role/permission check (is user.role == 'admin'?), optional IP whitelist, 2FA; failure: Role field tampering in request, missing permission checks on individual admin endpoints, role bypass via URL parameter
- **B5: Web app → payment processor (cryptomus API)** — data: HTTPS request with API key header; JSON body (amount, user_id, webhook_url); webhook callback with signature; auth: API key validation on outbound request; webhook signature verification (HMAC-SHA256) on callback; failure: API key in logs/config/source, weak signature algorithm, missing signature verification, webhook URL validation not validating scheme (http://localhost allowed), replay attacks
- **B6: Web app → OIDC provider (authentication server)** — data: Authorization code exchange; ID token, access token, refresh token in response; auth: Code validation, client_secret validation, redirect_uri match, token signature verification (RS256 or HS256?); failure: Alg confusion attack (accepting HS256 when RS256 expected), kid header injection, weak redirect_uri validation (domain prefix match), missing state parameter, code reuse
- **B7: Web app → database** — data: SQL queries; results include user credentials, balances, orders, payment keys; auth: None (implicit: app has DB credentials); parameterized queries; failure: SQL injection via user input in search/filter, unparameterized queries, database credentials in config files
- **B8: Web app → file system (uploads, config)** — data: User-uploaded files (profile picture, service proof); app reads .env, config.php, logs; auth: File ownership, upload directory permissions; failure: Unrestricted file upload (RCE via .php), path traversal in file operations, .env readable from web root

## 5. STRIDE

- **[D] B1: Anonymous → web app**: Brute force login attempts without rate limiting (realistic)
- **[I] B1: Anonymous → web app**: User enumeration via login response timing or error messages (realistic)
- **[S] B2: Auth user → web app**: Session hijacking if cookies lack HttpOnly/Secure flags (realistic)
- **[T] B2: Auth user → web app**: CSRF on balance withdrawal: forged POST to /api/withdraw without CSRF token validation (realistic)
- **[I] B2: Auth user → web app**: XSS in user profile name field stored and reflected in admin panel (realistic)
- **[S] B3: User-A → User-B**: Insecure direct object reference (IDOR) on /api/user/{id}/balance: attacker calls /api/user/123/balance without ownership check (realistic)
- **[T] B3: User-A → User-B**: Mass assignment vulnerability: PATCH /api/user/me with balance=99999 if balance field is not explicitly blacklisted (realistic)
- **[E] B4: User → Admin**: Role escalation via parameter tampering: user modifies role field in profile update request (realistic)
- **[S] B4: User → Admin**: Missing authorization checks on individual admin endpoints: /admin/users/delete/{id} called without admin role verification (realistic)
- **[S] B5: Web app → Payment processor**: Webhook signature verification missing or weak: attacker forges cryptomus callback to credit arbitrary user balance (realistic)
- **[I] B5: Web app → Payment processor**: API key exposure in environment file, logs, or GitHub repository history (realistic)
- **[S] B6: Web app → OIDC provider**: JWT algorithm confusion: attacker switches alg from RS256 to HS256 and signs with public key (realistic)
- **[I] B6: Web app → OIDC provider**: Weak redirect_uri validation: app accepts http://attacker.com if registered URI is https://app.com (prefix match instead of exact) (realistic)
- **[I] B7: Web app → Database**: SQL injection in user search endpoint: /api/users?search=X with unparameterized query (realistic)
- **[T] B7: Web app → Database**: Mass assignment in user update: POST /api/user/update with is_admin=true (realistic)
- **[T] B8: Web app → File system**: Unrestricted file upload: PHP file uploaded as profile picture and executed (realistic)
- **[I] B8: Web app → File system**: Path traversal in file download: /download?file=../../../.env (realistic)

## 6. Attack tree (root)

```
Compromise SMM panel for financial gain
  └─ Drain payment processor keys
    └─ Discover API key in plaintext
      └─ .env file readable from web root  [?]
      └─ API key logged in application error logs  [?]
      └─ API key visible in GitHub repository history  [?]
      └─ API key in database backup accessible via path traversal  [?]
    └─ Gain admin panel access, extract keys from UI/database
      └─ Brute force admin credentials
        └─ No rate limiting on /login  [?]
        └─ Weak admin password (default creds: admin/admin)  [?]
      └─ Privilege escalation to admin
        └─ Role field tampering in profile update request  [?]
        └─ Missing permission check on /admin endpoints  [?]
    └─ Forge webhook callback to test key validity, then abuse
      └─ Webhook signature verification missing
        └─ App trusts incoming webhook without HMAC check  [?]
        └─ Signature algorithm too weak (MD5, SHA1)  [?]
  └─ Account takeover: steal user credentials or sessions
    └─ Brute force login
      └─ No rate limiting on POST /login  [?]
      └─ Weak password hashing (MD5, unsalted)  [?]
    └─ Session hijacking
      └─ Session cookies not marked HttpOnly  [?]
      └─ XSS in user-controlled field (profile name, order notes)  [?]
    └─ Password reset abuse
      └─ Predictable reset token (timestamp, sequential)  [?]
      └─ Reset link includes user ID in plaintext; attacker resets arbitrary user  [?]
    └─ OIDC token spoofing
      └─ JWT alg confusion (RS256→HS256 swap with public key)  [?]
      └─ Missing exp/iat validation on token  [?]
  └─ Drain user balances directly
    └─ Cross-tenant balance access (IDOR)
      └─ GET /api/user/{id}/balance without ownership check  [?]
      └─ PATCH /api/user/{id} to modify balance on target user  [?]
    └─ Manipulate balance in own account
      └─ Mass assignment: POST /api/user/update with balance=999999  [?]
      └─ Negative quantity in order: POST /api/order with quantity=-100 to credit account  [?]
    └─ Refund loop abuse
      └─ Double-refund via race condition (same order refunded twice)  [?]
      └─ Refund without authorization: PATCH /api/order/{id}/refund missing auth check  [?]
    └─ Coupon/voucher abuse
      └─ Reuse same discount code unlimited times  [?]
      └─ Stack multiple 50% coupons to net negative price  [?]
  └─ Forge payment callbacks to credit accounts
    └─ Webhook signature verification absent
      └─ POST to /webhook/cryptomus/deposit with fake signature  [?]
      └─ App does not validate Cryptomus IP whitelist  [?]
    └─ Weak signature check allows bypass
      └─ Signature only on some fields, not all (status field tampering)  [?]
      └─ Timing attack on signature comparison (not constant-time)  [?]
  └─ Achieve full admin takeover
    └─ Escalate privileges from regular user
      └─ Role field in profile update not blacklisted  [?]
      └─ Database direct role modification if SQL injection present  [?]
    └─ Compromise admin account
      └─ Default admin credentials unchanged (admin/admin, admin/password)  [?]
      └─ SQL injection on login query to bypass authentication  [?]
    └─ RCE via file upload (if admin panel vulnerable)
      └─ Upload .php file as profile picture to /uploads/  [?]
      └─ Web server executes PHP from /uploads directory  [?]
```

## 7. Catastrophic outcomes (worst first)

1. Cryptomus API keys compromised: attacker withdraws all customer-held funds (~$100k+), service becomes insolvent
2. Admin panel fully compromised: attacker becomes root operator, modifies all user balances, exports customer database, wipes audit logs
3. User account isolation broken: attacker transfers all user balances to attacker-controlled account via cross-tenant IDOR
4. Payment webhook forgery endemic: attacker forges deposits for arbitrary users, draining payment processor account
5. Widespread account takeover via credential stuffing or session hijacking: hundreds of user accounts compromised, funds stolen
6. OIDC token spoofing: attacker impersonates any user by forging JWT, no password needed
7. Service availability destroyed: DoS via unlimited order creation, payment processor rate limits exceeded, service halts
8. Customer data breach: all user credentials, targets, order history, and PII exfiltrated and sold on criminal forums
9. Reputation and regulatory fallout: platform blacklisted by payment processors, users file chargebacks, regulatory fines for AML/KYC failures

## 8. Not in model

- Nation-state adversaries with APT-grade capabilities and 0-days (target too low-value for strategic interest)
- Large-scale DDoS attacks via botnet (not core to business logic vulnerability, infrastructure-tier defense outside scope)
- Supply-chain attacks on npm/PHP dependencies (covered by patch management, not threat-model-specific)
- Physical access attacks on data center (assumed cloud-hosted with provider-managed physical security)
- Quantum computing breaks RSA/ECDSA (cryptographic agility not threat-modeled for current crypto state)

## 9. Refresh

Update this document at every phase boundary. Mark refuted assumptions explicitly; treat surprises as model errors.
