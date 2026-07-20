# Threat model — `mrbeanpanel.com`

**Status:** DRAFT (UTI-generated). Archetype: **PHP-Smarty SMM-panel fork** (`php-smarty-smm-panel-fork`).

> Drafted by URK from a live LLM call. Refresh after recon as you discover new components and refute assumptions.

## 1. Business context

SMM (Social Media Marketing) reseller panel. ~44k users, ~967k orders. Multi-PSP balance topup. Operator reports active account-takeover incidents.

## 2. Assets

| ID | Asset | Conf | Integ | Avail | Priority | Rationale |
|----|-------|------|-------|-------|----------|-----------|
| A1 | User Credentials (Reseller Accounts) | critical | critical | low | P0 | 44k user accounts; each ATO enables fraud, order theft, balance drainage. Criminal resale value $10-500/account. |
| A2 | User Account Balances/Wallet Funds | low | critical | low | P0 | 967k orders; direct theft via order manipulation or unauthorized topup reversal. Criminal monetization path. |
| A3 | Payment Processor API Keys & Merchant Account | critical | critical | medium | P0 | Direct access to PSP drain; highest single-transaction impact. Multi-PSP setup = multiple keys at risk. |
| A4 | Admin Panel / Super-admin Access | critical | critical | medium | P1 | Complete platform compromise: user moderation, balance manipulation, credential reset, audit log tampering. |
| A5 | Social Media Account Tokens (Order Targets) | high | high | medium | P1 | API tokens for Instagram, TikTok, Twitter, etc. Theft enables service hijack or sale to competitors. |
| A6 | Supplier/Upstream API Credentials | high | high | high | P1 | Integration with order-fulfillment services; theft enables supply-chain disruption or competitor sabotage. |
| A7 | User KYC/PII Data | critical | medium | low | P2 | If collected for compliance; theft = regulatory breach + reputational damage + resale value. |
| A8 | Transaction/Order History | high | medium | low | P2 | Business intelligence: lead lists, customer profiling, competitor activity tracking. |

## 3. Actors

- **T1 Automated Scanner/Bot** — Find and exploit default configs, public CVEs, exposed endpoints (skill: novice; motivation: opportunistic)
- **T2 Criminal with Public Tools** — Account takeover, balance theft, PSP key exfiltration (skill: journeyman; motivation: motivated)
- **T3 Insider Threat (Admin/Support Staff)** — Data theft, fraud, privilege abuse, competitive intelligence (skill: expert; motivation: motivated)
- **T4 Competitor Operator** — Disrupt service, steal leads, poach users, damage reputation (skill: journeyman; motivation: strategic)
- **T5 Supply-Chain Attacker** — Compromise upstream/downstream integrations; pivot to platform (skill: journeyman; motivation: strategic)

## 4. Trust boundaries

- **Browser → Web App (Anonymous User)** — data: Form input, API requests, tracking cookies; auth: None; public endpoints (login, signup, forgot password); failure: No authentication on public endpoints; CSRF on state-changing ops (forgot password link reuse, email enumeration)
- **Browser → Web App (Authenticated User)** — data: User data, orders, balance, session state; auth: PHPSESSID session cookie; _csrf token; _usid user ID cookie; failure: Session fixation, session hijack via XSS, CSRF if _csrf is weak, cookie theft via insecure transport
- **User → Admin Privilege Level** — data: Admin panel requests, system operations, user moderation, balance adjustment; auth: Role-based ACL check in PHP code; likely middleware or controller guard; failure: IDOR on admin endpoints, missing privilege check, vertical privilege escalation, mass-assignment (user can set is_admin=1)
- **User A → User B (Tenant Isolation)** — data: Cross-user orders, balance queries, profile views; auth: User ID parameter validation in queries (WHERE user_id = ?); failure: IDOR; user can request another user's data via parameter tampering; missing permission check
- **Web App → Database** — data: All business data (users, orders, balances, credentials); auth: App-level parameterized queries; database user permissions; failure: SQL injection if query building is dynamic; database user over-privileged; plaintext credentials in config
- **Web App → Payment Processor APIs** — data: Topup requests, balance checks, withdrawal requests, API keys in headers; auth: Bearer token or API key in Authorization header; PSP signature verification on webhooks; failure: API key leakage in logs/error messages; weak webhook signature verification (no HMAC or length-extension vuln); replay attacks on topup requests
- **Web App → Supplier APIs** — data: Order dispatch, order status, API credentials; auth: API key or token in headers; signature verification; failure: API key hardcoded in code; leaked in error traces; supplier auth validation missing; no rate limiting
- **Browser → API Endpoint (REST)** — data: JSON payloads, user data, order parameters; auth: PHPSESSID validation; _csrf token on POST/PUT/DELETE; failure: Missing CSRF on API; weak _csrf token (low entropy, predictable); no rate limiting on login/api endpoints
- **Admin User → System Operations** — data: System config changes, user bans, balance resets, log access; auth: Super-admin role check; no additional MFA or signing; failure: No audit logging; no MFA on admin login; no approval workflow; single admin account compromise = full takeover
- **Web App → Cache/Session Store (Redis)** — data: Session data, temporary balances, cached user data; auth: None; implicit trust (internal network); failure: If Redis is exposed: session hijack, balance manipulation in cache, arbitrary code execution if Redis RDB accessible

## 5. STRIDE

- **[S] Browser → Web App (Authenticated User)**: Session hijack via XSS; attacker steals PHPSESSID and impersonates user (realistic)
- **[S] Browser → Web App (Authenticated User)**: Credential stuffing / brute force on login endpoint; no rate limit or weak rate limit (realistic)
- **[S] Browser → Web App (Authenticated User)**: Session fixation via forcing user to attacker-controlled sessionid (realistic)
- **[T] Browser → Web App (Authenticated User)**: CSRF on state-changing operations (topup, withdraw, order placement) if _csrf token is missing or weak (realistic)
- **[S] User A → User B (Tenant Isolation)**: IDOR; request another user's balance, orders, or profile by changing user_id parameter (realistic)
- **[T] User A → User B (Tenant Isolation)**: IDOR on update; modify another user's balance, orders, or profile (realistic)
- **[E] User → Admin Privilege Level**: Vertical privilege escalation; user parameter tampering to elevate to admin role (realistic)
- **[E] User → Admin Privilege Level**: IDOR on admin endpoints; direct URL access to /admin/users, /admin/balance, /admin/logs without proper privilege check (realistic)
- **[T] Browser → Web App (Anonymous User)**: Password reset link reuse or prediction; attacker requests password reset, intercepts/guesses token, resets victim's password (realistic)
- **[I] Browser → Web App (Anonymous User)**: Email enumeration on forgot password; attacker can list valid account emails (realistic)
- **[S] Web App → Payment Processor APIs**: API key leakage in error messages, debug logs, or public .git history (realistic)
- **[T] Web App → Payment Processor APIs**: Webhook signature verification bypass; attacker forges topup webhook to credit account without payment (realistic)
- **[D] Web App → Payment Processor APIs**: Replay attack on topup requests; attacker captures topup request, replays it N times to duplicate credits (realistic)
- **[T] Browser → API Endpoint (REST)**: Missing CSRF on API requests; attacker-controlled form or script can place orders, withdraw funds without user consent (realistic)
- **[T] Web App → Database**: SQL injection in order filtering, user search, or balance queries if user input is concatenated (realistic)
- **[I] Web App → Database**: Database credentials hardcoded in source; database user over-privileged to all tables (realistic)
- **[D] Browser → Web App (Authenticated User)**: Denial of Service via API endpoint; no rate limiting on login, order placement, or balance topup endpoints (realistic)
- **[S] Web App → Supplier APIs**: Supplier API key leakage; attacker intercepts or exfiltrates key, impersonates platform to supplier (realistic)
- **[T] Web App → Supplier APIs**: Order data tampering in flight; attacker modifies order quantity, target, or payment without supplier verification (realistic)
- **[R] Admin User → System Operations**: Weak audit logging; admin actions not logged or logs tamperable; attacker covers tracks after privilege abuse (realistic)

## 6. Attack tree (root)

```
Compromise SMM Panel & Monetize
  └─ 1. Account Takeover & Monetization
    └─ 1.1. Compromise User Credentials
      └─ 1.1.1. Brute Force / Credential Stuffing
        └─ No rate limiting on /login endpoint  [?]
        └─ Weak CAPTCHA or bypassable CAPTCHA  [?]
        └─ Reused credentials from other breaches (public dumps)  [?]
      └─ 1.1.2. Password Reset Abuse
        └─ Reset token predictable or low entropy  [?]
        └─ Reset token not invalidated after use or timeout  [?]
        └─ Reset email contains token in plaintext (leakable via Referer)  [?]
        └─ No email verification step; attacker changes email, resets password  [?]
      └─ 1.1.3. Session Hijack via XSS
        └─ Stored XSS in user profile fields (display name, bio, avatar URL)  [?]
        └─ Stored XSS in support tickets, comment sections, or order notes  [?]
        └─ Reflected XSS in search, filter, or error parameters  [?]
        └─ PHPSESSID cookie missing HttpOnly flag; XSS can exfiltrate via JavaScript  [?]
      └─ 1.1.4. Phishing / Social Engineering
        └─ Attacker sends fake 'verify account' or 'update payment method' email  [?]
        └─ Credential capture via attacker-controlled lookalike domain  [?]
    └─ 1.2. Monetize Compromised Account
      └─ 1.2.1. Place Unauthorized Orders
        └─ Attacker places high-volume orders to deplete victim balance  [?]
        └─ Attacker sells order services to third parties (service resale)  [?]
      └─ 1.2.2. Extract or Resell Credentials
        └─ Attacker changes password, sells account to other fraudsters  [?]
        └─ Attacker exports user list or account data if admin access gained  [?]
  └─ 2. Balance Theft & Financial Fraud
    └─ 2.1. Bypass Balance Deduction at Order Time
      └─ Negative quantity or price in order request; balance increases instead of decreases  [?]
      └─ Client-trusted price/total field; attacker modifies order cost before submission  [?]
      └─ Race condition; attacker sends multiple orders simultaneously; balance check executed once, deduction twice  [?]
      └─ Mass-assignment vulnerability; attacker modifies user balance directly in profile update (user_balance=999999)  [?]
    └─ 2.2. Unauthorized Balance Topup
      └─ 2.2.1. Webhook Callback Forgery
        └─ No webhook signature verification; attacker sends fake topup confirmation  [?]
        └─ Weak webhook signature (short token, no HMAC-SHA256, reusable)  [?]
        └─ Signature verification has timing attack or length-extension vulnerability  [?]
        └─ Webhook does not validate merchant/user ID; can credit arbitrary accounts  [?]
      └─ 2.2.2. PSP Integration Bypass
        └─ Attacker directly calls topup endpoint without going through PSP  [?]
        └─ Topup amount not server-validated; client can send arbitrary amount  [?]
      └─ 2.2.3. Replay Attack on Topup
        └─ Attacker captures PSP webhook or topup confirmation, replays N times  [?]
        └─ No idempotency key or nonce on topup request  [?]
    └─ 2.3. Refund Abuse
      └─ Refund eligibility window not enforced or bypassable  [?]
      └─ Race condition; attacker requests refund twice simultaneously  [?]
      └─ IDOR on refund endpoint; attacker can refund any order (including others' orders)  [?]
      └─ Refund amount not validated; attacker requests larger refund than order cost  [?]
    └─ 2.4. Coupon/Voucher Abuse
      └─ Coupon reuse; attacker applies same code unlimited times  [?]
      └─ Coupon stacking; attacker applies multiple codes to single order  [?]
      └─ Arithmetic error; 100%+ discount possible (order cost becomes negative)  [?]
      └─ Coupon code prediction or brute-force; attacker generates valid codes  [?]
  └─ 3. Payment Processor Compromise
    └─ 3.1. Exfiltrate PSP API Keys
      └─ Keys hardcoded in PHP source code or config files  [?]
      └─ Keys logged in error messages, debug output, or server logs  [?]
      └─ Keys stored in plaintext in .env file; file accessible via path traversal or .env disclosure  [?]
      └─ Keys visible in git history or public repository (GitHub, GitLab)  [?]
      └─ Database dump contains PSP keys; attacker gains DB access via SQLi  [?]
    └─ 3.2. Drain Merchant Account via PSP
      └─ Use exfiltrated keys to initiate withdrawals to attacker bank account  [?]
      └─ Use exfiltrated keys to reverse legitimate transactions  [?]
      └─ Use exfiltrated keys to disable webhooks, modify account settings  [?]
    └─ 3.3. PSP Webhook Spoofing
      └─ No signature verification on payment status webhook  [?]
      └─ Attacker sends fake 'payment successful' webhook to credit account without payment  [?]
  └─ 4. Privilege Escalation to Admin
    └─ 4.1. Vertical Privilege Escalation
      └─ User parameter tampering; change is_admin flag in profile update request  [?]
      └─ Missing role check on admin endpoints; IDOR allows direct access to /admin/* URLs  [?]
      └─ Role check only on client-side; attacker bypasses frontend checks via API  [?]
      └─ Cookie or session tampering; attacker sets admin=true in session cookie  [?]
    └─ 4.2. Admin Account Compromise
      └─ Brute force admin account (weak password, default credentials)  [?]
      └─ SQL injection to extract admin password hash  [?]
      └─ XSS on admin panel to steal admin session  [?]
      └─ Insider threat; admin staff account compromised or turned malicious  [?]
    └─ 4.3. Abuse Admin Panel
      └─ Modify user balances, orders, or credentials  [?]
      └─ Export user database, credentials, payment info  [?]
      └─ Create rogue admin accounts or backdoor users  [?]
      └─ Tamper with audit logs or disable logging  [?]
  └─ 5. Supply Chain & Third-Party Attacks
    └─ 5.1. Compromise Supplier API Credentials
      └─ Supplier keys hardcoded or logged (same as PSP keys)  [?]
      └─ Supplier API validation missing; attacker spoofs orders or status updates  [?]
    └─ 5.2. Supply-Chain Pivot
      └─ Attacker compromises payment processor, gains access to platform via API integration  [?]
      └─ Attacker compromises supplier, sends malicious order confirmations or status updates  [?]
  └─ 6. Denial of Service
    └─ 6.1. Application-Level DoS
      └─ No rate limiting on login endpoint; brute force blocks legitimate users  [?]
      └─ Expensive database queries without pagination; attacker filters large datasets  [?]
      └─ ReDoS (Regular Expression Denial of Service) in input validation  [?]
      └─ Unbounded file upload; attacker uploads massive files to exhaust disk  [?]
    └─ 6.2. API Rate Limiting Bypass
      └─ Rate limit keyed only on IP; attacker uses proxies or Botnet  [?]
      └─ Rate limit bypassed via user-agent rotation or header manipulation  [?]
    └─ 6.3. Supplier Service Disruption
      └─ Attacker sends malformed or duplicate orders to overload supplier  [?]
      └─ Attacker exfiltrates supplier API key, makes unauthorized requests  [?]
  └─ 7. Data Exfiltration & Intelligence
    └─ 7.1. User Database Dump
      └─ SQL injection to extract user table (emails, hashed passwords, balances)  [?]
      └─ Database backup accessible via web root or misconfigured S3  [?]
      └─ Database credentials in git history; attacker clones and accesses DB directly  [?]
    └─ 7.2. Transaction History Intelligence
      └─ Attacker gains read access to all orders (IDOR on /api/orders endpoint)  [?]
      └─ Attacker sells aggregated lead list to competitors  [?]
    └─ 7.3. KYC/PII Exfiltration
      └─ If KYC data is stored: access via SQL injection or weak authorization  [?]
      └─ Attacker sells PII to fraudsters (identity theft, account opening)  [?]
```

## 7. Catastrophic outcomes (worst first)

1. Complete account takeover of 44k+ users; attackers place fraudulent orders draining all balances (~967k orders × avg price = millions in losses)
2. Merchant PSP account drained; attacker uses exfiltrated API keys to withdraw balance to personal bank accounts (direct theft of merchant reserves)
3. Full admin compromise; attacker modifies all balances, deletes audit logs, creates backdoor accounts for persistent access
4. Platform becomes vector for downstream fraud; SMM panel user accounts (Instagram, TikTok, Twitter) compromised and sold by attacker to botnet operators
5. Regulatory breach and reputation loss; user KYC data (if collected) exfiltrated; GDPR/CCPA fines and legal liability; payment processors terminate relationship
6. Supply-chain pivot; attacker gains control of payment processor or supplier integrations, pivots to compromise other platforms sharing same integrations
7. Service unavailability; ransomware infection or severe DoS leaves platform offline for weeks; users migrate to competitors

## 8. Not in model

- Nation-state APT with zero-day budget and multi-month reconnaissance campaigns
- Physical attacks on data center (break-in, theft of servers, direct hardware manipulation)
- Sophisticated supply-chain attacks (e.g., compiler trojans, binary distribution compromises, 3rd-party library poisoning)
- Quantum computing attacks on TLS or cryptographic hashing (10+ year future threat)
- Advanced persistent threat (APT) with full-time dedicated operators, custom malware, and persistence infrastructure

## 9. Refresh

Update this document at every phase boundary. Mark refuted assumptions explicitly; treat surprises as model errors.
