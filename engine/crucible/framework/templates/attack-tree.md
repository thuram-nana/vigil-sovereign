# Attack tree — `<target-name>`

**Last updated:** YYYY-MM-DD

A living document. Rooted at adversary objectives; leaves are
testable techniques. Update as you discover new branches and as
testing produces results.

Each leaf carries a status:

- `[ ] not started`
- `[~] testing`
- `[!] vulnerable — finding NNN`
- `[x] tested — not vulnerable`
- `[?] blocked — see notes`
- `[/] deferred — see notes`

At engagement close, every leaf should have a status. Leaves marked
`not started` are gaps.

---

## Tree

### A. Drain user balances / steal money

```
A. Drain user balances
├── A1. Account takeover then place orders
│   ├── A1.1 Brute force / credential stuffing
│   │   ├── [ ] No rate limit on login
│   │   ├── [ ] Username enumeration via timing
│   │   └── [ ] Username enumeration via response message
│   ├── A1.2 Password reset abuse
│   │   ├── [ ] Predictable / weak reset token
│   │   ├── [ ] Reset token doesn't expire
│   │   ├── [ ] Reset token reusable
│   │   ├── [ ] Host-header injection in reset URL
│   │   └── [ ] Reset token leaks via Referer
│   ├── A1.3 Session hijack via XSS
│   │   ├── [ ] Stored XSS in support ticket
│   │   ├── [ ] Stored XSS in profile name (admin viewer)
│   │   └── [ ] Reflected XSS on a publicly-shared link
│   ├── A1.4 CSRF on email change
│   │   └── [ ] Missing CSRF token + SameSite=None cookie
│   ├── A1.5 OAuth / SSO weakness (if applicable)
│   │   ├── [ ] Email-based binding without IdP-verified email
│   │   └── [ ] Open redirect on RP combined with broad allowlist
│   └── A1.6 2FA bypass
│       ├── [ ] 2FA not required on every privileged endpoint
│       └── [ ] 2FA disable doesn't require 2FA
├── A2. Forge balance crediting
│   ├── A2.1 Webhook callback without auth
│   │   └── [ ] No signature verification on payment callback
│   ├── A2.2 Webhook with weak signature
│   │   ├── [ ] Signature comparison not constant-time
│   │   └── [ ] Signature covers only headers, not body
│   ├── A2.3 Manual deposit reuse
│   │   └── [ ] Tx hash reusable across deposits
│   └── A2.4 Cross-network / currency confusion
│       └── [ ] Network field server-trusted from client
├── A3. Bypass balance deduction at order time
│   ├── A3.1 Race condition
│   │   ├── [ ] Place-order vs balance-deduct not atomic
│   │   └── [ ] HTTP/2 single-packet attack succeeds
│   ├── A3.2 Negative quantity
│   ├── A3.3 Client-supplied price/total trusted
│   ├── A3.4 Service-ID swap mid-flow
│   └── A3.5 Mass-assignment of balance in profile
├── A4. Refund-loop abuse
│   ├── A4.1 Refund eligibility window misenforced
│   ├── A4.2 Race on cancel-and-refund
│   └── A4.3 Refund without authorization (IDOR on /refund)
└── A5. Coupon / voucher abuse
    ├── A5.1 Reuse same code
    ├── A5.2 Stack codes
    ├── A5.3 100%+ discount arithmetic
    └── A5.4 Coupon applied after charge / via different endpoint
```

### B. Mass user data exfiltration

```
B. Mass user data exfiltration
├── B1. SQLi / NoSQLi at any endpoint
│   ├── [ ] Search endpoints
│   ├── [ ] Sort / order_by parameters
│   ├── [ ] Admin reports
│   ├── [ ] CSV / Excel export
│   └── [ ] Legacy / deprecated endpoints
├── B2. IDOR enumeration
│   ├── [ ] /order/{id} cross-user
│   ├── [ ] /ticket/{id} cross-user
│   ├── [ ] /transaction/{id} cross-user
│   ├── [ ] /user/{id} or /profile/{id}
│   └── [ ] Batched endpoints (?ids=1,2,3)
├── B3. Admin-side leak via auth bypass
│   ├── [ ] Vertical privilege via header tricks
│   ├── [ ] Vertical privilege via method swap
│   └── [ ] Vertical privilege via path traversal
├── B4. Public-listing endpoints
│   └── [ ] Endpoints intended for public, returning more than expected
├── B5. Backup / dump file in webroot
│   ├── [ ] .sql / .tar.gz / .zip / .bak in webroot
│   └── [ ] /storage/exports/ enumerated
└── B6. Source code disclosure
    ├── [ ] .git/ exposed
    └── [ ] .env exposed
```

### C. Full server compromise (RCE)

```
C. Full server compromise
├── C1. Server-side template injection (SSTI)
├── C2. Insecure deserialization
├── C3. Command injection via parameters
├── C4. Command injection via file content (image / PDF gen, archive
│        unpack)
├── C5. Arbitrary file upload + execution
│   ├── [ ] Upload .php / .jsp / .aspx with right mime
│   ├── [ ] Upload via path traversal
│   └── [ ] Upload via mime sniffing trick
├── C6. SSRF reaching internal RCE service
│   └── [ ] SSRF to cloud metadata service
└── C7. Direct exploit of dependency CVE
    ├── [ ] Outdated framework / library with known RCE
    └── [ ] Outdated server (web, app, db)
```

### D. Admin takeover

```
D. Admin takeover
├── D1. Default credentials
├── D2. Auth bypass on admin panel
│   ├── [ ] Path-based bypass
│   ├── [ ] Header-trust bypass
│   └── [ ] Method-swap bypass
├── D3. Admin XSS via user-supplied content
│   ├── [ ] Stored XSS in support ticket viewable by admin
│   ├── [ ] Stored XSS in user profile viewable in admin user list
│   └── [ ] CSV injection in admin export
├── D4. Privilege escalation via mass-assignment
└── D5. Direct admin endpoint exposure
    └── [ ] /admin reachable without auth
```

### E. Denial of capability (non-DoS)

```
E. Denial of capability (deliberately limited — no DoS testing)
├── E1. Lockout-based DoS (lock all users out)
├── E2. Storage-fill (large uploads, log spam)
├── E3. Workflow-stall (state-machine deadlock)
└── E4. Notification-flood (mass email/SMS triggered)
```

### F. Cross-tenant compromise (if multi-tenant)

```
F. Cross-tenant
├── F1. Tenant ID trusted from client
├── F2. Cache key not tenant-scoped
├── F3. Shared embedding / RAG corpus across tenants
├── F4. SCIM / provisioning credentials cross-tenant
└── F5. Federation / SSO tenant confusion
```

### G. Persistent compromise (post-RCE, narrative only unless authorized)

```
G. Persistence
├── G1. Webshell in webroot
├── G2. SSH authorized_keys injection
├── G3. Cron / systemd / scheduled task
├── G4. Database trigger / stored procedure
├── G5. CI/CD compromise → re-deploy on every release
└── G6. Cloud IAM role / user creation
```

---

## Status legend

- `[ ]` not started
- `[~]` testing
- `[!]` vulnerable — see Finding NNN
- `[x]` tested — not vulnerable
- `[?]` blocked — see Notes
- `[/]` deferred — see Notes

## Notes

(Append per-leaf or per-branch notes here as you work.)
