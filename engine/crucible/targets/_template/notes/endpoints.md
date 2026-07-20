# Endpoint inventory — `<target-name>`

Every URL/endpoint discovered, classified, and noted for testing
status.

This is the **coverage map**. Stages 4-6 ensure every endpoint here
gets at least one test from the playbooks that apply.

---

## Discovery sources

| Source | Items | Date |
|--------|-------|------|
| Wayback Machine | `<count>` | YYYY-MM-DD |
| JS bundle extraction (`linkfinder`, `gau`) | `<count>` | YYYY-MM-DD |
| Sitemap.xml / robots.txt | `<count>` | YYYY-MM-DD |
| Crawler (katana, hakrawler) | `<count>` | YYYY-MM-DD |
| API documentation (Swagger / OpenAPI / docs) | `<count>` | YYYY-MM-DD |
| Mobile binary (Frida proxy) | `<count>` | YYYY-MM-DD |
| Source code (route definitions) | `<count>` | YYYY-MM-DD |
| **Unique total** | `<count>` | — |

---

## Inventory

Status legend:
- `[ ]` — known but not yet tested.
- `[~]` — partially tested (one playbook, not all that apply).
- `[x]` — tested (at least one round on every applicable playbook).
- `[!]` — finding opened on this endpoint.

| Status | Method(s) | Path | Auth | Description | Discovered via | Last test date |
|--------|-----------|------|------|-------------|----------------|----------------|
| `[ ]` | GET | `/` | — | Homepage | crawler | — |
| `[ ]` | POST | `/login` | — | Login form submit | crawler | — |
| `[ ]` | GET | `/api/v2/orders` | session | List orders | docs | — |
| `[ ]` | GET | `/api/v2/orders/{id}` | session | Order detail | docs | — |
| `[ ]` | POST | `/api/v2/orders` | session | Place order | docs | — |
| `[ ]` | DELETE | `/api/v2/orders/{id}` | session | Cancel | docs | — |
| `[ ]` | GET | `/admin/users` | admin | Users index | source | — |
| `[ ]` | POST | `/webhook/stripe` | signature | Stripe webhook receiver | source | — |
| ... | ... | ... | ... | ... | ... | ... |

---

## Sub-categories

### Authentication / identity

| Path | Notes |
|------|-------|
| `/login` | session login |
| `/register` | sign-up |
| `/password/email` | reset request |
| `/password/reset` | reset confirm |
| `/email/verify/{id}/{hash}` | email confirm |
| `/two-factor-challenge` | 2FA verify |
| `/logout` | end session |
| ... | ... |

### Money / business invariants

| Path | Notes |
|------|-------|
| `/orders/place` | atomic with balance debit? |
| `/refunds` | idempotent? |
| `/withdrawals` | per-day limit; address whitelist |
| ... | ... |

### Admin / privileged

| Path | Notes |
|------|-------|
| `/admin/*` | role gating |
| `/internal/*` | internal-only? |
| ... | ... |

### Webhooks / callbacks

| Path | Notes |
|------|-------|
| `/webhook/stripe` | HMAC signature header `Stripe-Signature` |
| `/oauth/callback` | redirect_uri target |
| ... | ... |

### Static / public

| Path | Notes |
|------|-------|
| `/robots.txt` | recon source |
| `/sitemap.xml` | recon source |
| `/.well-known/security.txt` | should exist |
| ... | ... |

### Suspect / unauthenticated reachable

| Path | Notes |
|------|-------|
| `/debug/info` | should not exist in prod |
| `/.git/config` | source-leak candidate |
| `/server-status` | Apache info |
| ... | ... |

---

## Coverage summary

For Stage 9 retest planning:

| Playbook | Endpoints applicable | Tested | Pending |
|----------|----------------------|--------|---------|
| 04 Web app | `<N>` | `<N>` | `<N>` |
| 05 API security | `<N>` | `<N>` | `<N>` |
| 06 Auth | `<N>` | `<N>` | `<N>` |
| 07 Authz | `<N>` | `<N>` | `<N>` |
| 08 Injection | `<N>` | `<N>` | `<N>` |
| 09 Client-side | `<N>` | `<N>` | `<N>` |
| 10 Business logic | `<N>` | `<N>` | `<N>` |
| 11 Crypto | `<N>` | `<N>` | `<N>` |

A pending endpoint × playbook cell is a coverage gap.
