# IDOR / BOLA — technique reference

## 1. Mental model

The application **identifies an object the user wants to act on, but does
not verify that user is authorised to act on that object**. Object IDs are
sent by the client (URL, body, header, cookie, query, GraphQL variable) and
the server trusts the ID without cross-checking ownership.

OWASP API Top 10 calls it BOLA (Broken Object-Level Authorisation). Same bug,
slightly broader scope (objects in APIs, not just user-owned resources).
Sister bug BFLA (Broken Function-Level) is endpoint authorization. BOPLA
(Broken Object-Property-Level) extends to individual fields within an object
(mass assignment, over-fetching).

## 2. Where IDs come from

- Path: `/api/users/{id}`, `/orders/{id}`, `/files/{uuid}`
- Query: `?user_id=`, `?order=`
- Body JSON: `{"order_id": 123}`
- Body form: `order_id=123`
- Cookie: `cart_id=...`
- Header: `X-Tenant-ID:`, `X-Account:`, `X-Customer-Code:`
- GraphQL variable: `query Q($id: ID!) { order(id: $id) { ... } }`
- HTTP/2 pseudo-header (rare)
- Encoded inside JWT — `sub` (and the bug is trusting it without ownership re-check)

## 3. Test setup

You need TWO accounts in the same role tier (call them A and B).

- OBSIDIAN-TEST-A — primary attacker
- OBSIDIAN-TEST-B — victim peer
- (Optionally OBSIDIAN-TEST-C — admin, OBSIDIAN-TEST-D — staff, depending on
  role matrix)

Generate distinct objects in each account. Note their IDs. Then with A's
session, attempt to read / modify / delete B's objects.

## 4. Method matrix

For each endpoint accepting an ID, test all four methods:

| Method | Test |
|--------|------|
| GET | A's session reads B's object → expect 403/404, fail = leak |
| POST | A creates a child resource under B's parent → fail = data corruption |
| PUT/PATCH | A modifies B's object → fail = tampering |
| DELETE | A deletes B's object → fail = destruction |

Don't assume GET being protected implies the others are.

## 5. ID enumeration

If IDs are sequential (`1, 2, 3, ...`):

- Walk forward and backward from your own ID
- Look for system / admin objects at low IDs (`1`, `0`, `-1`)
- Compare response sizes: "your access denied" vs "object not found" vs
  "object accessible" often differ
- Use ffuf / Intruder over a numeric range

If IDs are UUIDs:

- v1 / v2: contain timestamp + MAC address; predictable if you know peer
  generation time
- v4: random, generally unenumerable — but they leak in:
  - Public profile URLs, share URLs, email links
  - Browser history, server logs (if you can read), referer headers
  - JS bundles (`window.__INITIAL_STATE__`, GraphQL preloads)
  - Email previews, admin dashboards, public API responses
- v7 (UUIDv7): includes timestamp prefix; partial guessability

If IDs are short opaque strings (e.g. `abc123`): test charset & length, may
be sequential under base-N encoding.

## 6. Higher-order IDOR

ID is a string that looks like a path: `file_id=user/123/avatar.png`. Try:

```
file_id=../456/avatar.png
file_id=user/456/avatar.png
file_id=admin/secret.txt
```

ID is a JWT: alter `sub` in payload (test against signature attacks first).

ID is encrypted: try padding-oracle if CBC, length-extension if HMAC-prefix
flavored MAC.

ID is signed but not bound to user (`?token=...&user=123`): may verify
signature but not bind to session — IDOR on `user` parameter despite signed
token.

## 7. Indirect IDOR (BOPLA)

Server uses your session to scope object lookup correctly, but you can submit
extra fields that mass-assign. Example:

```json
PATCH /api/profile
{
  "name": "harmless",
  "is_admin": true,
  "balance": 1000000,
  "password_reset_token": "..."
}
```

If server merges all fields without allowlist → property-level IDOR. Test
JSON, form-encoded, multipart, and GraphQL mutations.

## 8. Tenant / multi-tenancy IDOR

In B2B SaaS: company A user accessing company B's resources via:

- `X-Tenant-ID` header swap
- Subdomain swap (`tenant1.app.tld` → `tenant2.app.tld`) keeping cookie
- API endpoint with `account_id=` parameter
- Direct DB ID without tenant scoping in query

Test with two distinct tenants (request from client; in fixed scope, you may
have to register two organisations).

## 9. Workflow IDOR

Multi-step process where step 1 generates an ID accepted by step 2 without
re-validation:

- Step 1: A initiates wire transfer, server returns `transfer_id=42`
- Step 2: any user passes `transfer_id=42` to "confirm" endpoint, server
  trusts it because step 1 said it's valid

These are easy to miss — test the full flow with cross-user IDs at every
step.

## 10. Webhook / callback IDOR

Payment processors call back with `?order_id=...&status=paid`. If endpoint
trusts query parameters without verifying signature: any user can mark any
order paid. Test:

- Direct call to webhook endpoint with arbitrary order_id
- Replay legitimate webhook for a different order
- Modify order status via webhook (paid → refunded)

## 11. File / blob storage IDOR

S3 / GCS / Azure Blob URLs that aren't pre-signed are public if bucket allows
listing or has predictable keys:

- `https://bucket.s3.amazonaws.com/users/123/passport.jpg`
- Try ranges of users.
- Try predictable filenames: `passport.jpg`, `id.png`, `tax_form.pdf`.

For pre-signed URLs: check expiration window (sometimes 7 days), and whether
URL still works after object should be deleted.

## 12. Source code review

```
# Look for object lookups by ID without scoping
grep -rEn "Order\.find\(.*id\)|Order\.find_by\(id:.*\)" --include='*.rb'
grep -rEn "Order\.objects\.get\(id=" --include='*.py'
grep -rEn "@PathVariable.*id.*find" --include='*.java'

# Compare to scoped patterns
grep -rEn "current_user\.orders\.find|\.where\(user_id:.*current_user"
grep -rEn "Order\.objects\.filter\(user=request\.user"

# Mass-assign smell
grep -rEn "params\.permit\(:.*\)|update_attributes\(params\)|UpdateById\(input\)"
```

Flag: object lookup by user-supplied ID without joining to current user.

## 13. Defenses (for remediation)

1. **Authorisation on every object access** — at the data layer, scope
   queries by current user / tenant.
2. **Centralised authorisation library** (Pundit, CanCan, Casbin, OPA) so
   policies aren't reimplemented per controller.
3. **Random unguessable IDs** as defense-in-depth (UUIDv4 or longer) — does
   not replace authorisation.
4. **Allowlist mass-assign fields** explicitly — reject unknown keys.
5. **Tenant scoping middleware** — every query goes through a scope filter.
6. **Authorise on read AND write** — including DELETE and PATCH.
7. **Audit logs** of authorisation failures help catch missed paths.
8. **Test framework** — generate cross-user request matrices in CI.

## 14. CWE / standards mapping

- CWE-639 — Authorisation bypass through user-controlled key
- CWE-284 — Improper access control
- CWE-285 — Improper authorisation
- CWE-915 — Improperly controlled modification of dynamically-determined
  object attributes (mass assignment / BOPLA)
- OWASP WSTG WSTG-ATHZ-04
- OWASP API Top 10 2023 API1 (BOLA), API3 (BOPLA), API5 (BFLA)

## 15. Tools

- **AuthMatrix** (Burp extension) — generate role × endpoint test matrix
- **Autorize** (Burp extension) — automatic same-request-different-session
  comparison
- **autorepeater** — for header swap tests
- **ffuf / Intruder** — ID range enumeration
- Custom scripts: see `framework/scripts/api/idor-sweep.sh` (writes A's session, replays as B, compares).
