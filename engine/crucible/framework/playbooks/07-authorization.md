# Playbook 07 — Authorization

**Goal:** confirm every endpoint correctly enforces who can do what.
Vertical (user → admin) and horizontal (user A → user B) authorization
are the single most-common, highest-impact bug class on modern web
applications and APIs.

Mapped to OWASP API Top 10 API1 (BOLA), API3 (BOPLA), API5 (BFLA),
WSTG-ATHZ.

---

## 7.1 The role × endpoint matrix is your testing plan

Take `recon/enum/role-matrix.md` from Stage 3. For each cell that
says "-" (not allowed), test what **actually happens** as that role.

Three failure modes per cell:

1. **Endpoint accepts request and returns data** → broken auth.
2. **Endpoint returns 403 but the action *executed* anyway** → broken
   auth with cosmetic block. Verify side-effects.
3. **Endpoint returns 200 with empty body but logs / DB show action
   ran** → silent broken auth.

Don't trust HTTP status alone. Verify the side-effect every time.

---

## 7.2 Vertical privilege escalation

```bash
ENDPOINTS=(
  "GET /admin/users"
  "GET /admin/orders"
  "POST /admin/balance/add"
  "GET /admin/services"
  "GET /admin/settings"
  "GET /api/v2/admin/users"
  "POST /api/admin/announcements"
  "DELETE /api/admin/users/1"
  "GET /admin/audit-log"
  "POST /admin/impersonate"
)

for e in "${ENDPOINTS[@]}"; do
  method="${e%% *}"
  path="${e##* }"
  for sess in "$ANON_COOKIE" "$USERA_COOKIE" "$RESELLER_COOKIE" "$ADMIN_COOKIE"; do
    code=$(curl -sk -o /dev/null -w "%{http_code} bytes=%{size_download}" \
      -X "$method" -b "$sess" "https://<target>$path")
    label="${sess:0:24}"
    echo "$method $path  [$label] $code"
  done
done | tee evidence/authz/vertical.txt
```

### 7.2.1 Bypass tricks when direct request returns 403

Common header / path / method tricks:

```text
# Method swap
GET /admin/users → POST /admin/users
GET /admin/users → PUT /admin/users
GET /admin/users → HEAD /admin/users

# Header tricks
X-Original-URL: /admin/users
X-Rewrite-URL: /admin/users
X-Forwarded-For: 127.0.0.1
X-Forwarded-Host: localhost
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
Referer: https://<target>/admin/

# Path tricks
/admin/./users
/admin//users
/admin/users/
/admin/users..
/admin/users;.html
/admin/users.json
/admin/users%20
/admin/users%00
/Admin/Users          # case variation
/admin/users#         # fragment
/admin/users?         # empty query
/admin%2fusers        # encoded slash
/..%2fadmin/users
/admin/users#/../

# Verb tunneling (some frameworks)
POST /admin/users     with body _method=GET
```

A 403 followed by 200 on any variant is a finding — the original
auth check was incomplete.

### 7.2.2 IP-based trust

If the app has admin endpoints "only available from internal IPs":
- Try `X-Forwarded-For: 127.0.0.1`, `10.0.0.1`, `192.168.1.1`.
- Try with multiple `X-Forwarded-For` values; some apps trust the
  first or last in a chain.
- Some apps trust private IPs from any source.

If your IP gets you in via header injection, that's a Critical.

---

## 7.3 Horizontal IDOR / BOLA

For every endpoint that takes an ID, swap for a different user's ID
as a different user.

Pattern:
1. As User A, find your own object IDs (note format: numeric / UUID /
   slug).
2. As User B (separate session), try to access User A's objects.
3. If 200 with User A's data → IDOR.

Run for every resource type from the inventory:
- Orders, transactions, refunds, invoices, receipts.
- Tickets, ticket attachments, ticket replies.
- API keys, OAuth tokens.
- Payment methods on file (last-4 of card, addresses).
- Notifications.
- Documents / files.
- Audit logs.
- Profile data (PII).
- Webhooks / integrations.

### 7.3.1 ID format considerations

- **Numeric**: increment / decrement around your own ID. Identify
  range of valid IDs.
- **UUID v4**: not brute-forceable, but check predictability:
  - Are they actually v4 (random)? or v1 (timestamp+MAC, predictable)?
  - Sequential within a tenant?
  - Stored exposed somewhere (in chat history, email, admin
    notification, public link)?
- **Hash / slug**: derived from what? `md5(user_id+salt)` is
  predictable if the salt leaks.
- **Composite**: `(tenant_id, resource_id)` — auth check on tenant
  but not on resource membership?

### 7.3.2 Batch endpoints

```bash
# Some APIs let you query many at once
curl -sk "https://<target>/api/orders?ids=1,2,3,4,5" -b "$USERA_COOKIE"
curl -sk -X POST "https://<target>/api/orders/batch" \
  -b "$USERA_COOKIE" -H "Content-Type: application/json" \
  -d '{"ids":[1,2,3,4,5]}'
```

Auth check often happens at the request level (you have any auth)
but not per-item. Batch endpoints are common BOLA hits.

### 7.3.3 Read vs write IDOR

- **Read IDOR**: data leak. Severity depends on data sensitivity.
- **Write IDOR**: state change. Almost always Critical. Modify
  another user's email / password / orders → ATO.
- **Delete IDOR**: destructive. Critical.
- **State transition IDOR**: cancel another user's order, change
  another user's order status, mark another user's ticket closed.

### 7.3.4 Indirect IDOR via different surfaces

Sometimes the resource IDOR is blocked but a related surface leaks
the same data:

- IDOR blocked on `/order/{id}`, but `/api/orders?since=...&until=...`
  returns all orders ignoring user filter.
- IDOR blocked on `/ticket/{id}`, but `/search?q=...` returns
  matching tickets across users.
- IDOR blocked on `/user/{id}`, but `/api/notifications` for current
  user includes references with full data.

---

## 7.4 Object-property-level (BOPLA / mass-assignment)

When user updates their profile, what fields are accepted?

```bash
# Capture legitimate update, then add fields
curl -sk -X PUT "https://<target>/api/profile" \
  -b "$USERA_COOKIE" -H "Content-Type: application/json" \
  -d '{
    "name":"Alice",
    "email":"a@x.com",
    "balance":99999,
    "role":"admin",
    "is_admin":true,
    "is_staff":true,
    "user_id":1,
    "id":1,
    "tenant_id":2,
    "email_verified":true,
    "mfa_enabled":false,
    "credits":99999,
    "tier":"enterprise",
    "trial_ends_at":"2099-01-01"
  }'
```

Verify after:
- Did `balance` change?
- Did `role` change?
- Can you set `id=<other user id>` to update *their* record?

Common fields to test mass-assignment with:
- `role`, `roles[]`, `is_admin`, `admin`, `is_staff`, `staff`,
  `is_superuser`, `superuser`
- `balance`, `credits`, `points`
- `tenant_id`, `org_id`, `account_id`, `parent_id`
- `id`, `user_id`, `email_verified`, `mfa_enabled`
- `tier`, `plan`, `subscription_status`
- `is_banned`, `banned`, `disabled`
- `created_at` (sometimes used as trust signal)

Test on every update endpoint, not just profile:
- Settings update.
- Notification preferences.
- API key creation.
- Order placement.
- Ticket creation.
- File upload metadata.

### 7.4.1 Excessive data exposure

GET endpoints that return more than the UI shows:

```bash
curl -sk "https://<target>/api/me" -b "$USERA_COOKIE" | jq 'keys[]'
curl -sk "https://<target>/api/orders/123" -b "$USERA_COOKIE" | jq 'keys[]'
```

Hidden fields in API responses that the UI filters client-side:
- `password_hash`, `mfa_secret`, `mfa_backup_codes`
- `api_key`, `secret`, `internal_user_id`
- `session_id`, `csrf_token`
- `internal_notes`, `admin_comments`, `flagged`, `risk_score`
- `last_ip`, `last_user_agent` (PII)

---

## 7.5 API key scope

If users get API keys:
- Does User A's key only act on User A's resources?
- Does it grant any admin endpoint by accident?
- Does a child-tenant's key reach the parent's endpoints?
- Is the key sent in URL query (leaks via Referer)?
- Does the key have endpoint-scope or all-or-nothing?
- Per-key rate limit independent of session?

```bash
USER_A_KEY="..."
# Try to read another user's order via API
curl -sk -X POST "https://<target>/api/v2" \
  -d "key=$USER_A_KEY&action=status&order=<USERB_ORDER_ID>"
```

---

## 7.6 RBAC / ABAC implementation review

If source available, look for:

- **Policy enforcement point** — where in code?
- **Policy definition** — DB? config? hardcoded?
- **Policy decision point** — middleware? per-controller? per-method?
- **Default deny vs default allow** — when policy is missing for an
  action, what happens?

Common patterns and their bugs:

| Pattern | Common bug |
|---------|-----------|
| Per-controller `if Auth::user()->is_admin` | Forgotten on a new controller; "administrator" role exists but `is_admin` is for `super_admin` |
| Middleware `requireRole('admin')` | Bypassed by direct service-layer call from a different controller |
| Policy classes (e.g. Laravel) | Policy class exists but not registered; or `update` policy exists but `forceUpdate` doesn't |
| Resource ownership: `if order.user_id == request.user.id` | Doesn't apply for admin actions; admin tier accidentally bypasses |
| RLS in DB (Postgres row-level security) | Strong if used, but bypassed by raw queries or admin connection pool |

---

## 7.7 GraphQL field-level authorization

GraphQL responses can include fields that should be admin-only:

```graphql
{ user(id: 42) { id email role created_at last_login_ip mfa_secret } }
```

Each field needs its own check. Common bug: type-level auth (any
authenticated user reads `User`) without field-level (only admin
reads `mfa_secret`).

---

## 7.8 Tenant isolation (multi-tenant apps)

For SaaS / multi-tenant:
- Every query must filter by `tenant_id`. One missing filter = data
  leak across tenants.
- DB-level tenant isolation (separate schemas / databases) vs row-
  level filtering.
- Cache keys include tenant_id (otherwise data leaks via cache).
- Background jobs include tenant context.
- Logs include tenant_id (audit trail across tenants).

If source available, grep for queries without tenant filter:

```bash
grep -rn "WHERE.*=" --include="*.php" --include="*.py" --include="*.js" \
  | grep -v "tenant_id\|account_id\|org_id"
```

Manual review for false positives, but the gaps are real findings.

---

## 7.9 Output

For each broken authz finding, write a finding doc with:
- Exact request as User A vs User B vs anon vs admin.
- Response in each case.
- Side-effects (DB-visible, where checkable).
- Real-world impact statement.

Phase summary in `notes/engagement-log.md`:
- IDOR / BOLA findings count.
- Vertical privilege escalation findings.
- Mass-assignment findings.
- API key scoping findings.
- Multi-tenant isolation status (if applicable).
