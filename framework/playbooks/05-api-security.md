# Playbook 05 — API security

**Goal:** comprehensive testing of HTTP REST, GraphQL, gRPC, and
WebSocket APIs. Aligned to OWASP API Security Top 10 (2023).

APIs are increasingly the dominant attack surface. They are also the
most commonly under-tested because security teams focus on the UI.

---

## 5.1 OWASP API Security Top 10 — 2023

| # | Risk | Drill section |
|---|------|----------------|
| API1 | Broken Object Level Authorization (BOLA / IDOR) | §5.3 |
| API2 | Broken Authentication | §5.4 |
| API3 | Broken Object Property Level Authorization | §5.5 |
| API4 | Unrestricted Resource Consumption | §5.6 |
| API5 | Broken Function Level Authorization (BFLA) | §5.7 |
| API6 | Unrestricted Access to Sensitive Business Flows | §5.8 |
| API7 | Server-Side Request Forgery | playbook 08 §8.4 |
| API8 | Security Misconfiguration | §5.9 |
| API9 | Improper Inventory Management | §5.10 |
| API10 | Unsafe Consumption of APIs | §5.11 |

---

## 5.2 API key lifecycle

For each API key model:

- **Issuance**: how is a key issued? (registration auto-issue, on
  demand, per-resource scope).
- **Display**: where is the key shown? (dashboard once, dashboard
  always, in HTML view-source, leaked to analytics?).
- **Rotation**: can users rotate keys? Does password reset rotate
  the key? (it should — old key shouldn't survive a password
  compromise).
- **Revocation**: does revocation take effect immediately?
- **Entropy**: 32+ char from CSPRNG, not 8-char numeric.
- **Transmission**: where does the API accept the key?
  - **Header** (`Authorization: Bearer …`, `X-API-Key: …`) — best.
  - **Body parameter** — acceptable.
  - **URL query** (`?key=...`) — leaks via Referer, browser history,
    server access logs, third-party analytics on the dashboard.

```bash
# Test that the API accepts the key in unexpected locations
KEY="<test key>"
ENDPOINT="https://<target>/api/v2"
curl -sk -X POST "$ENDPOINT" -d "key=$KEY&action=balance" -o /tmp/body
curl -sk -X POST "$ENDPOINT" -H "Authorization: Bearer $KEY" -d "action=balance" -o /tmp/header
curl -sk -X POST "$ENDPOINT?key=$KEY" -d "action=balance" -o /tmp/url
diff /tmp/body /tmp/header
diff /tmp/header /tmp/url
```

If the API accepts the key in URL query when docs say header-only,
the operator may have backwards-compat code path that should be
removed.

## 5.3 BOLA / IDOR (API1)

The single highest-yield class on REST APIs. For every endpoint that
references an object by ID:

```bash
# As User A (key A), find your own object IDs.
# As User B (key B), try to access User A's objects.

USER_A_ORDER_ID="<from User A>"
KEY_B="<User B's key>"

curl -sk -X POST "https://<target>/api/v2" \
  -d "key=$KEY_B&action=status&order=$USER_A_ORDER_ID"
```

Test patterns:
- Numeric IDs — increment/decrement. Mass enumeration via
  `?orders=1,2,3,...` or `?id_in=[1,2,3,...]`.
- UUIDs — usually not brute-forceable, but check for predictability
  (UUIDv1 = timestamp+MAC; UUIDv4 = random).
- Slugs / hashes — sometimes derived predictably (`md5(user_id+salt)`).
- Composite keys — `(tenant_id, resource_id)` may be checked on
  tenant but not on resource.
- Batch endpoints — auth check on outer query but not per-item:
  `?ids=user_a_resource,user_b_resource`.

Per resource type:
- Orders, transactions, invoices, receipts.
- Tickets and their attachments.
- API keys (can you read another user's keys?).
- Profile fields (PII, address, phone).
- Settings and preferences.
- Notifications.
- Audit logs (yours vs all).

Both **read** and **write** IDOR. Write IDOR is much higher impact.

## 5.4 Broken authentication (API2)

- **No auth** on endpoints that should require it.
- **Weak auth** — short keys, predictable keys, keys that don't
  expire.
- **JWT** — playbook 11 §11.3.
- **OAuth flows** — playbook 19.
- **Auth check at wrong layer** — e.g. JWT validated for signature
  but `exp` not checked, or `aud` not checked, or `iss` not checked.
- **Auth bypass via empty / missing header** — sometimes apps
  default to "trusted" if no auth header is sent (tested for
  internal-service auth).
- **Re-auth gaps** — sensitive actions (password change, withdrawal)
  not re-authed, just session-checked.

## 5.5 Broken object-property-level authorization (API3)

The user can read/write fields they shouldn't:

- **Excessive data exposure**: GET endpoint returns more fields than
  the UI shows. Hidden `is_admin`, `internal_notes`, `password_hash`
  field?
- **Mass-assignment**: PUT/PATCH endpoint writes any field the
  client sends, including ones not in the form. (Playbook 07 §7.4.)
- **Field-level filtering missing** at the API layer — UI does it
  client-side, API trusts.

```bash
# Probe a profile GET for hidden fields
curl -sk -H "Authorization: Bearer $KEY" \
  "https://<target>/api/me" | jq 'keys[]'
```

Compare returned fields against the UI. Fields like
`password_hash`, `mfa_secret`, `internal_user_id`, `session_id`,
`role`, `tenant_id` should not be in client responses.

## 5.6 Unrestricted resource consumption (API4)

- **No rate limit** — playbook 04 §4.13.
- **Per-IP only** — bypassable with proxies; criminal-tier attackers
  always have proxies.
- **Per-key only** — bypassable by registering many keys.
- **Should be combined**: per-key AND per-IP AND per-action AND per-
  endpoint, with progressive backoff.
- **Expensive endpoints**: search, export, report-generation,
  password reset, bulk operations. These should have stricter
  limits and resource quotas.
- **Pagination not enforced**: `?limit=999999` returns gigabytes of
  data.

## 5.7 Broken function-level authorization (API5 / BFLA)

A regular user can call admin-tier functions:

```bash
# As regular user
curl -sk -X POST "https://<target>/api/admin/users/disable" \
  -H "Authorization: Bearer $REGULAR_KEY" \
  -d '{"user_id":42}'
```

Discovery:
- Admin endpoints in JS that are checked client-side only.
- Admin endpoints in API docs marked "admin only" — actually
  enforced?
- Method swap: `POST /api/admin/users` returns 200 even though
  `GET /api/admin/users` returns 403.
- Verb tunneling: `POST /api/something` with `_method=DELETE`
  bypassing checks tied to verb.
- Header tricks: `X-Original-URL: /api/admin/...`,
  `X-Forwarded-For: 127.0.0.1` (some apps trust internal IPs).

## 5.8 Unrestricted access to sensitive business flows (API6)

The bug class for SMM panels, e-commerce, and any app with
abuseable workflows. See playbook 10 (business logic).

Examples:
- API endpoint that allows mass purchase / mass action without
  human friction — abused for scalping, financial fraud.
- API endpoint that allows account creation without CAPTCHA — bot
  registration at scale.
- API endpoint that allows unlimited password-reset triggers —
  email-bombing a target user.
- API endpoint that allows withdrawal without secondary
  confirmation — drain via stolen API key.

## 5.9 Security misconfiguration (API8)

- **CORS** — `Access-Control-Allow-Origin: *` with credentials, or
  reflective Origin (playbook 09 §9.1).
- **Verbose errors** — stack traces, DB errors, internal paths.
- **Default endpoints** — health checks, metrics endpoints (Prometheus
  `/metrics`) exposed publicly.
- **Documentation endpoints** — Swagger UI at `/api-docs`, GraphQL
  Playground in production.
- **Debug headers** — `X-Debug-Token`, `X-Profiler-Token`.
- **Cache control** missing on auth-required endpoints.
- **Permissive HTTP methods** — TRACE, CONNECT, PROPFIND.

## 5.10 Improper inventory management (API9)

The classic "v1 still routed after v2 launched" bug:

```bash
# Are old versions still routed?
for v in v0 v1 v2 v3 beta alpha old internal; do
  echo "=== /api/$v ==="
  curl -sk "https://<target>/api/$v" -o /dev/null -w "%{http_code}\n"
done
```

Other inventory issues:
- Internal-only API routes accidentally exposed externally.
- `/api/internal/*` reachable from outside.
- Staging API endpoints reachable from production hosts.
- Different auth requirements on `v1` vs `v2` (often `v1` looser).

## 5.11 Unsafe consumption of APIs (API10)

Your app calls third-party APIs. Test:
- Does your app trust third-party responses without validation?
- Do you re-render third-party content without escaping?
- If a third-party returns a redirect, do you follow it without
  origin check (SSRF chain)?
- Are third-party API keys stored securely server-side?

Hard to test from outside; comes up in source review (playbook 20).

---

## 5.12 GraphQL specifics

If `/graphql` exists:

```bash
# Introspection
curl -sk -X POST "https://<target>/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name fields{name}}}}"}' | jq .

# Disable in prod is best practice. If on, you have full schema.

# Depth attack
curl -sk -X POST "https://<target>/graphql" -H "Content-Type: application/json" -d '{
  "query": "{ user { friends { friends { friends { friends { friends { id } } } } } } }"
}'

# Alias rate-limit bypass
curl -sk -X POST "https://<target>/graphql" -H "Content-Type: application/json" -d '{
  "query": "{ a:user(id:1){...} b:user(id:2){...} c:user(id:3){...} }"
}'

# Batched query  
curl -sk -X POST "https://<target>/graphql" -H "Content-Type: application/json" -d '[
  {"query":"{user(id:1){id email}}"},
  {"query":"{user(id:2){id email}}"}
]'
```

GraphQL-specific attacks:
- Introspection in production.
- Depth limit absent → DoS.
- Field-level auth missing — admin-only fields embedded in normal
  queries.
- Aliases bypass rate limits (one HTTP request, N logical operations).
- Batched queries similar.
- Mutation enumeration via introspection reveals admin mutations.

Tools: `clairvoyance` (reconstruct schema if introspection off),
`graphql-cop`, `inql`, `graphw00f`.

---

## 5.13 gRPC / Protobuf

If you find a gRPC endpoint (HTTP/2, content-type
`application/grpc`):

- Reflection enabled? `grpcurl -plaintext <host> list`.
- Pull `.proto` from JS bundles, mobile app, or repo.
- Service-level auth: can you call services unauth?
- Method-level auth: are sensitive methods admin-only?

`grpcui` for interactive exploration. `evilgrpc` for fuzzing.

---

## 5.14 WebSocket / SSE

For each real-time channel:
- Capture handshake (`ws://...`, `wss://...`).
- Auth: cookie? subprotocol token? URL token?
- Origin check on handshake (Cross-Site WebSocket Hijacking).
- Per-message auth: does the server re-check auth per-message, or
  trust the connection?
- Message validation: send malformed JSON, oversized messages,
  unexpected message types.

```python
# scripts/api/ws-fuzz.py — per-target adapt
import websocket, json
ws = websocket.create_connection("wss://<target>/ws", cookie=cookie)
ws.send(json.dumps({"type":"admin_command","action":"list_users"}))
print(ws.recv())
```

Cross-Site WebSocket Hijacking: if the WS handshake auth is just a
cookie (no Origin check), an attacker page can open a WS connection
on the user's behalf and read pushed messages.

---

## 5.15 Output

Per-finding in `findings/`. Phase summary in
`notes/engagement-log.md`:

- API key handling assessment.
- Rate-limit posture across endpoints.
- Old version exposure status.
- BOLA / BFLA findings count.
- GraphQL / gRPC / WS findings if applicable.
- API-specific Critical / High count.
