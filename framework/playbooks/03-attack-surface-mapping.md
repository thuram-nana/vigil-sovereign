# Playbook 03 — Attack surface mapping

**Goal:** enumerate every endpoint, parameter, role, file upload,
WebSocket / SSE channel, message queue topic, and trust boundary
that the application exposes. The map you build here is the
foundation for all vulnerability hunting.

A bug you don't have the endpoint for is a bug you won't find.

---

## 3.1 Authenticated crawl, per role (manual)

For each role you can test as (anonymous, low-priv user A, low-priv
user B, reseller / tenant if applicable, admin if available on
staging):

1. Open Burp Suite (Community is fine, Pro is faster), configure
   browser proxy. Or use `mitmproxy` / `caido`.
2. Log in.
3. Click every link, open every modal, exercise every form.
4. For each form, submit a valid value and one obviously-invalid
   value to see the error path.
5. Open the API docs page; if there's a "try it" UI, exercise each
   endpoint.
6. Save the Burp project per role:
   `targets/<name>/recon/enum/burp-<role>.burp`.

The human pass catches state-dependent behavior automated crawlers
miss: modals, async loads, lazy-loaded routes, conditional menus.

## 3.2 Automated crawl as backup

```bash
mkdir -p targets/<name>/recon/enum && cd $_

UA="OBSIDIAN/1.0 (authorized owner-test)"
COOKIE="<paste from browser session>"

# Authenticated
katana -u "https://<target>/" -d 4 -jc \
  -H "Cookie: $COOKIE" -H "User-Agent: $UA" \
  -rl 30 -c 5 -o katana-authed.txt

# Unauthenticated
katana -u "https://<target>/" -d 4 -jc \
  -H "User-Agent: $UA" \
  -rl 30 -c 5 -o katana-unauth.txt

# Diff: anything reachable unauth that should require auth = finding
diff <(sort katana-authed.txt) <(sort katana-unauth.txt) > crawl-diff.txt
```

## 3.3 Content discovery (directory + file fuzzing)

```bash
SL="$HOME/.local/share/seclists"
WL="$SL/Discovery/Web-Content/raft-medium-directories.txt"

# Unauthenticated
ffuf -u "https://<target>/FUZZ" -w "$WL" \
  -mc 200,301,302,401,403 -fs 0 \
  -t 10 -p 0.1 -H "User-Agent: $UA" \
  -o ffuf-unauth.json -of json

# Authenticated
ffuf -u "https://<target>/FUZZ" -w "$WL" \
  -b "$COOKIE" -mc 200,301,302,401,403 -fs 0 \
  -t 10 -p 0.1 -H "User-Agent: $UA" \
  -o ffuf-authed.json -of json

# Recursive on interesting directories (admin, api, etc.)
ffuf -u "https://<target>/admin/FUZZ" -w "$WL" \
  -mc 200,301,302,401,403 -fs 0 -t 5 \
  -b "$COOKIE" -o ffuf-admin.json -of json

# File-extension fuzzing for known dirs
ffuf -u "https://<target>/admin/FUZZ" \
  -w "$SL/Discovery/Web-Content/raft-medium-files.txt" \
  -e .php,.asp,.aspx,.jsp,.do,.action -mc all -fs 0 \
  -o ffuf-admin-files.json -of json
```

Filter aggressively by size (`-fs`) and word count to drop catch-all
200s that some apps return for any path. Refine filters as you learn
the app's default response shape.

`feroxbuster` / `gobuster` are alternatives if `ffuf` doesn't fit.

## 3.4 API endpoint enumeration

The public `/api/v2` (or whatever) is just one piece. Mine for more:

```bash
# Pull every JS file the app loads
hakrawler -url "https://<target>/" -d 3 -insecure 2>/dev/null \
  | grep -E "\.js(\?|$)" | sort -u > js-urls.txt

while read -r url; do
  curl -sk "$url" 2>/dev/null
done < js-urls.txt > all-js.txt

# Extract API-shaped strings
grep -oE "/api/[a-zA-Z0-9_/.-]+" all-js.txt | sort -u > api-from-js.txt
grep -oE "[\"']/[a-zA-Z0-9_/.-]+[\"']" all-js.txt \
  | sed -e 's/^.//' -e 's/.$//' | sort -u > paths-from-js.txt

# Source maps reveal full source if present
grep -E "sourceMappingURL" all-js.txt
```

JS sources frequently expose:
- Internal admin endpoints not linked from UI.
- Beta / feature-flagged endpoints.
- Hardcoded API keys (treat as Critical, surface immediately).
- AWS S3 / GCS bucket names.
- Internal hostnames and IPs.
- Constants like role names, permission strings, error codes.

## 3.5 Parameter discovery

For each interesting endpoint, brute-force parameter names:

```bash
PARAM_WL="$SL/Discovery/Web-Content/burp-parameter-names.txt"

ffuf -u "https://<target>/admin/users?FUZZ=test" \
  -w "$PARAM_WL" -fs <baseline-size> -t 10 \
  -b "$COOKIE" -o param-disc-admin-users.json -of json

# arjun for reflect/length-diff parameter discovery
arjun -u "https://<target>/api/v2" -m POST -c 10 -oJ arjun-results.json
```

Hidden parameters (e.g. `debug`, `admin`, `is_admin`, `_method`,
`role`) are common.

## 3.6 HTTP method enumeration

For every interesting endpoint:

```bash
for m in GET POST PUT DELETE PATCH OPTIONS HEAD TRACE CONNECT; do
  echo "=== $m /admin/users ==="
  curl -sk -X "$m" -o /dev/null -w "%{http_code}\n" \
    -b "$COOKIE" "https://<target>/admin/users"
done
```

Surprising 200s where you expected 405 are findings. Especially:
- PUT working on a nominally read-only endpoint.
- DELETE working without admin.
- OPTIONS returning method list including unexpected verbs.
- TRACE enabled (XST risk).

## 3.7 WebSocket / SSE / long-poll discovery

Modern apps use real-time channels that fuzzers miss:

- Browser DevTools → Network → WS — list every WebSocket connection.
- Look for `EventSource` / SSE consumers in JS.
- Long-poll endpoints (returning after 30s+ of waiting).

For each channel, capture:
- Auth (cookie? subprotocol token? URL token?).
- Message format (JSON? msgpack? custom?).
- Server-pushed message types.
- Client-emitted message types (often more numerous than docs
  suggest).

## 3.8 GraphQL specifics

If `/graphql`, `/api/graphql`, or similar exists:

```bash
# Introspection check (often left on in production)
curl -sk -X POST "https://<target>/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name fields{name}}}}"}' | jq . > graphql-schema.json

# If introspection is off, try:
# - clairvoyance to reconstruct schema
# - graphql-cop / inql for query enumeration
clairvoyance "https://<target>/graphql" -o graphql-clairvoyance.json
```

## 3.9 GRPC / Protobuf / RPC

If `/twirp/`, `/grpc/`, or HTTP/2 with binary content-type:
- `grpcui` for interactive exploration if reflection is enabled.
- Pull `.proto` files from JS bundles or repo if available.

## 3.10 Build the inventory

`targets/<name>/recon/enum/inventory.md`:

```markdown
| Method | Path                          | Auth | Roles allowed | Notes |
|--------|-------------------------------|------|---------------|-------|
| GET    | /                             | no   | all           |       |
| POST   | /login                        | no   | all           |       |
| POST   | /register                     | no   | all           |       |
| GET    | /dashboard                    | yes  | user, child   |       |
| POST   | /api/v2                       | key  | scoped        |       |
| GET    | /admin                        | yes  | admin only    |       |
| POST   | /admin/users                  | yes  | admin only    |       |
| WS     | wss://<target>/ws/orders      | yes  | user, admin   |       |
| GET    | /graphql                      | yes? | ?             |       |
| ...    |                               |      |               |       |
```

Every row in this table becomes a target for Stages 4–6.

## 3.11 Build the role × endpoint matrix

`targets/<name>/recon/enum/role-matrix.md`:

```markdown
|                                | Anon | UserA | UserB | Reseller | Admin |
|--------------------------------|:----:|:-----:|:-----:|:--------:|:-----:|
| GET /dashboard                 |  -   |   ✓   |   ✓   |    ✓     |   ✓   |
| POST /api/v2 add order         |  -   |   ✓   |   ✓   |    ✓     |   ✓   |
| GET /admin/users               |  -   |   -   |   -   |    -     |   ✓   |
| POST /admin/balance/add        |  -   |   -   |   -   |    -     |   ✓   |
| GET /order/{userA's order id}  |  -   |   ✓   |   -   |    -     |   ✓   |
| ...                            |      |       |       |          |       |
```

Each `-` is a hypothesis to verify in Stage 4 (authorization).

## 3.12 Build the data-flow map

For every meaningful endpoint, sketch:

```
client input → controller → validation? → DB / cache / queue / 3rd-party → output → client
```

You'll re-use this map throughout testing. Ask:
- Where is auth checked?
- Where is authorization checked?
- Where is input validated, and against what schema?
- What's the side-effect (DB write, queue push, webhook fire,
  email send)?

`recon/enum/dataflow.md` — one diagram per major feature.

## 3.13 Output

In `targets/<name>/recon/enum/`:

- `katana-authed.txt`, `katana-unauth.txt`, `crawl-diff.txt`
- `ffuf-*.json`
- `js-urls.txt`, `all-js.txt`, `api-from-js.txt`,
  `paths-from-js.txt`
- `param-disc-*.json`, `arjun-results.json`
- `inventory.md`
- `role-matrix.md`
- `dataflow.md` (one section per major feature)
- `graphql-*.json` (if applicable)

Append to `notes/engagement-log.md`:
- Total endpoints discovered.
- Endpoints not in API docs (interesting).
- Endpoints reachable unauth that probably shouldn't be.
- Hardcoded secrets in JS (Critical, surfaced separately).
- Coverage state of role-matrix.

Ask operator to advance to Stage 4.
