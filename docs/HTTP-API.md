<!-- CLAIM:W16-STD-7-http-api -->
# The HTTP API — `crucible api`

This chapter is the briefing's answer to a question the prose chapters and the CLI reference left
unanswered (limitations inventory §17): **how do I drive and observe CRUCIBLE over HTTP, and what is the
exact surface a request can reach?** Every route the server actually declares is listed below with its
method and effect. The page is kept honest by
[`docs/tests/test_w16_std7_docs_completeness.py`](tests/test_w16_std7_docs_completeness.py), a **required**
CI check (`the briefing explains every agent and capability`) that enumerates the routes **from the code**
(`engine/crucible/framework/v2/api/server.py`) and fails the build when a new route is added and not
documented here — or when this page documents a route the code does not serve.

> The HTTP API is **off unless you start it**, binds **loopback only**, and exposes **no ungated
> capability**. It is a programmatic view over the same audited reads the Ops Console renders, plus a
> POST surface where every action runs through the **same fail-closed gate chain as a local action**.

## Starting it

```
vigil crucible api [--port 8799] [--host 127.0.0.1] [--allow-host H]... [--allow-origin O]...
python3 -m framework.v2 api [--port 8799] [--host 127.0.0.1]      # equivalent, from engine/crucible
```

- **Default bind:** `127.0.0.1:8799`. `serve()` **refuses any non-loopback host**
  (`api/server.py` `serve()` raises `ValueError` when `host not in LOOPBACK_BIND_HOSTS`), so the API
  cannot be bound to a routable interface by a flag typo.
- **`--allow-host` / `--allow-origin`** (repeatable; also `$CRUCIBLE_UI_ALLOWED_HOSTS` /
  `$CRUCIBLE_UI_ALLOWED_ORIGINS`) widen the same-origin POST guard **only** for an operator who
  deliberately fronts the API behind an authenticated reverse proxy. Default is empty = loopback-only.

## Authentication and CSRF

- **Loopback bind** is the primary control: by default only a process on the same host can connect.
- **Same-origin / CSRF guard on every POST** (`api/guard.py check_same_origin`): a POST must satisfy
  loopback + a custom header + a Host/Origin proof, so a cross-site page cannot drive the API. A failing
  POST is `403`.
- **Optional API key** (`api/authn.py`): opt-in via `$CRUCIBLE_API_KEY` (or `serve(api_key=...)`). When
  set, **every** request must present it as `Authorization: Bearer <key>` **or** the `X-Relay-Key` header;
  the key is compared in constant time (`hmac.compare_digest`) and travels only in a header (never the
  query string). A **missing** key is `401`, a **wrong** key is `403`. It is **stacked on top of** the
  loopback + same-origin guards, never in place of them. A blank/whitespace value is treated as unset, so
  a misconfigured empty key cannot silently disable auth. **Default (no key configured) = no-op**
  (loopback + same-origin only).

## Request and response model

- **No static-file serving** at all, so there is **no path-traversal surface**.
- A POST body is **bounded** (`_MAX_BODY = 8 MiB`), parsed as **JSON only** (no eval/shell), and must be
  a JSON **object**; a bad length, an oversize body, non-JSON, or a non-object all return a clean `400`
  (never a traceback).
- Responses are `application/json; charset=utf-8` with hardening headers on every response:
  `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`.
- Errors never leak a traceback: `404` for an unknown endpoint/action, `500` wrapped as
  `{"error": "<Type>: <msg>"}` for an unexpected read/gate error.

## Health and readiness probes (unauthenticated)

These are answered **before** the API-key gate so a k8s / load-balancer probe (which presents no key)
can reach them. They carry no secret.

| Method | Route | Effect |
|---|---|---|
| GET | `/healthz` | Liveness — the process answers. Always `{"ok": true}`. |
| GET | `/readyz` | Readiness — checks the console working directory the API reads from and the importer writes to; `503` (with the exception **type** name, never a path) when that store cannot be created/written. |

## Reads — `GET /api/v1/*` (issue no traffic, mutate nothing)

Each read delegates to the console's already-audited read layer (`api/reads.py` → `console.api`) and
returns a JSON-serialisable dict; it is safe on a fresh / half-initialised tree.

| Method | Route | Returns |
|---|---|---|
| GET | `/api/v1/status` | Environment summary: reachable backends, resolved paths, optional deps. |
| GET | `/api/v1/engagements` | List every engagement (slug + summary). |
| GET | `/api/v1/engagement/<slug>` | One engagement's detail. |
| GET | `/api/v1/authority/<slug>` | The full charter / scope / authority object bounding a slug. |
| GET | `/api/v1/runs` | List every recorded run. |
| GET | `/api/v1/report/<run_id>` | The assembled report for a run. |
| GET | `/api/v1/worldmodel/<run_id>` | The world model (assets/findings) projected for a run. |
| GET | `/api/v1/evidence/<run_id>` | The signed evidence tree for a run. |
| GET | `/api/v1/intel/<slug>` | The intel-graph state for a slug. |
| GET | `/api/v1/tools` | Enumerate the gated tool registry — the **action surface described, not invoked** (name + tier + capability + destructive + reaches-hosts). Listing runs nothing and passes no gate. |
| GET | `/api/v1/imports/<slug>` | Enumerate the **leads** a prior import minted into the intel store for a slug — each labelled an **unverified lead**, not a fact. |

## Actions — `POST /api/v1/*` (gated tool invocations)

There is exactly one way an action runs: it is translated into a tool invocation and threaded through the
**full fail-closed gate chain** (`api/actions.py` → `agents.tools.invoke_tool`) — kill-switch, entitlement
(per the tool's declared capability), charter scope (if the tool touches a host), destructive-confirm, and
the egress allowlist. An unauthorised action is **refused exactly as it would be locally**: the tool never
runs, nothing is sent, and the refusal `{gate, reason}` is returned. The registry the API drives
(`default_registry`) holds only **safe** tools — re-verify a finding (offline) and import a third-party
report (passive) — **no egress or exploit tool is exposed**. Destructive-confirm defaults to **deny** on an
API request (there is no interactive operator), so a destructive tool can **never** be auto-approved here.

| Method | Route | Body | Effect |
|---|---|---|---|
| POST | `/api/v1/tool/invoke` | `{"tool": str, "slug": str, "args": object}` | Invoke `tool` through the gate chain, bound to `slug`'s charter/scope/kill-switch. Returns `{ok, refused, gate, summary, note, output}`. |
| POST | `/api/v1/import` | `{"format": str, "report": str, "slug": str, "source_tool": str?}` | Import a third-party report as **unverified leads** — still routed through the gate chain (a tripped kill-switch refuses it before it runs). |

## Route reference (the exact set the code serves)

The complete set of routes this server declares, which the required test enumerates from
`api/server.py` and pins against this page in both directions:

`/healthz` · `/readyz` · `/api/v1/status` · `/api/v1/engagements` · `/api/v1/engagement/<slug>` ·
`/api/v1/authority/<slug>` · `/api/v1/runs` · `/api/v1/report/<run_id>` · `/api/v1/worldmodel/<run_id>` ·
`/api/v1/evidence/<run_id>` · `/api/v1/intel/<slug>` · `/api/v1/tools` · `/api/v1/imports/<slug>` ·
`/api/v1/tool/invoke` · `/api/v1/import`

## Other HTTP surfaces in the product (documented elsewhere)

The `crucible api` server above is the general-purpose programmatic API. The product ships a few other
HTTP surfaces, each with a narrower, dedicated purpose and its own security posture — they are **not**
part of the `/api/v1` surface and are documented where they live:

- **The unified command UI reverse proxy** — `vigil up` (`integration/vigil_integration/uiproxy.py`):
  one loopback origin federating the two planes; see [README](../README.md#the-unified-web-ui--vigil-up).
- **The Ops Console** — `crucible console` (`framework/v2/console/server.py`): a loopback read-only web UI.
- **The AEGIS runtime gateway** — `framework/v2/aegis/gateway.py`: the embeddable defensive gateway.
- **The posture endpoint** — `integration/vigil_integration/posture/endpoint.py`: serves a signed
  Certificate of Non-Exploitability bundle (`vigil posture`).
- **The witness co-sign service** — `vigil witness` (`integration/vigil_integration/witness_service.py`):
  an independently-keyed loopback transparency witness.
- **The MCP server** — `crucible mcp` (`framework/v2/mcp`): engine tools over the Model Context Protocol.

For the behaviour and honest scope of each subsystem see [`docs/CLI-REFERENCE.md`](CLI-REFERENCE.md),
[`docs/FEATURES.md`](FEATURES.md), and [`docs/AS-BUILT.md`](AS-BUILT.md).
