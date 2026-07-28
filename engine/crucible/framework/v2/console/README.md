# `framework.v2.console` — the offense Ops Console

## What it is

A decoupled, **loopback-only** HTTP surface that serves the operator UI over the artifacts
the offense engine already writes — reports, the memory/authority stores, the world-model —
and tails the append-only structured log and per-engagement blackboard for the live view. It
is a stdlib-only `ThreadingHTTPServer` (`http.server` + `sqlite3` + `urllib` + vanilla JS)
bound to `127.0.0.1` that issues **zero outbound calls**. Nothing here is imported by the
scanner or the engagement runner (`console/__init__.py`): if the console is down every CLI
path still works. The surface is split in two — a **read-only GET/SSE plane** (`api.py`,
`sse.py`, `blackboard_sse.py`) that is inherently in-scope, and a small **gated-POST plane**
(`actions.py`, `sessions.py`, `chat.py`) whose every mutation is non-destructive, cannot relax
scope, and cannot bypass a gate. This package is **offense-plane** (`.venv-offense`): it may
import `framework.v2` offense modules, but importing `vigil_integration` / anything sovereign
into this interpreter is **FATAL-2** — it bridges to the integration `vigil` process by
subprocess only.

Behind the `vigil up` reverse proxy this same surface is what the CSP-clean **vigil-ui** SPA
(`packages/vigil-ui`) talks to. See the full picture in
[../../../../../knowledge/kb/console-and-ui.md](../../../../../knowledge/kb/console-and-ui.md).

## Authoritative code paths

| File | Role |
|------|------|
| `server.py` | The HTTP handler: route tables, static serving, SSE, the CSRF/rebind guard, and the loopback-only `serve()` bind refusal. |
| `api.py` | Pure, resilient read-only data providers (one per GET route). |
| `actions.py` | The SAFE POST mutations (launch / re-verify / kill-switch trip / provision / AEGIS / proof-export) — each spawns only an already-gated CLI. |
| `sessions.py` | First-class operator-managed engagement sessions (F2): create/rename/delete/connect. |
| `chat.py` | The operator chatbot — a natural-language front door to the SAME gated launcher. |
| `sse.py` / `blackboard_sse.py` | Incremental append-only tailers for the structured log and the engagement blackboard spine. |
| `cli.py` | `python3 -m framework.v2 console` — starts the server and blocks. |

### Routing (all in `server.py:ConsoleHandler`)

**GET — read-only.** `do_GET` (`server.py:211`) dispatches:

- Exact routes: `server.py:_EXACT_ROUTES` (`server.py:59`) — path → zero-arg `api.*` provider
  (`/api/status`, `/api/engagements`, `/api/runs`, `/api/sessions`, `/api/benchmark`,
  `/api/memory`, `/api/kernel`, `/api/tools`, `/api/toolprofiles`, `/api/capabilities`,
  `/api/aegis/status`).
- Prefix routes: `server.py:_PREFIX_ROUTES` (`server.py:81`) — `/api/<name>/<arg>` → provider
  taking one string arg (`/api/report/`, `/api/worldmodel/`, `/api/coverage/`, `/api/charter/`,
  `/api/planner/`, `/api/intel/`, `/api/vulnintel/`, `/api/evolve/`, `/api/compliance/`,
  `/api/drift/`, `/api/evidence/`, `/api/proof/`, `/api/remediate/`, `/api/toolresearch/`).
- Inline SSE / chat: `/api/events` (structured-log tail via `sse.stream_path`), `/api/blackboard`
  (blackboard spine tail with a `Last-Event-ID` durable cursor, `server.py:_sse_blackboard`),
  `/api/aegis/verdicts` (managed-gateway verdict feed), `/api/chat/sessions`,
  `/api/chat/session/<id>`.
- Anything else under `/api/` → 404; everything else → `server.py:_static` (path-traversal-guarded
  serve from `static/`).

**POST — gated mutations.** `do_POST` (`server.py:340`). **First line is the CSRF/rebind guard**
(`_same_origin_as_console`); only then does it branch. Every branch delegates to a function that
validates fail-closed and returns a clean JSON body (never a traceback for operator input):

| POST path | Handler |
|-----------|---------|
| `/api/launch/scan` | `actions.launch_scan` |
| `/api/launch/assessment` | `actions.launch_assessment` (the New-Assessment wizard's one action) |
| `/api/launch/cloud` | `actions.launch_cloud` (seedless cloud/K8s/infra fusion) |
| `/api/reverify/<run>` | `actions.reverify_run` (pure re-computation, no traffic) |
| `/api/proof/export` | `actions.proof_export` |
| `/api/authority/provision` | `actions.provision_loopback_authority` (scope hard-fixed to `127.0.0.1`) |
| `/api/authority/ledger` | `actions.attestation_ledger` (read-only chain replay) |
| `/api/knowledge/gitsync` | `actions.knowledge_gitsync` (local commit, never push) |
| `/api/evolve/<slug>/tick` | `actions.run_evolve_tick` (drafts proposals, mints no fact) |
| `/api/killswitch/<slug>/trip` | `actions.trip_killswitch` (emergency stop; never *clears*) |
| `/api/tools/install` | `actions.provision_tool` |
| `/api/session/{create,rename,delete,connect,disconnect}` | `sessions.*` |
| `/api/chat/send` | `chat.chat_send` |
| `/api/aegis/{setup,stop}` | `actions.aegis_*` |

## Invariants it must preserve, and why

1. **Loopback-only bind (sovereignty).** `serve()` (`server.py:457`) refuses any non-loopback
   host: `if host not in ("127.0.0.1","localhost","::1"): raise ValueError`. The console is a
   single-operator, on-host surface; the unified reverse proxy is the *only* public listener.
   Never widen this bind. Reinforces invariant #4 (never a public bind).

2. **CSRF + DNS-rebinding defense on every POST.** `server.py:_same_origin_as_console`
   (`server.py:274`) is the load-bearing gate. The **positive** proof is a custom header
   `X-Requested-With` (`_CSRF_HEADER`) that the SPA's `fetch` sets and a cross-site HTML `<form>`
   physically cannot (a custom header forces a CORS preflight the console never answers) — this
   is deny-by-*proof*, not deny-by-absence-of-signal, so it also closes the Safari/WebView gap
   where a form POST omits both `Origin` and `Sec-Fetch-Site`. On top of that: `Host` is mandatory
   and must be loopback+exact-port (or an operator-allowlisted proxy domain), `Origin` (when
   present) likewise, and a cross-site `Sec-Fetch-Site` is refused. A malformed authority fails
   **closed** (clean 403, never a 500/traceback). Do not weaken any of these to "make a client
   work" — fix the client.

3. **Strict `'self'` CSP + hardening headers on data responses.** `_CSP` (`server.py:27`) —
   `default-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'` — plus
   `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer` are sent on every
   `_json`/`_sse` response (`_sec_headers`, `server.py:108`). Reinforces invariant #4
   (strict-`'self'` CSP). Note the **deliberate** exception in `_static` (`server.py:143`): the
   local `static/` dir still serves the *legacy* console SPA (inline handlers/`data:` icons) that
   strict CSP would break, so static HTML omits it; the canonical strict CSP for the CSP-clean
   `vigil-ui` bundle is set by the `vigil up` reverse proxy. See Gotchas.

4. **The gate is never bypassed; the console mints no facts.** Read routes only *read* artifacts
   the engine already wrote. Every POST that touches a target spawns the SAME already-gated CLI as
   a subprocess (`actions._spawn_background`) — it never re-implements a scan and never fires
   traffic in-process. Scope is **charter-signed and never passed as an argument**
   (`launch_assessment`, `actions.py:482`); a remote `engage` without a signed charter is refused
   (`actions.py:613`); a non-loopback `scan` is refused; destructive/target-touching steps still
   **queue for owner approval inside the engine** (approve-then-run). A finding becomes a FACT only
   when a deterministic oracle fires in the engine — the console can neither promote a LEAD nor
   relax the [gate of record](../../../../../knowledge/kb/gate-of-record.md). Reinforces invariants
   #2 and #3.

5. **Two-env boundary.** This package runs in `.venv-offense`. It imports `framework.v2` offense
   modules (lazily where heavy — see the function-local imports throughout `api.py`/`actions.py`),
   but it **must never import `vigil_integration` or anything sovereign** — that co-loads the two
   planes in one interpreter (FATAL-2). The graph-backed run path is the model to copy: it resolves
   the integration entrypoint (`actions._vigil_bin`, `actions.py:445`) and **subprocesses** `vigil
   engage` (`_graph_backed_engage_cmd`, `actions.py:451`), never imports it. Reinforces invariant #1.
   See [../../../../../knowledge/kb/two-env-boundary.md](../../../../../knowledge/kb/two-env-boundary.md).

6. **Determinism + append-only.** SSE tailers (`sse.EventTailer`, `blackboard_sse.BlackboardTailer`)
   are read-only over append-only logs; the blackboard stays append-only. Session ordering uses a
   **monotonic per-registry `seq`, not wallclock** (`sessions._next_seq`, `sessions.py:87`) because
   it becomes the F3/F4 graph coordinate; a wallclock `updated_ts` drives UI sort only. Chat/session
   transcripts live off the spine at `0700`/`0600` under `$VIGIL_LIVE_DIR`. Reinforces invariant #4.

## How to extend it safely

**Add a read-only provider + GET route.**
1. Write a **pure, total** function in `api.py` that returns a JSON-serializable `dict` and
   **never raises on a fresh checkout** — wrap every read in `_safe(...)` (`api.py:21`) and reuse
   the framework's own read helpers (`common.paths`, `authority.killswitch`, `memory.store`, …),
   imported **at function scope** (keep the module import-light and hot-path-free).
2. Register it: zero-arg → `_EXACT_ROUTES`; one-string-arg (a run id / slug) → `_PREFIX_ROUTES`.
   Any run id must flow through `actions.run_dir` / `_safe_run_id` so it cannot traverse.
3. Add a unit test under `console/tests/` that calls the provider directly against a half-initialised
   tree and asserts it returns a partial dict, not an exception.

**Add a gated action + POST route.**
1. Write the mutator in `actions.py` (or `sessions.py`/`chat.py`). It must **validate fail-closed
   and return `{"error": ...}`** for any operator-input problem — never raise a traceback into the
   handler. It must spawn only an already-gated CLI via `_spawn_background`; it must **not** relax
   scope (never pass a scope/charter arg) and must **not** import the sovereign plane (subprocess
   `vigil` if you need the integration engine, per `_graph_backed_engage_cmd`).
2. Add a branch in `do_POST` **after** the `_same_origin_as_console()` guard (never before it).
3. Test both the happy path and a fail-closed refusal (bad target, missing charter, unsafe id →
   404, cross-site POST → 403).

**Bridge to the sovereign/integration plane.** Do it exactly like `_vigil_bin` + a subprocess argv.
Never `import vigil_integration`.

## Gotchas

- **Don't "fix" the missing CSP on static responses.** `_static` omits strict CSP on purpose — the
  local SPA is the legacy inline-handler bundle and strict CSP breaks it. The strict-CSP path is the
  `vigil-ui` bundle served behind `vigil up`'s reverse proxy (which sets the canonical CSP). Data
  responses (`_json`/`_sse`) already carry it as harmless defense-in-depth.
- **The custom-header check is load-bearing — do not remove it.** Deny-by-absence-of-`Origin` alone
  lets a cross-site form POST through on older Safari / in-app WebViews. `X-Requested-With` is the
  positive proof.
- **`allowed_hosts`/`allowed_origins` default EMPTY** = loopback-only, byte-identical to before. They
  are the operator's exact reverse-proxy domain forms (via `--allow-host/--allow-origin` or
  `$CRUCIBLE_UI_ALLOWED_HOSTS/_ORIGINS`, `cli.py:34`); the console still **binds** loopback.
- **Traversal is guarded in exactly one place per id kind** — run ids via `_safe_run_id`
  (`actions.py:279`), static via the `STATIC_DIR` resolve check (`server.py:132`), chat/session ids
  via `_safe_chat_id`/`_safe_session_id`. A bad id raises `ValueError`, which `do_GET`/`do_POST` map
  to a clean **404** — never a 500, never a path leak. Reuse these; don't hand-roll a new guard.
- **Some `api.*` providers have no GET route** by design (`engagement_detail`, `reports_data`,
  `authority_full`, `session_detail` — see the U0 note at `server.py:74`). They stay callable and
  unit-tested; don't assume "no route" means "dead code."
- **Kill-switch state fails closed:** `api._killswitch_state` reports `tripped=True` on an unreadable
  state — mirror that honesty in any new safety-state provider.
- **The console never *clears* a kill-switch.** Tripping is a console action; clearing is a
  deliberate out-of-band act.

## Related

- [../../../../../knowledge/kb/console-and-ui.md](../../../../../knowledge/kb/console-and-ui.md) — the console + vigil-ui architecture in full.
- [../../../../../knowledge/kb/gate-of-record.md](../../../../../knowledge/kb/gate-of-record.md) — the conjunctive gate every launched action still passes.
- [../../../../../knowledge/kb/two-env-boundary.md](../../../../../knowledge/kb/two-env-boundary.md) — why importing the sovereign plane here is FATAL-2.
- [../../../../../knowledge/kb/live-layer.md](../../../../../knowledge/kb/live-layer.md) — the blackboard/live spine the SSE routes tail.
