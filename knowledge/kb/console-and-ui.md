# Console & Web UI

## What it is

The **VIGIL COMMAND UI** is one beginner-friendly, no-build, strict-CSP single-page app that fronts
the *whole* system. It is a single committed bundle — `packages/vigil-ui/` (`app.js`, `ui.js`,
`manual.js`, `tokens.css` + `components.css` → `style.css`, `index.html`) — that federates **two
isolated trust planes** behind one browser origin: the **offense** plane (the CRUCIBLE console + gated
api) and the **sovereign** plane (the SIGIL owner cockpit). The browser talks to *one* listener — the
`vigil up` reverse proxy — which forwards `/offense/*` and `/sovereign/*` to three separate loopback
backend processes, each in its own venv. `app.js` is a hash-router over **21 screens**; each screen is
a `render*(screen)` function that fetches read-only JSON (or fires a safe action) against the right
plane and builds DOM with `VUI.h` (no inline handlers, no `eval` — CSP-native). The offense console
(`engine/crucible/framework/v2/console/`) serves the read plane (`api.py` GET providers) and the only
mutations the UI can make (`actions.py` safe actions, `server.py` routing). SIGIL knows the UI through
a generated **system map** (`screens.yaml` → `system-map.json`), and CI (`test_system_map_sync.py`)
fails the build if the map ever drifts from the real NAV/route.

See [`architecture.md`](./architecture.md) for the two-plane model, oracle authority, and the gate.

## Authoritative code paths

### Frontend — `packages/vigil-ui/`

- **`app.js`** — the shell + all 21 screens.
  - `const NAV` (lines 19–47) — the navigation model: three groups (`DO` / `MANAGE` / `LEARN`), each
    item `{ id, label, icon, ready, owner? }`. `owner: true` marks a sovereign-owner-plane screen
    (`safety`, `charter`, `apikeys`, `settings`).
  - `CFG` / `SOV` / `OFF` (lines 12–14) — `SOV(p) = CFG.api.sovereign + p`, `OFF(p) = CFG.api.offense
    + p`. These are the plane prefixes every fetch prepends.
  - `renderNav()` + `visible()` (lines 91–104), `navItem()` (105–116), `current()` (117) — render the
    sidebar; `visible()` hides offense-only screens (`assess`/`live`/`findings`/`fixes`) unless the
    top-bar plane toggle is `offense`, and `defense` unless it is `defense`.
  - `shell()` (119–129) — builds `#topbar`, `#nav`, `#main > #screen`, and the detail drawer.
  - `route()` (3932–3961) — the hash router: `current()` → an `if (id === "…") { render…(screen);
    return; }` branch per screen; unknown ids fall to `renderStub`.
  - `boot()` (3963–3977) — reads the server-injected `data-token` / `data-sovereign` / `data-offense`
    body attributes into `CFG`, mounts the shell, wires `hashchange → route`, defaults to `#/home`.
  - `isFact(p)` (500) `= !!p.verified_by_oracle`; `KIND_META` (469–498) — the 14 offense event kinds
    the Live/Findings views render. **A FACT badge is shown only when the oracle verified it.**
  - Exemplar screen: `renderTools()` (435–450) — `V.getJSON(OFF("/api/tools")).then(renderToolsData)
    .catch(…offline…)`. Copy this pattern.
- **`ui.js`** — the `window.VUI` micro-framework (export at 151–153): `h(tag, props, children)` (10),
  `mount` (48), `store` (52), `getJSON` (70) / `postJSON` (75), `sse` (87), `icon`, `pill`, `toast`.
  `_headers()` (65) sets **`X-Requested-With: vigil-ui`** and the token header on every fetch — this is
  the anti-CSRF header the console requires (see below).
- **`index.html`** — `<body data-token="__VIGIL_TOKEN__" data-sovereign="__VIGIL_SOVEREIGN__"
  data-offense="__VIGIL_OFFENSE__">`. The serving layer rewrites these placeholders per deployment
  (standalone → `""`; behind `vigil up` → `/sovereign` and `/offense`).
- **`sync.sh`** — author-time vendoring (NO build, NO network): concatenates the CSS and copies the JS
  + index, **byte-identically**, into *both* plane servers' static dirs
  (`apps/sigil/sigil/ui/static` and `engine/crucible/framework/v2/console/static`). Re-run after
  editing any `packages/vigil-ui/*` source. `packages/vigil-ui/` is the single source of truth; the
  copies are generated.

### Offense console — `engine/crucible/framework/v2/console/`

- **`server.py`** — a stdlib `ThreadingHTTPServer` bound **127.0.0.1 only** (`serve()`, 457–473,
  refuses any non-loopback bind). Serves the SPA + read APIs + SSE + safe POSTs.
  - `_EXACT_ROUTES` (59–71) — exact-path GET → zero-arg `api.*` provider (`/api/status`,
    `/api/tools`, `/api/sessions`, `/api/aegis/status`, …).
  - `_PREFIX_ROUTES` (79–96) — `"/api/<name>/"` GET → one-arg `api.*` provider (`/api/report/<run>`,
    `/api/proof/<run>`, `/api/compliance/<run>`, `/api/authority/<slug>`, …).
  - `do_GET` (211–264) — SSE streams (`/api/events`, `/api/blackboard`, `/api/aegis/verdicts`), the
    chat reads, then the two route tables, else `_static`.
  - `do_POST` (340–454) — the **only mutations**: `launch/scan`, `launch/assessment`, `launch/cloud`,
    `reverify/<run>`, `proof/export`, `authority/provision`, `killswitch/<slug>/trip`, `tools/install`,
    `session/*`, `chat/send`, `aegis/setup|stop`, `evolve/<slug>/tick`. Each dispatches to `actions.*`
    or `sessions.*`/`chat.*`.
  - `_same_origin_as_console` (274–338) — anti-CSRF / anti-DNS-rebind guard on **every** POST:
    requires the custom `X-Requested-With` header (`_CSRF_HEADER`, 23), a same-origin/`none`
    `Sec-Fetch-Site`, and a loopback (or operator-allowlisted proxy) `Host`/`Origin` on the exact
    port. Fails closed.
  - `_CSP` (27) — `default-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
    sent on every JSON/SSE response.
- **`api.py`** — read-only data providers, one per endpoint (`status_data` 35, `tools_data` 591,
  `run_report` 212, `proof_list` 419, `compliance_data` 885, `drift_data` 912, …). Every one is PURE +
  RESILIENT: `_safe()` (21) swallows errors so a half-initialised tree renders partially, never 500s.
  It reuses the framework's own read helpers and **imports nothing from the scan/engage hot path**. It
  mints no facts — reads only.
- **`actions.py`** — the safe operator actions. Each is non-destructive and **spawns the SAME gated
  CLI as a subprocess** — `[sys.executable, "-m", "framework.v2", "engage"|"scan"|"aegis", …]`
  (e.g. `launch_assessment` 469, spawns at 599/617; `launch_cloud` 202) — never in-process. It cannot
  relax scope (scope is charter-signed, never an arg) and cannot bypass a gate (the spawned engine
  runs its own kill-switch + signed-charter preflight and queues every target-touching step for owner
  approval). `reverify_run` (636) is a pure re-computation of retained oracle certificates; no traffic.

### Sovereign cockpit — `apps/sigil/sigil/ui/server.py`

The owner plane (`build_server`/`serve`, default port **8733**). Serves `/api/snapshot`,
`/api/settings`, `/api/stream` (SSE), `/api/sigil/hud`, and the token+`Origin`-gated `POST /api/action`.
These are exactly the endpoints `app.js` reaches via `SOV(…)` — used by owner screens (`settings`,
`apikeys`, `charter`, `safety`) and the SIGIL voice/HUD channel.

### The reverse proxy — `integration/vigil_integration/uiproxy.py`

`vigil up` — the one-command launcher + a **pure-stdlib** self-contained reverse proxy (module
docstring 1–33). It imports **neither** `framework`/`strix` **nor** `sigil`; it spawns the three
backends as separate OS processes (via `dispatch.resolve`) and forwards:

```
browser ─▶ vigil up proxy (127.0.0.1:8770, the ONLY human-facing listener)
             ├─ /sovereign/*        ▶ 127.0.0.1:8733   (sigil serve — sovereign cockpit)
             ├─ /offense/api/v1/*   ▶ 127.0.0.1:8799   (crucible api  — gated action plane)
             └─ /offense/*          ▶ 127.0.0.1:8787   (crucible console — read + SSE plane)
```

Ports/bases: `DEFAULT_PROXY_PORT=8770`, `SOVEREIGN_PORT=8733`, `CONSOLE_PORT=8787`, `API_PORT=8799`,
`SOVEREIGN_BASE="/sovereign"`, `OFFENSE_BASE="/offense"` (59–67). The proxy refuses a public/unspecified
bind (`bind_ok`, ~392–399); `--domain` is an allowlist *string* (front it with a TLS proxy), never a
bind.

### The system map — SIGIL's machine-readable knowledge of the UI

- **`knowledge/system-map/screens.yaml`** — the HUMAN source of truth. One entry per screen:
  `id · label · group · owner · plane · description · synonyms` (voice phrases for SIGIL nav; ≥1
  required).
- **`knowledge/system-map/system-map.json`** — **generated** from `screens.yaml` and **committed** so
  both planes read it same-origin. Screens sorted by id; carries a `source_sha` of `screens.yaml`
  (the sha *is* the version — no wallclock).
- **`tools/system-map/generate.py`** — read-only + deterministic. `--write` regenerates the json
  (byte-identical for the same input); `--check` fails on drift. `_verify()` asserts **manifest ids ==
  NAV ids == route() ids**, plus a cardinality guard (a duplicate or unparseable id can't vanish), plus
  ≥1 synonym per screen, plus "json not stale". Extraction is **scoped** to the `const NAV = [...]`
  array (`_nav_block`) and the `function route()` body (`_route_block`) so unrelated ids (scan modes,
  wizard targets, providers) are never wrongly picked up.
- **`apps/sigil/tests/test_system_map_sync.py`** — the CI gate. It proves the gate *bites*: a phantom
  screen, a missing synonym, a camelCase/hyphen id, and a duplicate NAV id are all caught.

## Invariants this subsystem must preserve (and why)

1. **Two-env boundary / FATAL-2.** The console is offense-plane; the cockpit is sovereign-plane; they
   **never co-load in one interpreter**. `uiproxy.py` is pure stdlib and imports neither engine.
   `api.py` reuses framework read helpers but stays off the hot path; `actions.py` reaches the engine
   *only* by spawning `python -m framework.v2 …` subprocesses. **Never** `import sigil` (or any
   sovereign module) from console code, and never call an offense engine function in-process from the
   proxy. Planes bridge only by subprocess or the signed inert file spool. *Why: a single interpreter
   holding both the keyless offense engine and the owner-key sovereign core is the one failure that
   collapses sovereignty.*
2. **Oracle authority — the UI renders provenance honestly.** `isFact()` gates the FACT badge on
   `verified_by_oracle`; a LEAD is never shown as a FACT. The console mints **nothing**: `api.py` is
   read-only, `actions.py` only launches gated CLIs and re-computes certificates. *Why: "the machine
   cannot lie about a finding" must hold at the pixel, not just in the engine.*
3. **Gate of record.** Every target-touching action the UI triggers goes through the engine's
   conjunctive gate — the console spawns the same gated CLI and cannot pass scope or skip approval.
   The console's own `do_POST` adds a same-origin/anti-rebind guard so a malicious page the operator
   visits cannot drive it. *Why: the browser is an untrusted driver; the gate is the authority.*
4. **Determinism + append-only + never-public.** `generate.py` and `_build_manifest` use no wallclock
   or rng (the `source_sha` is the version); `system-map.json` is byte-identical per input. Every
   server binds **loopback only** (the proxy is the sole public listener, and it refuses a routable
   bind). The CSP is strict `'self'`. *Why: the map must be reproducible and diffable, and no plane may
   ever be directly reachable.*

## How to extend it safely — add a screen end-to-end

Follow every step; CI enforces the ones that keep SIGIL's map in sync.

1. **NAV.** Add an item to `const NAV` in `app.js` (lines 19–47): `{ id: "myscreen", label: "My
   Screen", icon: "bolt", ready: true }` (add `owner: true` only if it needs the sovereign owner
   plane). Pick a lowercase, hyphen/underscore-free `id`.
2. **Render fn.** Write `function renderMyscreen(screen) { … }`. Copy the `renderTools` (435) pattern:
   `V.mount(screen, [ h("div.screen-head", …), … ])`, then `V.getJSON(OFF("/api/myscreen")).then(fn)
   .catch(offline)`. Use `SOV(…)` instead of `OFF(…)` if the data lives on the owner cockpit. Build DOM
   only with `V.h`/`V.icon` — no inline handlers, no `eval` (strict CSP).
3. **Route.** Add a branch to `route()` (3932–3961): `if (id === "myscreen") { renderMyscreen(screen);
   return; }`. The `id` string must be **identical** to the NAV id.
4. **Backend (if it needs data).**
   - *Read:* add a provider to `console/api.py` (`def myscreen_data() -> dict` — wrap risky reads in
     `_safe`, never raise), then register it in `server.py` — `_EXACT_ROUTES` for a fixed path or
     `_PREFIX_ROUTES` for `"/api/myscreen/<arg>"`.
   - *Safe action:* add a handler to `console/actions.py` that **spawns a gated CLI** (never touches
     the engine in-process; never accepts a scope arg), then add a branch in `server.py:do_POST`. From
     the frontend call it with `V.postJSON(OFF("/api/myaction"), body)` — `postJSON` already sets the
     `X-Requested-With` header the anti-CSRF guard requires.
5. **System map.** Add the screen to `knowledge/system-map/screens.yaml`: `id` (== NAV id == route id),
   `label`, `group`, `owner`, `plane: unified`, a `description`, and **≥1 `synonyms`** (voice nav fails
   CI otherwise).
6. **Regenerate + commit** the manifest: `python tools/system-map/generate.py --write` and commit the
   updated `system-map.json` (else the "stale" check fails).
7. **Vendor the bundle:** run `packages/vigil-ui/sync.sh` so both plane static dirs get the new
   `app.js` byte-identically.
8. **Verify:** `python tools/system-map/generate.py --check` (or run
   `apps/sigil/tests/test_system_map_sync.py`) — it must report ids match NAV == route() with a synonym
   each.

**Tests to add:** the drift test already covers the id-set/synonym contract automatically once steps
1–6 are done. If you added a backend provider/action, add a unit test under
`engine/crucible/framework/v2/console/tests/` asserting the provider returns a JSON-safe dict on a
fresh tree and that the action spawns the gated CLI (and refuses without a charter / on a bad target).

## Gotchas

- **Three ids must match exactly.** `id` in NAV, in `route()`, and in `screens.yaml` must be identical.
  The generator only sees ids inside `const NAV = […]` and `function route() {…}` — a typo, a duplicate,
  or an id it can't parse is surfaced as drift by the cardinality guard, not silently dropped.
- **Forgetting to regenerate/commit `system-map.json`** fails CI with "STALE — run generate.py --write".
- **Missing a synonym** fails CI (voice nav needs ≥1). Keep them lowercase and distinctive.
- **Right plane.** Offense data/actions → `OFF(…)` (console 8787 / gated api 8799). Owner/cockpit data
  → `SOV(…)` (sigil 8733). `owner: true` screens (`settings`, `apikeys`, `charter`, `safety`) live on
  the sovereign plane. `renderNav`'s `visible()` also hides `assess`/`live`/`findings`/`fixes` unless
  the plane toggle is `offense` — check your screen shows where you expect.
- **CSP is strict `'self'`.** No inline `onclick`, no `<script>`, no `eval`, no external fonts/CDN —
  build everything through `V.h` and pass handlers as `onClick`/`onKeydown` props.
- **Never import across the plane boundary.** Console code must not `import sigil`; the proxy must not
  import either engine. Reach the engine only by subprocess.
- **Re-run `sync.sh`.** Editing `packages/vigil-ui/*` alone changes nothing the servers serve until you
  vendor it — and the script asserts both copies are byte-identical.
- **Don't loosen the POST guard.** New POSTs inherit `_same_origin_as_console`; call them via
  `V.postJSON` so the `X-Requested-With` header is present. A `fetch` that omits it is refused 403.
- The console binds **loopback only** by design. To host it, front the `vigil up` proxy with a TLS
  reverse proxy and add the domain to `allowed_hosts`/`allowed_origins` — never change the bind.
