# vigil-ui — VIGIL COMMAND, the canonical web UI

The single, committed, **no-build, strict-CSP** single-page app that fronts the *whole* system.
`packages/vigil-ui/` is the one source of truth (`app.js`, `ui.js`, `manual.js`, `tokens.css` +
`components.css` → `style.css`, `index.html`, `manifest.json`); `sync.sh` vendors it **byte-identically**
into both plane servers' static dirs. It is a hash-router over **21 screens** that federates the two
isolated trust planes behind one browser origin — the keyless **offense** plane (CRUCIBLE console + gated
api) via `OFF()`, and the owner-key **sovereign** plane (SIGIL cockpit) via `SOV()` — building all DOM
with `VUI.h` (no framework, no inline handlers, no `eval`). The UI is a *driver*, not an authority: it
prefixes fetches and renders provenance; it never mints a FACT, never relaxes scope, and never binds a
port. For the full server-side picture (console `api.py`/`actions.py`/`server.py`, the `vigil up` proxy,
the two-plane model) see [`../../knowledge/kb/console-and-ui.md`](../../knowledge/kb/console-and-ui.md).

## Authoritative code paths

### `ui.js` — the `window.VUI` micro-kit (CSP-native, shared by both planes)

Exported on `window.VUI` at `ui.js:151–153`. This is the entire framework:

- `h(tag, props, children)` (`ui.js:10`) — hyperscript. `h('div.card#x', {onClick, dataset,…}, [kids])`.
  Handlers are passed as `onClick`/`onKeydown` **props** (wired via `addEventListener`), never inline
  attributes. `mount` (`:48`), `clear` (`:47`), `store()` observable (`:52`).
- **Federated fetch helpers** — read config once at boot from `window.VIGIL_CFG`:
  - `getJSON(url)` (`ui.js:70`) — GET, throws on non-2xx.
  - `postJSON(url, body)` (`ui.js:75`) — POST JSON, parses error envelopes.
  - `_headers()` (`ui.js:65`) sets **`X-Requested-With: vigil-ui`** and the `X-SIGIL-Token` header on
    every request. That custom header is the console's anti-CSRF requirement — a `fetch` that omits it is
    refused. Always go through `getJSON`/`postJSON`; never call `fetch` directly.
  - `sse(url, onEvent, onError)` (`ui.js:87`) — `EventSource` with query-param token auth (SSE can't set
    headers).
- Builders that return DOM nodes: `pill` (`:117`), `statusBadge` (`:121`), `tile` (`:125`), `card`
  (`:129`), `icon` (`:134`, a fixed inline-SVG glyph set — the only place `html:` innerHTML is used, and
  only for static markup), `toast` (`:97`), `router` (`:105`).

### `app.js` — the shell + all 21 screens

- **Config / plane prefixes** (`app.js:12–14`): `CFG = window.VIGIL_CFG`, then
  `SOV(p) = CFG.api.sovereign + p` and `OFF(p) = CFG.api.offense + p`. **Every** fetch prepends one of
  these — `OFF(...)` for offense (CRUCIBLE console/gated api), `SOV(...)` for the owner cockpit (SIGIL).
- **`const NAV`** (`app.js:19–47`) — the navigation model: three groups (`DO` / `MANAGE` / `LEARN`),
  each item `{ id, label, icon, ready, owner? }`. `owner: true` marks a sovereign-owner-plane screen
  (`safety`, `charter`, `apikeys`, `settings`). This array is one of the three sides of the system-map
  contract (below).
- **Shell**: `shell()` (`app.js:119–129`) builds `#topbar`, `#nav`, `#main > #screen`, and the detail
  drawer. `topbar()` (`:50`) has the plane segmented toggle (`all`/`offense`/`defense`), the live/
  kill-switch pill, counts, and the safety pill. `renderNav()` + its `visible()` filter (`:91–104`),
  `navItem()` (`:105–116`), `current()` (`:117`, derives the active screen id from `location.hash`).
- **`route()`** (`app.js:3989–4018`) — the hash router. `current()` → an `if (id === "…") {
  render…(screen); return; }` branch per screen (21 branches); an unready/unknown id falls to
  `renderStub` (`:3135`). It calls `teardownLive()` (`:853`) first so any SSE stream / interval from the
  previous screen is closed. Each `render*(screen)` fetches read-only JSON (or fires a gated action) and
  mounts DOM with `V.h`.
- **`boot()`** (`app.js:4020–4034`) — reads the server-injected `data-token` / `data-sovereign` /
  `data-offense` body attributes into `CFG`, restores the theme, mounts `shell()`, wires
  `hashchange → route`, defaults to `#/home`, then starts the persistent SIGIL HUD channel.
- **Provenance rendering**: `isFact(p) = !!(p && p.verified_by_oracle)` (`app.js:500`). The FACT badge is
  shown **only** when the oracle verified it; everything else renders as a `span.shield.lead` "LEAD"
  (e.g. `:1039–1041`, `:1458`, `:1627`). This is the pixel-level expression of oracle authority.
- **SIGIL HUD / voice-nav** (`startSigilHud()`, `app.js:3544–3572`): a persistent SSE from
  `SOV("/api/sigil/hud")` that fans `sigil.nav` signals to a hash navigation — but **only** to a known
  NAV screen id. `navIds` is an `Object.create(null)` map (`:3549`) so a payload of `constructor` /
  `__proto__` can never read truthy off the prototype chain; a spoofed id navigates to nothing.

### `index.html` — the CSP-native entry

```html
<body data-token="__VIGIL_TOKEN__" data-sovereign="__VIGIL_SOVEREIGN__" data-offense="__VIGIL_OFFENSE__">
```

The serving layer rewrites these placeholders per deployment: **standalone** (a single server serving its
own `/api`) → `""`; **behind `vigil up`'s reverse proxy** → `data-sovereign="/sovereign"`
`data-offense="/offense"`. Scripts load same-origin in order: `ui.js`, `manual.js`, `app.js`. No inline
script, no CDN — the only stylesheet is same-origin `style.css`.

### `manifest.json` + `sync.sh` — the no-build vendoring contract

`manifest.json` declares `static_allowlist` (`style.css`, `ui.js`, `manual.js`, `app.js`), the
`build` map (`style.css = tokens.css + components.css`), and the two `targets`
(`apps/sigil/sigil/ui/static`, `engine/crucible/framework/v2/console/static`). `sync.sh` is **author-time,
no tooling, no network**: it concatenates the CSS and copies the JS + index into both plane static dirs,
then `cmp`-asserts the two trees are **byte-identical** (`sync.sh:40–45`). Run it after editing any
`packages/vigil-ui/*` source — until you do, the servers serve the old bundle.

### `manual.js` — in-app documentation (not runtime data)

`window.VIGIL_MANUAL` (`manual.js:8`) is a static array of doc sections; `app.js`'s `renderManual`
(`app.js:211`) renders it for the `manual` screen. No target/runtime data lives here.

## The 21-screen NAV / route / system-map contract

Three lists must stay set-equal, and CI enforces it:

1. `const NAV` ids in `app.js` (`:19–47`).
2. `route()` `id === "…"` branch ids in `app.js` (`:3989–4018`).
3. `knowledge/system-map/screens.yaml` ids (the human SSOT SIGIL reads via the generated
   `knowledge/system-map/system-map.json`).

`tools/system-map/generate.py` (`_verify`, `generate.py:101`) asserts **manifest ids == NAV ids ==
route() ids**, a cardinality guard (a duplicate or unparseable id can't vanish — raw token count must
equal distinct-id count), and **≥1 synonym per screen** (voice nav). Extraction is *scoped* to the
`const NAV = [...]` block (`_nav_block`, `:42`) and the `function route()` body (`_route_block`, `:49`)
so unrelated ids (scan modes, wizard targets, providers) are never picked up. The 21 screens:

| Group | ids |
|-------|-----|
| DO | `home` `assess` `chat` `live` `findings` `proof` `report` `fixes` `defense` |
| MANAGE | `sessions` `activity` `safety` `charter` `apikeys` `tools` `brain` `compliance` `assurance` `settings` |
| LEARN | `manual` `knowledge` |

## Invariants this package must preserve (and why)

1. **Strict-CSP, no build, no CDN.** `default-src 'self'`: no inline `<script>`/handlers, no `eval`/`new
   Function`, no external fonts/images/CDN. Build every node with `V.h` and pass handlers as
   `onClick`/`onKeydown` props; the only innerHTML use is `V.icon`'s static SVG. *Why: the UI drives a
   pentest engine; a single injected script in this origin could forge actions. Strict `'self'` +
   no-build keeps the served bytes auditable and diffable.*
2. **Federation is a prefix, never a bridge.** `OFF()` and `SOV()` only prepend a same-origin base path;
   the browser reaches one listener and the `vigil up` proxy forwards `/offense/*` and `/sovereign/*` to
   separate loopback processes in separate venvs. The UI never co-mingles plane data in a way that
   implies one interpreter holds both. *Why: the two-env boundary / FATAL-2 — the keyless offense engine
   and the owner-key sovereign core must never share an interpreter. The UI must not paper over the split.*
3. **Render provenance honestly (oracle authority).** `isFact()` gates the FACT badge on
   `verified_by_oracle`; a LEAD is never styled as a FACT. The UI mints nothing — reads render, and the
   only mutations call gated backend actions. *Why: "the machine cannot lie about a finding" must hold at
   the pixel, not just in the engine.*
4. **The UI is an untrusted driver; the gate is the authority.** Every target-touching action posts to a
   backend endpoint that spawns the *same* gated CLI (kill-switch + signed-charter + owner approval + m-of-n
   if destructive); the UI cannot pass scope or skip a gate. `postJSON` carries `X-Requested-With` so the
   console's anti-CSRF / anti-DNS-rebind guard admits it. *Why: a malicious page the operator visits must
   not be able to drive the engine.*
5. **Byte-identical, deterministic vendoring.** `sync.sh` produces identical bytes in both plane trees and
   asserts it; the system-map generator is wallclock/rng-free (`source_sha` is the version). *Why: both
   planes serve the same auditable app, and SIGIL's map is reproducible and diffable.*

## How to add a screen safely

Copy the `renderTools` pattern (`app.js:435`). All six steps; CI enforces 5–6.

1. **NAV.** Add to `const NAV` (`app.js:19–47`): `{ id: "myscreen", label: "My Screen", icon: "bolt",
   ready: true }` (`owner: true` only if it needs the sovereign plane). Pick a lowercase id (no spaces).
2. **Render fn.** Write `function renderMyscreen(screen) { … }`: `V.mount(screen, [ h("div.screen-head",
   …), … ])`, then `V.getJSON(OFF("/api/myscreen")).then(fn).catch(offline)` — use `SOV(…)` if the data
   lives on the owner cockpit. Build DOM only with `V.h`/`V.icon`; handlers as props (strict CSP). For a
   mutation, `V.postJSON(OFF("/api/myaction"), body)` (it sets `X-Requested-With` for you).
3. **Route.** Add `if (id === "myscreen") { renderMyscreen(screen); return; }` to `route()`
   (`app.js:3989–4018`). The id string must be **identical** to the NAV id.
4. **Backend (if it needs data).** Add a read provider to `console/api.py` (register in `server.py`), or a
   safe action to `console/actions.py` that **spawns a gated CLI** (never in-process, never a scope arg)
   plus a `do_POST` branch — see [`../../knowledge/kb/console-and-ui.md`](../../knowledge/kb/console-and-ui.md).
5. **System map.** Add the screen to `knowledge/system-map/screens.yaml` (`id` == NAV == route, plus
   `label` `group` `owner` `plane: unified` `description`, and **≥1 `synonyms`**).
6. **Regenerate + vendor.** `python tools/system-map/generate.py --write` (commit the updated
   `system-map.json`), then run `packages/vigil-ui/sync.sh`.

**Verify / tests:** `python tools/system-map/generate.py --check` must report ids match NAV == route()
with a synonym each; `apps/sigil/tests/test_system_map_sync.py` is the CI gate (it proves the gate bites:
a phantom screen, a missing synonym, a camelCase/hyphen id, and a duplicate NAV id are all caught). If you
added a backend provider/action, add a console unit test asserting it returns a JSON-safe dict on a fresh
tree and that the action spawns the gated CLI (and refuses without a charter / on a bad target).

## Gotchas

- **Three ids must match exactly** — NAV, `route()`, and `screens.yaml`. A typo, duplicate, or
  unparseable id is surfaced as drift by the cardinality guard, not silently dropped.
- **Forgetting `generate.py --write`** fails CI with "system-map.json is STALE"; **missing a synonym**
  fails CI (voice nav needs ≥1, lowercase and distinctive).
- **Re-run `sync.sh`.** Editing `packages/vigil-ui/*` alone changes nothing the servers serve until you
  vendor it, and the script asserts both copies are byte-identical.
- **Right plane.** Offense data/actions → `OFF(…)`; owner/cockpit data → `SOV(…)`. `owner: true` screens
  (`safety`, `charter`, `apikeys`, `settings`) live on the sovereign plane. `renderNav`'s `visible()`
  (`app.js:94–99`) also hides `assess`/`live`/`findings`/`fixes` unless the plane toggle is `offense`,
  and `defense` unless it is `defense` — confirm your screen appears where you expect.
- **Never `fetch` directly.** Use `V.getJSON`/`V.postJSON` so `X-Requested-With` and the token are set; a
  bare `fetch` that omits the header is refused 403 by the console's POST guard.
- **CSP is strict `'self'`.** No inline `onclick`, no `<script>`, no `eval`, no external fonts/CDN. The
  only `html:` (innerHTML) call is `V.icon`'s static SVG — keep it that way.
- **Voice-nav is allowlist-only.** `startSigilHud` navigates only to a known NAV id via an
  `Object.create(null)` map; do not swap it for a plain object (prototype pollution) or accept arbitrary
  URLs from the HUD stream.
- **`app.js` is large and grep-hostile.** The system-map generator only reads ids inside `const NAV = […]`
  and `function route() {…}` — keep both blocks parseable (don't split the NAV array or rename `route()`)
  or the extractor breaks.
