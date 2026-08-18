# vigil-ui — VIGIL COMMAND, the canonical web UI

The single, committed, **no-build, strict-CSP** single-page app that fronts the *whole* system.
`packages/vigil-ui/` is the one source of truth (`app.js`, `ui.js`, `manual.js`, `legal.js`, `tokens.css` +
`components.css` → `style.css`, `index.html`, `manifest.json`); `sync.sh` vendors it **byte-identically**
into both plane servers' static dirs. It is a hash-router over **every screen declared in
[`knowledge/system-map/screens.yaml`](../../knowledge/system-map/screens.yaml)** — that file is the SSOT
and `python3 tools/system-map/generate.py --check` prints the current count — federating the two
isolated trust planes behind one browser origin — the keyless **offense** plane (CRUCIBLE console + gated
api) via `OFF()`, and the owner-key **sovereign** plane (SIGIL cockpit) via `SOV()` — building all DOM
with `VUI.h` (no framework, no inline handlers, no `eval`). The UI is a *driver*, not an authority: it
prefixes fetches and renders provenance; it never mints a FACT, never relaxes scope, and never binds a
port. For the full server-side picture (console `api.py`/`actions.py`/`server.py`, the `vigil up` proxy,
the two-plane model) see [`../../knowledge/kb/console-and-ui.md`](../../knowledge/kb/console-and-ui.md).

## Authoritative code paths

### `ui.js` — the `window.VUI` micro-kit (CSP-native, shared by both planes)

Exported on `window.VUI` at `ui.js:284–288`. This is the entire framework:

- `h(tag, props, children)` (`ui.js:10`) — hyperscript. `h('div.card#x', {onClick, dataset,…}, [kids])`.
  Handlers are passed as `onClick`/`onKeydown` **props** (wired via `addEventListener`), never inline
  attributes. `mount` (`:48`), `clear` (`:47`), `store()` observable (`:52`).
- **Federated fetch helpers** — read config once at boot from `window.VIGIL_CFG`:
  - `getJSON(url)` (`ui.js:90`) — GET, throws on non-2xx.
  - `postJSON(url, body)` (`ui.js:95`) — POST JSON, parses error envelopes.
  - `_headers()` (`ui.js:85–87`) sets **`X-Requested-With: vigil-ui`** and the `X-SIGIL-Token` header on
    every request. That custom header is the console's anti-CSRF requirement — a `fetch` that omits it is
    refused. Always go through `getJSON`/`postJSON`; never call `fetch` directly.
  - `sse(url, onEvent, onError)` (`ui.js:218`) — `EventSource` with query-param token auth (SSE can't set
    headers).
- Builders that return DOM nodes: `pill` (`:246`), `statusBadge` (`:250`), `tile` (`:254`), `card`
  (`:258`), `icon` (`:263`, a fixed inline-SVG glyph set — the only place `html:` innerHTML is used, and
  only for static markup), `toast` (`:226`), `router` (`:234`).

### `app.js` — the shell + every screen

- **Config / plane prefixes** (`app.js:12–14`): `CFG = window.VIGIL_CFG`, then
  `SOV(p) = CFG.api.sovereign + p` and `OFF(p) = CFG.api.offense + p`. **Every** fetch prepends one of
  these — `OFF(...)` for offense (CRUCIBLE console/gated api), `SOV(...)` for the owner cockpit (SIGIL).
- **`const NAV`** (`app.js:107–146`) — the navigation model: three groups (`DO` / `MANAGE` / `LEARN`),
  each item `{ id, label, icon, ready, owner?, perm? }`. `owner: true` marks a sovereign-owner-plane screen
  (`safety`, `charter`, `apikeys`, `settings`, `users`). This array is one of the three sides of the system-map
  contract (below).
- **Shell**: `shell()` (`app.js:681–691`) builds `#topbar`, `#nav`, `#main > #screen`, and the detail
  drawer. `topbar()` (`:149`) has the plane segmented toggle (`all`/`offense`/`defense`), the live/
  kill-switch pill, counts, and the safety pill. `renderNav()` + its `visible()` filter (`:644–666`),
  `navItem()` (`:667–678`), `current()` (`:679`, derives the active screen id from `location.hash`).
- **`route()`** (`app.js:8854–8894`) — the hash router. `current()` → an `if (id === "…") {
  render…(screen); return; }` branch per screen (one branch per `screens.yaml` id); an unready/unknown id falls to
  `renderStub` (`:7166`). It calls `teardownLive()` (`:2557`) first so any SSE stream / interval from the
  previous screen is closed. Each `render*(screen)` fetches read-only JSON (or fires a gated action) and
  mounts DOM with `V.h`.
- **`boot()`** (`app.js:8896–8928`) — reads the server-injected `data-token` / `data-sovereign` /
  `data-offense` body attributes into `CFG`, restores the theme, mounts `shell()`, wires
  `hashchange → route`, defaults to `#/home`, then starts the persistent SIGIL HUD channel.
- **Provenance rendering**: `isFact(p) = !!(p && p.verified_by_oracle)` (`app.js:1923`). The FACT badge is
  shown **only** when the oracle verified it; everything else renders as a `span.shield.lead` "LEAD"
  (e.g. `:2842`, `:3469`, `:3711`). This is the pixel-level expression of oracle authority.
- **SIGIL HUD / voice-nav** (`startSigilHud()`, `app.js:7960–7988`): a persistent SSE from
  `SOV("/api/sigil/hud")` that fans `sigil.nav` signals to a hash navigation — but **only** to a known
  NAV screen id. `navIds` is an `Object.create(null)` map (`:7965`) so a payload of `constructor` /
  `__proto__` can never read truthy off the prototype chain; a spoofed id navigates to nothing.

### `index.html` — the CSP-native entry

```html
<body data-token="__VIGIL_TOKEN__" data-sovereign="__VIGIL_SOVEREIGN__" data-offense="__VIGIL_OFFENSE__">
```

The serving layer rewrites these placeholders per deployment: **standalone** (a single server serving its
own `/api`) → `""`; **behind `vigil up`'s reverse proxy** → `data-sovereign="/sovereign"`
`data-offense="/offense"`. Scripts load same-origin in order: `ui.js`, `manual.js`, `legal.js`, `app.js`. No inline
script, no CDN — the only stylesheet is same-origin `style.css`.

### `manifest.json` + `sync.sh` — the no-build vendoring contract

`manifest.json` records `static_allowlist` (`style.css`, `ui.js`, `manual.js`, `legal.js`, `app.js`), the
`build` map (`style.css = tokens.css + components.css`), and the two `targets`
(`apps/sigil/sigil/ui/static`, `engine/crucible/framework/v2/console/static`). `sync.sh` is **author-time,
no tooling, no network**: it concatenates the CSS and copies the JS + index into both plane static dirs,
then `cmp`-asserts the two trees are **byte-identical** (`sync.sh:40–45`). Run it after editing any
`packages/vigil-ui/*` source — a plane server run **standalone** serves from its own static dir, so
until you sync it serves the old bundle. `vigil up` does not depend on the sync: its proxy assembles
the serve dir straight from `packages/vigil-ui` on every start (`assemble_serve_dir`,
`uiproxy.py:446–490`, source path resolved at `:1899`/`:2030`), so it always serves the sources.

**`static_allowlist` is a hand-maintained inventory, not a source of truth.** No code reads that field.
The sets actually in force are `sync.sh`'s `COPY` array (`sync.sh:17`) and `uiproxy.BUNDLE_JS`
(`integration/vigil_integration/uiproxy.py:219`), which together with `assemble_serve_dir`
(`uiproxy.py:446–490`) decide what is copied and served. Adding or removing a bundle file means editing
all three by hand and keeping them in step; nothing derives one from another.

### `manual.js` — in-app documentation (not runtime data)

`window.VIGIL_MANUAL` (`manual.js:8`) is a static array of doc sections; `app.js`'s `renderManual`
(`app.js:914`) renders it for the `manual` screen. No target/runtime data lives here.

### `legal.js` — the in-product legal pages (not runtime data)

`window.VIGIL_LEGAL` is a static `{ preamble, sections[] }` object — Acceptable Use, Privacy, Licenses &
Attribution, Security & Disclosure — rendered by `app.js`'s `renderLegal` / `legalBlock` for the `legal`
screen (`renderLegal`, `app.js:957–988`; `legalBlock`, `:993–1023`), wired exactly like `manual.js` (same `<script>` slot, same `manifest.json` inventory entry, same
`sync.sh` `COPY` list, same `uiproxy.BUNDLE_JS` tuple). It **fetches nothing**: the pages must render with no
network and no backend, because "what leaves this machine" is one of the questions they answer. Its
block vocabulary is the Manual's (`h` / `p` / `note` / `list`) plus `rule` (an `.owner-banner` — the gold
"this one is on YOU" treatment), `code`, `table` (`table.tbl`), and `docs` (the governing repository
files). Every class it uses already exists in `components.css`, so both themes are inherited.

**Truth constraint:** these pages *summarise*; the repository documents (`ACCEPTABLE-USE.md`,
`PRIVACY.md`, `TERMS.md`, `EXPORT.md`, `SECURITY.md`, `LICENSE`, `NOTICE`) *govern*. Every behavioural
statement in `legal.js` must be true of the code on this branch and name the file it comes from — in
particular the **PERMISSIVE model-egress default** and the fact that the spine hard-prune's destructive
cutover is **not shipped**. If you change one of those behaviours, change this file in the same commit.

## The NAV / route / system-map contract

Three lists must stay set-equal, and CI enforces it:

1. `const NAV` ids in `app.js` (`:107–146`).
2. `route()` `id === "…"` branch ids in `app.js` (`:8854–8894`).
3. `knowledge/system-map/screens.yaml` ids (the human SSOT SIGIL reads via the generated
   `knowledge/system-map/system-map.json`).

`tools/system-map/generate.py` (`_verify`, `generate.py:101`) asserts **manifest ids == NAV ids ==
route() ids**, a cardinality guard (a duplicate or unparseable id can't vanish — raw token count must
equal distinct-id count), and **≥1 synonym per screen** (voice nav). Extraction is *scoped* to the
`const NAV = [...]` block (`_nav_block`, `:42`) and the `function route()` body (`_route_block`, `:49`)
so unrelated ids (scan modes, wizard targets, providers) are never picked up.

**The screen list is deliberately not restated here.** It lives in
[`knowledge/system-map/screens.yaml`](../../knowledge/system-map/screens.yaml) (id, label, group,
owner, plane, description, synonyms), and CI fails the moment that file, `NAV` and `route()` disagree.
To read the current set and its count:

```sh
python3 tools/system-map/generate.py --check     # prints e.g. "system map OK — N screens, ids match NAV == route()"
grep -n 'id:' knowledge/system-map/screens.yaml  # the ids themselves, in group order
```

A hard-coded count in this file would be a fourth copy with nothing enforcing it, which is how the
previous one drifted.

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
