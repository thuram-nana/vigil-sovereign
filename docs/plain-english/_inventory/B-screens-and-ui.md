# B — Screens and UI: technical inventory

**Purpose:** an accurate, complete, source-grounded inventory of every user-facing screen and control in
VIGIL, plus every command-line verb. This is raw material for writers — not lay prose.

**Method:** every statement below was read out of the repository at `/home/kali/vigil` (branch `main`,
HEAD `1487e03a` — "Merge PR #293 … E4 TIER-2 K8s dangerous-VERB / default-SA RBAC verb-grant oracle").
File + line references are given so any claim can be re-checked. Where the repo's own docs disagree with
the code, the code is reported and the disagreement is flagged. Re-verified against the working tree on
2026-08-12; the screen inventory, the route tables, the CLI verb lists and every count in §12 were
re-read from source at this HEAD.

**Verification status legend used throughout:**
- **WIRED** — the control exists in UI code *and* reaches a backend route that exists.
- **READ-ONLY** — renders data, mutates nothing.
- **STUB** — the control exists in the UI but does nothing meaningful.
- **NOT VERIFIED** — mentioned in code/docs but not confirmed by me end-to-end at runtime.

---

## 0. How many user interfaces exist, and how each is served

There are **three distinct web UIs** in this repo plus **one vendored third-party terminal UI**. This
matters: a reader who assumes "the UI" is one thing will be wrong.

| # | UI | Source of truth | Served by | Default listener | Status |
|---|----|-----------------|-----------|------------------|--------|
| 1 | **VIGIL COMMAND** — the unified 28-screen single-page app | `packages/vigil-ui/` (`app.js` 5,703 lines / 349 KB, `ui.js`, `manual.js`, `tokens.css` + `components.css`, `index.html`) | the `vigil up` reverse proxy, from a runtime serve dir assembled at start-up (`integration/vigil_integration/uiproxy.py:153` `assemble_serve_dir`, called at `:965`; source dir resolved at `:797` = `<repo>/packages/vigil-ui`) | `127.0.0.1:8770` (`uiproxy.py:57` `DEFAULT_PROXY_PORT`) | **This is the primary product UI.** |
| 2 | **CRUCIBLE Ops Console** (legacy) — 22 screens | `engine/crucible/framework/v2/console/static/{index.html,app.js,graph.js,styles.css}` | the offense console server itself at `/` (`console/server.py:136` `_static`) | `127.0.0.1:8787` | Older SPA, still committed and still served when you hit the console directly. |
| 3 | **SIGIL cockpit** (legacy) — one page, 5 panels | `apps/sigil/sigil/ui/static/{index.html,app.js,style.css}` | the sovereign cockpit server at `/` (`apps/sigil/sigil/ui/server.py`) | `127.0.0.1:8733` | Older minimal page. |
| 4 | **Strix TUI** — terminal UI (vendored third party) | `vendor/strix/strix/interface/tui/` (Textual app: `app.py` `StrixTUIApp`, modal screens `SplashScreen`, `HelpScreen`, `StopAgentScreen`, `VulnerabilityDetailScreen`, `QuitScreen`; 15 renderers under `tui/renderers/`) | `strix` console-script (`vendor/strix/pyproject.toml:53-54`) | terminal | Third-party (Apache-licensed vendor tree), reachable via `vigil strix …`. |

### 0.1 IMPORTANT — the vendoring contract is currently NOT satisfied in the tree

`packages/vigil-ui/manifest.json` and `sync.sh` declare that the unified bundle is vendored
byte-identically into both plane static dirs (`apps/sigil/sigil/ui/static`,
`engine/crucible/framework/v2/console/static`). **In the current tree that has not happened.** Verified:

- `packages/vigil-ui/app.js` = 349,245 bytes (mtime 2026-08-12); `console/static/app.js` = 67,409 bytes,
  `apps/sigil/sigil/ui/static/app.js` = 5,119 bytes (both mtime 2026-08-03). They differ.
- `ui.js` and `manual.js` are absent from both static dirs; `console/static` still carries its own
  `graph.js` + `styles.css` (not in the sync manifest).
- Git history explains it: commit `4fe9cbc6` "UI vendoring reconciliation: serve the unified bundle from
  both planes + a CI drift gate (#220)" was **reverted** by `a12961fe` "Revert … it broke the SIGIL
  sovereign plane (CI red) (#221)".

**Consequence to state honestly:** the 28-screen VIGIL COMMAND app is reachable **only through
`vigil up`** (which builds its serve dir straight from `packages/vigil-ui/`). Hitting the console
(`:8787`) or the cockpit (`:8733`) directly gets you the *legacy* UI, not VIGIL COMMAND. The console
server's own comment acknowledges this (`console/server.py:155-159`: "this dir still serves the LEGACY
console SPA … The strict CSP belongs to the CSP-clean unified bundle (packages/vigil-ui) — served by the
`vigil up` reverse proxy").

### 0.2 The `vigil up` topology (one browser origin, three loopback backends)

From `integration/vigil_integration/uiproxy.py` (module docstring + `:56-70`, `:846-905`):

```
browser ─▶ vigil up proxy   (the ONLY listener a human points a browser at, default 127.0.0.1:8770)
             ├─ /sovereign/*        ▶ 127.0.0.1:8733   sigil serve      (sovereign cockpit, owner key)
             ├─ /offense/api/v1/*   ▶ 127.0.0.1:8799   crucible api     (gated action plane)
             └─ /offense/*          ▶ 127.0.0.1:8787   crucible console (read + SSE plane)
     /  and the bundle files (style.css, ui.js, manual.js, app.js, index.html) are served by the proxy
        itself from the runtime serve dir.
```

- The proxy refuses a public bind: `bind_ok()` (`uiproxy.py:101`) allows loopback, RFC1918, Tailscale
  CGNAT `100.64.0.0/10`, IPv6 ULA `fc00::/7`, IPv6 link-local `fe80::/10` — and explicitly refuses
  `0.0.0.0`/`::` and globally routable addresses (IPv6 uses a positive allowlist because Python
  mislabels Teredo `2001::/32` and 6to4 `2002::/16` as private).
- `--domain` is an **allowlist string**, not a bind; with `--domain` set and `CRUCIBLE_API_KEY` unset the
  command **refuses to start** unless `--insecure-no-api-key` is passed (`uiproxy.py:787-795`).
- Port preflight: all four ports must be free or `vigil up` refuses cleanly rather than orphaning
  backends (`uiproxy.py:817-828`).
- Processes `vigil up` spawns (tracked in a pids file for `vigil down`): `sovereign-cockpit`,
  `offense-console`, `offense-api`, `sovereign-learn-grants`, and conditionally `offense-learn-drain`,
  `offense-feed` (`--with-feed`), `offense-telemetry` (`--with-telemetry`), `sovereign-voice`
  (`--with-voice`).
- Access URL printed at the end includes a session token: `{origin}/?token={token}` — the token is
  captured from the cockpit's own stdout (`_TOKEN_RE`, `uiproxy.py:96`).

### 0.3 UI security posture (relevant because it constrains what screens can do)

- **Strict CSP** on the bundle the proxy serves: `default-src 'self'; base-uri 'self'; form-action
  'self'; frame-ancestors 'none'; object-src 'none'; img-src 'self' data:` (`_BUNDLE_CSP`,
  `uiproxy.py:79-81`). No inline script, no CDN, no `eval`. All DOM is built with `VUI.h`; the only
  `innerHTML` use is `V.icon()`'s static SVG.
- **Anti-CSRF / anti-DNS-rebinding**: every UI fetch sets `X-Requested-With: vigil-ui` and, when a token
  is configured, an `X-SIGIL-Token` header (`_headers`, `packages/vigil-ui/ui.js:64-68`). The console
  refuses a POST without the custom header (`console/server.py:23` `_CSRF_HEADER`, checked in
  `_same_origin_as_console` at `:371-384`), and refuses a *read* whose `Host` does not name the loopback
  console or an allowlisted proxy domain (`_host_is_console`, `:322`; called on every GET at `:230`).
- **The UI is a driver, not an authority.** It never mints a finding, never passes a scope argument to a
  spawn, and every mutating control posts to a backend that re-spawns the *same* gated CLI. FACT vs LEAD
  is rendered from `verified_by_oracle` only (`app.js:isFact`).
- Console `serve()` refuses a non-loopback bind — `raise ValueError` unless the host is
  `127.0.0.1`/`localhost`/`::1` (`console/server.py:602-615`). The console's own JSON/SSE CSP is
  stricter still: `default-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`
  (`_CSP`, `:30`) — but it is deliberately **not** sent on the static HTML responses, because that dir
  still serves the legacy inline-handler SPA (`_static`, `:137-163`, comment at `:155-159`).

---

## 1. VIGIL COMMAND — global chrome (present on every screen)

Source: `packages/vigil-ui/app.js`.

| Element | Where | What the user sees / can do | Status |
|---|---|---|---|
| Brand block | `app.js:119-129` (`shell`) | "V · VIGIL COMMAND" | READ-ONLY |
| **Plane toggle** (segmented) | `app.js:57-60` (`topbar`) | Three buttons: `All` / `Offense` / `Defense`. Filters the sidebar: `defense` shows only on the defense plane; `assess`, `live`, `findings`, `fixes` show only on offense; everything else always shows (`renderNav`'s `visible()`, `app.js:98-104`). | WIRED (client-side filter only) |
| **Command palette button** ("Search or run a command", ⌘K) | `app.js:61-62`, handler `openPalette` `app.js:146` | Clicking it shows a toast: *"Command palette is on the roadmap — for now use the sidebar. Start a run from New Assessment."* | **STUB — does nothing else.** |
| Live counts | `app.js:66-70` | agents / tools / findings counts, fed from `OFF /api/status` and the Tools screen | READ-ONLY |
| Live / Idle / Kill-switch pill | `app.js:64-65` | `Live`, `Idle`, or `Kill-switch` | READ-ONLY |
| **Failing-API-key badge** | `app.js:79-90` (`refreshKeysBadge`) | Hidden until `SOV /api/settings` reports `keys_failing > 0`; then shows "N API keys failing" and links to `#/apikeys`. Fetched at boot and after each key/provider mutation — **not a recurring poll**. | WIRED |
| **Safety button** | `app.js:71-77` | Three states: `KILL-SWITCH TRIPPED` / `N waiting for you` / `Safe · 0 waiting`. Click → `#/safety`. | WIRED |
| Theme toggle | `app.js:78`, `toggleTheme` `app.js:140-145` | light/dark, persisted in `localStorage` key `vigil-theme` | WIRED |
| Primary CTA | `app.js:80` | "New Assessment" → `#/assess` | WIRED |
| **Detail drawer** | `app.js:126-128`, `openDrawer`/`closeDrawer` `app.js:132+` | Right-hand slide-over used by Findings, Live, Defense, and the AEGIS production-command panel | WIRED |
| Toast | `ui.js:97` | transient message strip | WIRED |
| **SIGIL HUD overlay** | `app.js:5119-5155` (`updateSigilHud`) | A corner card showing SIGIL's state (`listening` / `thinking` / `speaking` / `idle`) plus the live transcript or feedback line. Buttons: **Minimize** (–) and **Dismiss** (×); a new non-idle interaction re-shows a dismissed HUD. Fed by SSE `SOV /api/sigil/hud`. | WIRED (data source is off by default — see §7) |
| **Voice / gesture navigation** | `startSigilHud` `app.js:5096-5117` | A `sigil.nav` event navigates to a screen. Two forms: an absolute `screen_id`, or `direction: next|prev` which steps the NAV list (wraps). **Allowlist-only** — `navIds` is an `Object.create(null)` map, so a spoofed `constructor`/`__proto__` payload navigates nowhere. | WIRED; producer is opt-in |
| Router | `route()` `app.js:5650-5686` | Hash router `#/<id>`; calls `teardownLive()` first to close any SSE stream / interval from the previous screen; 28 explicit `if (id === …)` branches. | WIRED |
| Boot | `boot()` `app.js:5688-5701` | Reads server-injected `<body data-token / data-sovereign / data-offense>`, restores theme, mounts shell, wires `hashchange`, defaults to `#/home`, starts the key badge + SIGIL HUD. | WIRED |

### 1.1 The screen-count contract

Three lists are held set-equal and gated in CI:

1. `const NAV` in `packages/vigil-ui/app.js:19-53`
2. the `route()` branch ids in `app.js:5650-5686`
3. `knowledge/system-map/screens.yaml`

**Verified count: 28 in all three.** (`grep -c "^  - id:" knowledge/system-map/screens.yaml` → 28; the
`route()` body has 28 `if (id === …)` branches; NAV has 11 DO + 13 MANAGE + 4 LEARN = 28.)

The gate is `tools/system-map/generate.py` (`_verify`, `:101`): it asserts manifest ids == NAV ids ==
`route()` ids, applies a cardinality guard so a duplicate/unparseable id cannot vanish, and requires ≥1
voice synonym per screen. CI test: `apps/sigil/tests/test_system_map_sync.py`.

**Doc inconsistency to flag:** `docs/FEATURES.md:189` correctly says **28 screens**, but
`docs/FEATURES.md:284-285` still says "The **22** `screens.yaml` ids…" and `packages/vigil-ui/README.md`
still says "**21 screens**". The code is 28. FEATURES.md line 189's own group listing also puts `replay`
under MANAGE while `app.js` puts it under DO.

---

## 2. VIGIL COMMAND — the 28 screens, one by one

Ordered as the sidebar orders them. `OFF(...)` = offense plane, `SOV(...)` = sovereign (owner) plane.

### Group DO (11 screens)

---

#### 1. `home` — **"Command"**
*Sub-title: "One place to run, watch, and govern every VIGIL assessment."* — `app.js:155-206`

**Sees:** four tiles — **Active runs**, **Waiting for you**, **Confirmed findings**, **Budget today**;
a **Quick start** card with three buttons; a **Recent activity** feed.

**Data:** `SOV /api/snapshot` + `OFF /api/status`, both fail-soft (one plane down never blanks the page).
Recent-activity rows come from `snapshot.recent_decisions` (max 8).

**Actions:**
- Quick-start "Scan a codebase" → `#/assess`
- Quick-start "Scan a website" → `#/assess`
- Quick-start "Defend an app (AEGIS)" → `#/defense`
- Empty-state → "Run your first assessment…"

**Status:** READ-ONLY (navigation only).

---

#### 2. `assess` — **"New Assessment"**
*Sub-title: "Set up a run in five short steps. Everything stays on your machine."* — `app.js:1162-1499`

A 5-step wizard with a clickable step rail (**Target · Where · Scope · How · Model**), a live
**"What will happen" (SUMMARY)** side card, and a footer with Back / Next / **Launch assessment**.

**Step 1 — "What do you want to assess?"** Six target types (`TARGET_TYPES`, `app.js:1145-1152`):

| mode | label | description shown |
|---|---|---|
| `codebase` | Scan a codebase | local path or repo; Strix reads and reasons over the source |
| `url` | Scan a website / API | full gate; a `127.0.0.1` target runs a quick loopback scan |
| `tool` | Run one tool | a single gated capability pack |
| `suite` | Full autonomous suite | the autonomous OODA loop drives the whole arsenal |
| `cloud` | Cloud / K8s posture | seedless posture review; **needs a signed charter** |
| `aegis` | Defend an app (AEGIS) | defensive dual over telemetry/logs |

**Step 2 — "Where is it?"** Fields adapt to the mode:
- `codebase`: **Codebase path** (local path or git URL) + checkbox **"Bind-mount instead of copy (large monorepos)"**
- `aegis`: **Telemetry / log file** path
- `cloud`: **Assessment type** select (`Cloud account` / `Kubernetes` / `Declared service`,
  `CLOUD_MODES` `app.js:1154-1158`), **Cloud provider** select (`aws`/`gcp`/`azure`, `app.js:1159`),
  **Cloud target label**, **Engagement slug**
- `url`/`tool`/`suite`: **Target URL** + **Engagement slug** (auto-slugified from host)
- All non-AEGIS modes: a required checkbox **"I am authorized to test this target (I own it or have
  written permission)."** — recorded with the run
- All modes: optional **Objective** textarea ("Guides the reasoning; never widens scope.")

**Step 3 — "Scope".** For engage modes on a non-loopback target: a chip list of authorized hosts, a text
input + **Add** button. **CIDR is rejected client-side** ("No CIDR — use a literal host or a
`*.wildcard`."). A loopback target shows scope fixed to `127.0.0.1`. Codebase/cloud/AEGIS show an
explanatory legend instead ("no network scope to set"). Legend states scope is *signed into the
charter/authority* and the console never passes it.

**Step 4 — "How should it run?"** Depth choice from the live capability catalog (`OFF /api/capabilities`
`scan_modes`; fallback Quick/Standard/Deep); checkbox **"Let the AI choose the tools (recommended)"**;
when off (or in single-tool mode) a pill picker over the real capability catalog with tier labels;
checkbox **"Apply fixes after discovery"** (hint: fixes are PROPOSED and queue for approval).

**Step 5 — "Model & keys."** Shows live LLM backend status from `OFF /api/kernel`; checkbox **"Run
keyless"**; **Session** select (from `OFF /api/sessions`); and, for a loopback target with a session
chosen, checkbox **"Graph-backed run"** (routes through `vigil engage --session` so facts partition that
session's Neo4j graph; falls back to the normal engine if `vigil`/Neo4j is unavailable).

**Launch:**
- `cloud` mode → `POST OFF /api/launch/cloud` `{slug, mode, target, provider}`
- everything else → `POST OFF /api/launch/assessment` `{mode, target, slug, scope, objective, scan_mode,
  tools, apply_fixes, keyless, model, mount, aegis_action, session_id, graph_backed}`
- On success: toast + redirect to `#/live?run=<run_id>`.

**Status:** WIRED, actionable. Backends: `console/actions.py:471` `launch_assessment`, `:156`
`launch_cloud`.

---

#### 3. `chat` — **"Chat"**
*Sub-title: "Ask in plain language what to test — the agent launches gated, oracle-confirmed runs and saves the conversation on your machine."* — `app.js:4453-4583`

**Sees:** left rail of saved chat sessions (each with a turn count) + **New chat** button; a bubble
transcript; owner-plane **model** and **effort** selects with **Use model** / **Apply effort** buttons;
a composer (textarea, Enter to send, Shift+Enter newline), an optional **target** field, and a **mode**
select (`auto` / `url / API / infra` / `codebase` / `suite (autonomous)` / `single tool`).

**Actions:**
- `POST OFF /api/chat/send` `{chat_id?, message, target, mode}`; reloads the transcript from
  `GET OFF /api/chat/session/<id>`
- A message of kind `launched` renders a **Watch live** button → `#/live?run=<run_id>` plus the slug pill
- Model/effort changes post `SOV /api/action` `set_model` / `set_effort`

**Honesty note rendered in-screen:** "Every run is gated: scope is charter-signed and target-touching
steps wait for your approval. The conversation is saved locally under `.vigil-live/chats/`."

**Status:** WIRED, actionable. Model/effort controls degrade to a hint if the sovereign plane is down.

---

#### 4. `terminal` — **"Terminal"**
*Sub-title: "Ask in plain English or type a command. The AI proposes; you approve; only local read-only commands run."* — `app.js:3791-4014`

**Sees:** three sections.
1. **AI CHAT dock** ("Ask in plain English") — collapsible with **Minimize** / **Maximize** buttons
   (state persisted in `localStorage` key `vigil-term-dock`; Escape restores). Input + **Ask** button.
2. **"Or type a command" (DIRECT)** — a command input with a **live dry-run verdict badge** that
   debounces 300 ms and posts to `OFF /api/terminal/dryrun`, plus a **Run** button.
3. **Output (SIGNED)** `<pre>` and **Recent commands (HISTORY)**.

**The AI router has three modes** (`termRenderProposal`, `app.js:3891`):
- `command` → shows the proposed command, a verdict badge (**ALLOWED** / **QUEUES FOR YOU** /
  **REFUSED**), and **Run** / **Edit** / **Cancel** buttons
- `answer` → a read-only answer bubble labelled **"READ-ONLY · NOTHING RAN"**, with a `Cites:` line
- `route` → **"USE THE ENGAGEMENT PATH"** + a button to the right screen; nothing runs

**Backends:** `POST OFF /api/terminal/propose` `{intent, run_id, session_id}` · `POST /api/terminal/dryrun`
· `POST /api/terminal/run` · `GET /api/terminal/history`.

**Constraints stated in-screen and enforced server-side:** allowlisted local read/inspect binaries only
(`ls`, `cat`, `grep`, `find`, `stat`, …), no network, no writers, no interpreters, no shell; every run is
a signed record. "Even if the AI is wrong or prompt-injected, the allowlist refuses it and nothing runs
without your approval." Without a Claude key the propose path returns `need_key` and the direct terminal
still works.

**Output shows:** `$ command`, `outcome`, `tier`, `ran: yes/no`, `reason`, `exit`, `signed record: <id>`,
then stdout/stderr.

**Status:** WIRED, actionable (allowlist-gated).

---

#### 5. `live` — **"Live"**
*Sub-title: "Every action, as it happens — with proof-grade FACT vs LEAD clarity."* — `app.js:1501-1797`

**Sees:** a **Run** select; a header card with a status pill, target, mode pill, elapsed ticker and a
**Stop run** button; four tiles (**Actions** / **Facts** / **Leads** / **Refusals**); an oracle-authority
legend; an approvals card; and a two-column body — **Reasoning graph (LIVE)** (a CSP-native SVG built
with `createElementNS`, 7 lanes: Observe · Orient · Plan · Act · Result · Finding · Review, capped at 22
nodes per lane, parent→child bezier edges) and a **TIMELINE** feed with a filter segment
**All / Facts / Leads / Inbox**.

**Streams (three shapes, chosen by `run.stream`):**
- `blackboard` → SSE `OFF /api/blackboard?slug=…`, the 14-kind reasoning spine, with an `id:` cursor so
  an EventSource reconnect resumes from `Last-Event-ID` and replays are de-duplicated
- `progress` → SSE `OFF /api/events?run=…`, a loopback scan's progress log, normalised into
  timeline-shaped events
- `none` (Strix/AEGIS) → no live spine; polls `OFF /api/runs` every 3 s and says so honestly

Approvals are polled separately from `SOV /api/snapshot` every 4 s.

**The 15 event kinds rendered** (`KIND_META`, `app.js:1112-1141`): Observed · Hypothesis · Plan ·
Decision · Action · Tool call · Result · Tool result · Finding · Critique · Critic · Reflection · Reward ·
Refusal · Message (`agent_message`, explicitly ADVISORY, rendered in the `review` lane, never as a
finding).

**Actions:**
- **Stop run** → `POST OFF /api/killswitch/<slug>/trip` `{reason:"stopped from Live view"}`
- **Approve** / **Deny** per pending approval → `POST SOV /api/action` `{action, seq, reason}`
- Click any timeline row → detail drawer with kind, agent, timestamp, event id, parent id, verdict,
  oracle, confidence, and the raw JSON payload. A LEAD gets an explicit note: "A LEAD is a proposal. It
  becomes a FACT only when a deterministic oracle re-executes and confirms it."
- **Inbox tab** → `GET OFF /api/inbox/<slug>`, refreshed every 8 s while open. Banner: "Advisory
  coordination only. These are agent-to-agent messages — NOT evidence. No fact-building path reads them."

**Status:** WIRED, actionable (stop + approve/deny).

---

#### 6. `findings` — **"Findings"**
*Sub-title: "Proven bugs, the attack graph, re-checkable evidence, coverage and replay — all oracle-gated."* — `app.js:2152-2217`

A Run select plus **five sub-tabs** (`P3_TABS`, `app.js:2103-2109`). Tab state is reflected in the hash
(`#/findings?run=…&tab=…`).

**6a. Findings** (`p3Findings`, `app.js:2240`) — four tiles (**Confirmed** / **Leads** / **Endpoints** /
**Requests**), a filter segment **All / Facts / Leads**, an oracle legend, and a table with columns
*Severity · Bug class · Surface · Oracle · Status*. A row opens a **detail drawer** containing: verdict
(CONFIRMED / CONTRADICTED / UNGROUNDED / LEAD), severity, bug class, surface, oracle kind, confidence,
CVSS vector + base, derived-from-hypothesis, "re-runnable certificate yes/no", IMPACT, **ORACLE
RATIONALE**, **HOW TO VERIFY & TEST** (server-supplied `how_to_verify` if present, else derived — and it
never implies a lead is proven), **REMEDIATION**, **REFERENCES**, and a **RE-VERIFY** section with a
**"Re-verify this run (offline)"** button → `POST OFF /api/reverify/<run_id>`, rendering `N / M
reproduced` and a per-certificate list. Data: `GET OFF /api/report/<run_id>`.

**6b. Attack Graph** (`p3Graph`) — a deterministic force-directed SVG over the world model
(`GET OFF /api/worldmodel/<run_id>`). Node kinds colour-coded: endpoint, finding, host, datastore,
credential, principal, cloud_resource, service, webapp, session, control, network_segment, attacker.

**6c. Evidence** (`p3Evidence`, `app.js:2601`) — four tiles (**Certificates** / **Sound** / **Not sound** /
**Traffic sent = 0, "pure re-run"**), then one card per certificate with a four-state badge:
**Sound ✔** / **Tampered ✖** / **Claim mismatch ⚠** / **No certificate —**, each with an explicit "why"
sentence. Per-card **Offline re-verify** button re-fetches `GET OFF /api/evidence/<run_id>` and
re-resolves the state. Fields: Finding, Surface, OracleKind, Confidence, **Cert id (content hash)**.

**6d. Coverage** (`p3Coverage`, `app.js:2661`) — tiles (**Pages crawled** / **Requests audited** /
**Endpoints** / **Confirmed**), a **Detected stack (FINGERPRINT)** pill list, **Endpoints seen
(SURFACE)** (first 200), **Passive hygiene (LEADS · not proven)**, **DOM-XSS leads (STATIC ·
candidates)**, and an explicit blind-spot legend naming what a quick loopback scan does *not* exercise.
Data: `GET OFF /api/coverage/<run_id>`.

**6e. Timeline** (`p3Timeline`, `app.js:2706`) — an **Investigation replay** slider that scrubs the
attack graph's growth by monotonic `first_seen`. Paths and choke-points are only highlighted once fully
materialised at that cut ("no premature path highlight"). Counter reads "Step N of M · seq ≤ X · N nodes
· M edges · P paths". Pure reconstruction, no traffic.

**Honest empty states:** a `blackboard`-stream run says "This run reports on the reasoning spine" +
**Open in Live**; a `none`-stream run (Strix/AEGIS) says "Runs in its own sandbox".

**Status:** READ-ONLY + offline re-verify (which issues zero target traffic).

---

#### 7. `proof` — **"Proof Studio"**
*Sub-title: "Strix generates an exploit; VIGIL turns it into PROOF. A FACT here means a deterministic oracle FIRED over the executor-captured raw bytes of the reproduction — not the model's word. A LEAD is an honest 'not reproduced'. A DENIED proof had dangerous PoC content refused BEFORE any mint. Read-only."* — `app.js:5555-5648`

**Sees:** Run select; a **Proofs** card with a disposition line (`N FACT` / `N lead` / `N denied`); one
card per proof showing bug class, finding ref, status badge (**FACT — oracle re-fired over captured
bytes** / **DENIED — dangerous PoC refused (<category>)** / **LEAD — not reproduced**), the oracle +
confidence, the channels it was reproduced from, and whether it **crossed to spine** ("signed evidence
spooled" — only a FACT crosses).

**Action:** **Export verifiable bundle** → `POST OFF /api/proof/export` `{run}`. Disabled unless the run
has ≥1 oracle-confirmed FACT. On success it shows the **bundle path**, the **trust-root fingerprint**
(with the instruction: "PUBLISH this out-of-band — the client pins it so a bundle re-signed under another
key is refused"), and the exact **verify offline** command.

**Status:** WIRED (read-only + one export action).

---

#### 8. `report` — **"Client Report"**
*Sub-title: "A LIVE, always-current report: every finding is re-verified OFFLINE on load, so a FACT is a re-checkable certificate — not a stale PDF, and not the AI's word. Read-only."* — `app.js:5370-5434`

**Sees:** Run select; an **Executive summary** card ("N sound of M total" re-verified); one card per
proven finding with Surface, Oracle + confidence, **Certificate** (truncated cert id) and **Standards**
control pills (OWASP / CWE / ATT&CK / PCI) joined from the compliance provider.

**Action:** **⤓ Download dossier** (`downloadDossier`, `app.js:5333`) → `POST OFF
/api/dossier/<run_id>/build`, then an `<a download>` click on `GET OFF /api/dossier/<run_id>.zip`.
Status line: "Packaging the dossier (reports + proof bundle + signed manifest)…" then "Dossier
downloaded — tamper-evident + offline-verifiable."

**Data:** `GET OFF /api/evidence/<run>` + `GET OFF /api/compliance/<run>`.

**Status:** WIRED (read-only + dossier download).

---

#### 9. `fixes` — **"Fixes"**
*Sub-title: "What to fix after discovery, and the gated process an auto-fix follows."* — `app.js:3603-3789`

**Sees:** Run select; four tiles (**Fixable** / **Unproven** / **Live auto-fix: OFF — "provision +
authorize"** / **Verify: oracle-silent — "proof required"**); **The gated fix ladder (PROCESS)** — a
horizontal numbered stage strip rendered from the server's `plan.ladder`; **Fixable findings
(CONFIRMED)** cards; and **Highest-impact fix points (IMPACT)** — choke-points from the world model
(kind, `src → dst`, "severs N path(s)", "· bridge").

**Action per finding:** **Apply fix (gated)** → `POST OFF /api/remediate/<run_id>/<ref>/apply`. The
in-UI hint states it: "Runs the gated `vigil patch` ladder when this run has a signed offense spine;
otherwise it shows exactly what's needed. **Non-destructive — never opens a PR.**" The result panel
prints the command, a note, and the ladder's raw output.

**Explicit honesty:** "Only oracle-confirmed findings are eligible — unproven leads are never
auto-fixed." Live auto-application (clone/build/open-PR) is a *separate* sovereign-gated capability that
must be provisioned and authorized; nothing is cloned/built/opened from this screen.

**Data:** `GET OFF /api/remediate/<run_id>` + `GET OFF /api/worldmodel/<run_id>`.

**Status:** WIRED, actionable (gated, non-destructive).

---

#### 10. `defense` — **"Defense (AEGIS)"**
*Sub-title: "Put VIGIL in front of an app you run and watch it prove AI attacks in real time."* — `app.js:3426-3600`

**Sees:** a prominent legend — *"A CONFIRMED verdict here is a PROVEN attack on your app (an oracle
fired). A 'lead' is a suspicion. 'Clear' means nothing was proven — it is NOT proof of safety."* Four
tiles (**Gateway** / **Mode** / **Upstream** / **Actors seen**), a setup or running panel, an **actor
beliefs** card, and a **Live verdicts** feed.

**Setup form fields** (`defSetupForm`, `app.js:3506`):
- **Your app's URL (upstream)** — required
- **Bind host** (default `127.0.0.1`) + **Port** (default `8080`); a non-loopback bind triggers a
  `confirm()` warning
- **Mode** select: `Observe — watch only (default, blocks nothing)` / `Enforce — block PROVEN attacks
  (needs entitlement)`
- **Honeypot paths** (optional, comma-separated)
- **Deployment secret** + a **Generate** button (`crypto.getRandomValues`, 24 bytes hex). In-UI text is
  explicit that this is *identifier pseudonymisation on the SDK ingest path, **NOT** a request
  password/auth*
- **Gateway name (slug)** (default `aegis-gateway`)
- Legend clarifying that canary / prompt-injection detection for an LLM app is the **in-process SDK
  path** (`aegis detect` / the Aegis SDK), **not** this reverse proxy

**Actions:**
- **Start defense** → `POST OFF /api/aegis/setup`. On success it opens a drawer, **"Run on your edge"**,
  with a copyable production command
- **Stop gateway** → `POST OFF /api/aegis/stop`
- Verdict rows with a certificate are clickable → **Attack certificate** drawer (attack, confirmed-by,
  cert id, confidence). Note: "the matched-span detail is kept server-side and not streamed to the
  browser."

**Enforce downgrade is surfaced honestly:** if `requested_mode == enforce` but `effective_mode !=
enforce`, the panel says "You requested ENFORCE but it downgraded to observe (the `AEGIS_RESPOND`
entitlement isn't available here) — nothing is being blocked."

**Actor rows** show the **client source IP** (an AEGIS actor key with the internal `session:` prefix
stripped), a belief bar (0-100 %) and an observation count.

**Data:** `GET OFF /api/aegis/status` (4 s poll) + SSE `GET OFF /api/aegis/verdicts`.

**Status:** WIRED, actionable.

---

#### 11. `replay` — **"Replay the Proof"**
*Sub-title: "Paste a VIGIL report or finding (report.json) and re-fire its retained oracle proofs OFFLINE — pure re-computation, no target, no traffic. A tampered proof shows as CONTRADICTED, never a green reproduction."* — `app.js:911-994`

**Sees:** a 10-row textarea for the JSON, a **Re-fire proofs offline** button, then four tiles
(**Findings** / **Reproduced** / **Contradicted** / **Ungrounded**) and one card per finding with a badge
labelled **REPRODUCED** / **CONTRADICTED (tampered / won't re-fire)** / **UNGROUNDED (no re-runnable
claim)**, the re-fired oracle and confidence, and a note.

**Action:** `POST OFF /api/replay` `{doc}` → `console/actions.py:672` `replay_document`, which routes to
`verify.reverify.reverify_document`. Invalid JSON is caught client-side with a refuted badge.

**Status:** WIRED, actionable — but the action is *pure offline re-computation*, no target, no mint.

---

### Group MANAGE (13 screens)

---

#### 12. `sessions` — **"Sessions"** — `app.js:4708-4724`

**Sees:** a **New session** button in the header; a hint explaining that connecting a session lets a live
`vigil engage --session … --connect …` run draw on the other session's knowledge as **advisory priors
(never facts)**; then a 2-column card grid, one card per session showing the kind pill, run count, up to
8 clickable run ids (→ `#/live?run=…`), and a "draws on:" row of connected session ids each with a ✕
disconnect link.

**Actions (all `window.prompt`/`window.confirm` based):**
- **New session** → `POST OFF /api/session/create` `{name, kind:"engagement"}`
- **Rename** → `POST OFF /api/session/rename`
- **Connect…** → `POST OFF /api/session/connect` `{id, other}` (prompt lists the other sessions)
- ✕ on a connection → `POST OFF /api/session/disconnect`
- **Delete** → `POST OFF /api/session/delete` `{hard:false}` ("Remove from your session list?" —
  reversible)
- **Delete permanently** → same with `{hard:true}` ("It is removed from history — **your runs and the
  signed record are kept**")

**Data:** `GET OFF /api/sessions`.

**Status:** WIRED, actionable.

---

#### 13. `activity` — **"Activity"**
*Sub-title: "How VIGIL is working in the background — active runs, the SIGIL agent mesh, spine activity, and a live event stream."* — `app.js:1903-2101`

**Sees:** a plane-status strip (**Offense: online/offline**, **Sovereign: online/offline**,
**Kill-switch: ENGAGED/released**); a legend stating plainly *"A read-only view across both planes —
nothing here changes anything"*; four tiles (**Active runs** / **Agents active** / **Ingest lag** /
**Kill-switch**); an **Active work (OFFENSE)** card listing up to 12 runs (status, mode, target, elapsed,
slug, findings count, stream type, **Watch live** button); an **Agent mesh & spine (SOVEREIGN)** card
(per-agent recent-record count and per-agent action/interrupt budget, plus a spine head / records-since-
checkpoint / last-consolidation line); and a **Live event stream** feed.

**Data:** polls `OFF /api/runs` (3 s) and `SOV /api/snapshot` (4 s); attaches **one** sovereign SSE
`SOV /api/stream?since=<head_seq>` so it tails from the current head instead of replaying the whole
spine; de-duplicates by `seq`.

**Status:** READ-ONLY (the only button is the navigation "Watch live").

---

#### 14. `safety` — **"Approvals & Safety"** *(owner plane)*
*Sub-title: "Everything that needs your sign-off, the kill-switch, capabilities, and the live governance feed."* — `app.js:3193-3424`

Owner banner: *"Owner plane — approvals, the kill-switch, and capability changes are all signed with your
key on the server."*

**Sees:** four tiles (**Kill-switch** / **Waiting** / **Spine head** / **Budget today**) and six cards.

| Card | Contents | Actions |
|---|---|---|
| **Waiting for your approval (OWNER)** | one card per pending approval: kind · seq, tier pill, agent → subject | **Approve** / **Deny** → `POST SOV /api/action` |
| **Capabilities (OWNER)** | rows for `gesture` and `voice` with an enabled/disabled chip | **Enable** / **Disable** → `SOV /api/action` `enable_*`/`disable_*` |
| **Agent promotions (OWNER)** | the verified fold of owner-signed promotions (agent + scope) | **Revoke** per row; and an **agent** + **scope** input pair with **Grant promotion** |
| **Kill-switch (OWNER)** | ENGAGED / released status sentence | **Engage kill-switch** (danger) or **Release** → `SOV /api/action` `kill`/`release`. Hint: *"Halting is always safe and immediate. Releasing requires your signed request."* |
| **Live governance feed (LIVE)** | SSE `SOV /api/stream`, last 60 rows | READ-ONLY |
| **Pending approvals (READ-ONLY)** | the **offense-plane, keyless** queue: one card per queued offense action with `request_id`, timestamp, args preview, and a **copyable** `vigil approve sign --base-dir … --request-id …` command | **Copy** only — **the console is keyless and can NEVER sign** (GET only, no POST route). Stated in-screen. |

**Promotion semantics rendered in-screen:** "A scope of `*` covers every kind; a per-kind revoke does NOT
reduce a `*` grant — revoke the `*` row to fully un-promote. **ENVOY and DELEGATE can never be
promoted.**" (Enforced server-side: `apps/sigil/sigil/ui/actions.py:49-55` returns an explicit `error` so
a refused grant cannot read as success.)

**Data:** `SOV /api/snapshot` (5 s poll) + `OFF /api/approvals/loopback` (5 s poll) + SSE `SOV /api/stream`.

**Status:** WIRED, actionable (owner-signed server-side; the browser never holds a key).

---

#### 15. `charter` — **"Charter & Attestation"** *(owner plane)*
*Sub-title: "Every target-touching action is gated on a signed engagement charter + a who/when/what usage attestation minted BEFORE anything runs — no attestation, no run. This UI provisions a LOOPBACK authority; a REMOTE target needs a signed charter this UI cannot mint — it VERIFIES + guides you through the out-of-band ceremony instead."* — `app.js:5229-5368`

**Sees / does:**
1. **Engagement slug** input + **Load** button (default slug `loopback`)
2. **Authorization status** card: Charter present (yes/no), Authorized scope (pills), **Reach** (REMOTE
   authorized + hosts / loopback only / none), **Window** (`not_before → not_after`, environment),
   **Gate chain** (pills)
3. **Provision a loopback authority (OWNER)** — button **"Provision (loopback only)"** →
   `POST OFF /api/authority/provision` `{slug}`. Scope is **hard-fixed to 127.0.0.1**
4. **Remote target — charter required (out-of-band)**: a **Target host** input; an advisory
   "Authorized for this target?" verdict computed client-side by `_scopeCovers` (exact host or
   `*.wildcard` suffix) and explicitly labelled *advisory; the gate enforces*; a literal copy-ready
   ceremony command `vigil provision --slug <slug> --scope <HOST>` with the instruction *"Run this on a
   TRUSTED host that holds the owner key — NOT in this UI"*; and a **Re-check charter** button
5. **Usage attestation ledger — who / when / what**: a **Load ledger + verify chain** button →
   `POST OFF /api/authority/ledger`, showing **Chain verified** ("verified — signed, monotonic, not
   back-dated" / "unverified") and the raw `who` output

**Status:** WIRED, actionable — but structurally **loopback-only**; it cannot mint or widen a remote
charter.

---

#### 16. `apikeys` — **"API Keys"** *(owner plane)*
*Sub-title: "Every key the system uses — sealed on this machine, never shown back to the browser. Press Test to check a key is live; a failing key always shows here."* — `app.js:3090-3151`

**Sees:** owner banner; a **Test all keys** button; a red banner if any key is failing; then sections by
category (`st.secret_categories`).

- **Plain secret cards** (`drawSecretCard`, `app.js:2955`): a status row (**Set** + backend + fingerprint
  + health chip, or **Not set** with an explanation), an explicit red failure line when the last live
  check failed, a masked password input, a **Seal** button, and a **Test** button (only offered for a
  *set*, *probeable* secret). Hint: *"Sealed to your OS keyring or a TPM-sealed store when available; the
  value never enters the spine, a log, or any response — only a fingerprint is recorded."*
- **Provider cards** for provider-backed categories (cloud / knowledge-graph) (`drawCloudProvider`,
  `app.js:3038`): a 2-column field grid mixing **sealed secrets** (masked input or a textarea for a
  pasted GCP service-account JSON / kubeconfig, via `set_cloud_file_secret`) and **non-secret config**
  (region / role ARN / tenant / subscription — value shown, saved with `set_cloud_config`), plus one
  **Test connection** button per provider.

**Health chip states** (`healthChip`, `app.js:2944`): **Working** (ok) / **Failing** (fail) / **Can't
verify** (unknown) / **Not tested**.

**Actions (all `POST SOV /api/action`):** `set_secret`, `set_cloud_file_secret`, `set_cloud_config`,
`check_secret`, `check_secrets`.

**Status:** WIRED, actionable (owner plane). If the sovereign plane is down or unauthenticated the screen
says so explicitly and offers nothing.

---

#### 17. `tools` — **"Tools"**
*Sub-title: "External security tools the offense engine runs on this host — installed live."* — `app.js:442-473`

**Sees:** four tiles (**Installed** / **Missing** / **Failed** / **Required missing**); a header line
naming the detected OS; a card per tool with a status badge, name, `core`/`optional` pill, version,
purpose, resolved path, and — when action is needed — a copyable install command with a **Copy** button.

**Status vocabulary is deliberately honest** (`TOOL_BADGE`, `app.js:428`): `installed` → confirmed,
`missing` → idle, `failed` → blocked, **`shadowed` → blocked** ("A different `<name>` on your PATH (…) is
shadowing the real tool — it is NOT usable"), `unsupported` → refuted. On a non-Linux host the screen
says plainly that host tools are Linux packages and nothing is probed.

**Strix sandbox tools** are listed in a clearly separated card labelled **"NOT HOST-INSTALLED"** —
provided by the container image, "neither probed nor installed on this host. Listed for reference only."

**Tool consciousness (ADVISORY) panel** (`drawToolProfiles`, `app.js:353`): four tiles (**Adopted** /
**Refused** / **Installed** / **Installable**) and per-tool rows showing `host CLI` vs `agent skill`, a
**Controllable (cli)** or **Refused** chip with the admission reason, and signal pills `playbook ✓` /
`typed argv ✓` / `installed` / `installable`. Two buttons per adopted-but-missing tool:
- **Install** → `POST OFF /api/tools/install` `{name}`; the server replies `needs_consent` + the exact
  command, which the UI then displays as `$ <cmd>` next to a **Run it** button that re-posts with
  `{consent:true}` — a deliberate **two-step operator consent**
- **Research** → `GET OFF /api/toolresearch/<name>`; renders the canonical research query and official
  doc links

**Data:** `GET OFF /api/tools` + `GET OFF /api/toolprofiles`.

**Status:** WIRED, actionable (gated install).

---

#### 18. `brain` — **"Brain"**
*Sub-title: "The propose-only decision engine, plus what the system has learned, how well it scores, and the capabilities it can bring to bear."* — `app.js:4127-4451`

**Six sub-tabs** (`BRAIN_TABS`, `app.js:4120-4124`), tab reflected in the hash:

**18a. Decision engine** (`brainDecision`) — a propose-only banner ("Every step crosses the conjunctive
gate + egress gate; a finding is a FACT only when a VIGIL oracle fires"), an **Active brain** card
(name, `propose-only` pill, design credit, module path), the gate-posture doctrine, and — **only if a
real proposal is persisted** — a **Target profile (OBSERVED)** card and the **proposed attack chain**:
per-step priority, tool, a danger chip (`recon` / `active`), a per-step gate verdict (**auto-eligible**
only for recon in staging/twin posture, otherwise **queues for owner approval**), an effectiveness
(prior) bar, and the raw params. That persisted proposal is written by a REAL producer — a
`vigil engage --brain hexstrike` run persists the ordered chain it drives (via
`vigil_integration/brains/engine_think.py::BrainThink`) to `<run_dir>/brain-proposal.json`, the exact
file the panel reads; the reader invents nothing. **No live proposal → an honest empty state: "No live
proposal wired."** Data: `GET OFF /api/brain/decision` (an optional `?run=<id>` scopes it to one run's
proposal with no cross-run fallback — a run with no proposal shows empty, never a stale earlier proposal).

**18b. Memory** — four tiles (**Engagements** / **Findings** / **Priors** / **Dead ends**) and a
**Learned priors (MEMORY)** list (bug_class · archetype · surface → success % with a lower confidence
bound and successes/attempts). Empty state states it never fabricates a score. Data: `GET OFF /api/memory`.

**18c. Benchmark** — a **Run the soundness benchmark (LIVE)** card explaining the corpus (11 planted bugs
+ 5 safe controls, loopback-only, no external target/scope/egress) with a **Run benchmark now** button
(labelled "Running… (up to ~5 min)" while in flight) → `POST OFF /api/benchmark/run`. Result renders four
tiles (**True positives** / **False positives** / **False negatives** / **F1** with precision + recall)
and a verdict line. Also a **Benchmark baseline (CALIBRATION)** list of recorded tp/fp/fn per app+engine.
Data: `GET OFF /api/benchmark`.

**18d. Catalog** — a filter input over the real capability catalog; each entry shows label, tier and
purpose. Two legends: "Capabilities map to already-gated engage flags" and "Reasoning (critics, learning,
reflection) is **advisory only** — it re-ranks and defers, but never promotes a finding." Data:
`GET OFF /api/capabilities`.

**18e. Intel** (per engagement) — an engagement select, a raw JSON dump of `GET OFF /api/intel/<slug>`,
and an **Intel recon (OFFLINE)** action card: a seed apex-domain input + **Run offline recon** button →
`POST OFF /api/intel/run` `{slug, seed}`. In-screen text: *"Ingest passive recon for this engagement from
bundled fixtures — no network. Live collection is a charter-gated engagement decision, never a one-click
button, so this control cannot egress."*

**18f. Planner** (per engagement) — same engagement select + raw JSON of `GET OFF /api/planner/<slug>`,
plus a **Planner (READ-ONLY PROJECTION)** card with a **Compute plan projection** button →
`POST OFF /api/planner/run` `{slug}`. "It sends no traffic and drives no tools."

**Status:** WIRED; three owner-plane actions (benchmark run, planner projection, offline intel ingest),
all explicitly non-egressing.

---

#### 19. `mcp` — **"MCP Servers"**
*Sub-title: "The gated capabilities this engine exposes to an external MCP (Model Context Protocol) client over an on-host stdio server."* — `app.js:4017-4057`

**Sees:** a note from the server, then one card per exposed tool with its description and pills: **tier
T<N>**, **gated**, its provenance (`observation`), and **read-only** when annotated. Footer: "Transport:
stdio — on-host, no network surface. Start the server with `crucible mcp serve --slug <engagement>`."

**Verified exposed-tool allowlist:** `DEFAULT_EXPOSE_ALLOW = frozenset({"reverify_finding",
"declared_service"})` — `engine/crucible/framework/v2/mcp/server.py:67`. So **two** tools, fixed and
fail-closed, slug-independent.

**Status:** READ-ONLY. **There is no start/stop toggle in the UI** — starting the stdio server is a CLI
act. The code comment says so explicitly ("a UI start/stop toggle is a later slice", `app.js:4012`).

---

#### 20. `system` — **"System & Services"**
*Sub-title: "Everything the system needs, at a glance — prerequisites, the UI ports, and every docker service's state."* — `app.js:4060-4125`

**Sees:** four cards.
- **Prerequisites** (header reads `READY` or `ACTION NEEDED`): per-binary OK/missing rows; per-venv
  built/"not built — run ./bootstrap.sh"; per-directory path + writable/NOT writable
- **UI ports (127.0.0.1)**: each of the four ports as `free` or in-use
- **Docker services**: per service a state pill (`running` / `absent` / other) + purpose. Hint: "Create
  the absent ones — idempotent, running ones are left alone."
- **Action needed** (only when the report carries issues): a bulleted list

**Action:** **Bring up missing services** → `POST OFF /api/services/up` `{all: <checkbox>}`, with a
checkbox **"include Neo4j + otel"**. Re-polls `/api/services` after ~1.8 s.

**Data:** `GET OFF /api/services` — the `vigil doctor` report surfaced in the UI
(`console/api.py:218` `services_data`).

**Status:** WIRED (read-only report + one bring-up action).

---

#### 21. `compliance` — **"Compliance & ATT&CK"**
*Sub-title: "Every oracle-confirmed FACT mapped to OWASP / CWE / PCI-DSS / SOC 2 / ISO 27001 + MITRE ATT&CK. A lead never asserts control coverage — only a proven fact does."* — `app.js:5160-5227`

**Sees:** a Run select; a **Findings → standards controls** card. Each row is a finding with a **proven**
(confirmed) or **advisory** (idle) badge. A proven row shows control pills — `OWASP <id>`, up to 3 CWEs,
up to 3 `ATT&CK <id>` (warn-toned), up to 2 `PCI <id>`. A non-proven row shows only the sentence
*"advisory note only — a lead / unmapped class asserts no control coverage."*

**Data:** `GET OFF /api/compliance/<run_id>`.

**Status:** READ-ONLY.

---

#### 22. `assurance` — **"Assurance — continuous proof / drift"**
*Sub-title: "Diff the ORACLE-CONFIRMED fact set between two runs: a fact that newly appears is a regression (a new exposure); one that disappears is a fix. Deterministic + offline — each run's certificates are re-fired, never re-attacked. A lead is never counted."* — `app.js:5436-5553`

**Sees:**
- **Live assurance projection** card (`telemetryCard`, `app.js:5505`): header badge **collector running**
  / **collector not running**; when running, four tiles (**Facts** / **Leads** / **Refusals** / **Tool
  calls**), a **Per engagement** breakdown (FACT / lead / refused / events per slug), and a **By kind**
  histogram. When not running it says so and tells you to start it with `vigil up --with-telemetry`.
  Explicitly framed: "A read-only, one-way projection of the signed spine — it mints no fact and widens
  no scope."
- A **Now** run select and a **vs baseline** run select
- Summary: **drift detected** / **no drift — same proven set**, then three lists — **Regressions —
  newly-proven exposures**, **Fixed — no longer proven**, **Stable — proven in both** (each capped at 100
  shown)

**Actions:**
- **Re-verify now** — re-fires the retained certificates offline by re-fetching `GET OFF /api/drift/<curr>:<prev>`
- **Download drift (JSON)** — a pure client-side `Blob` export of the already-fetched view
  (`downloadJSON`, `app.js:5352`); no backend, no new data exposure

**Data:** `GET OFF /api/telemetry` + `GET OFF /api/runs` + `GET OFF /api/drift/<arg>`.

**Status:** READ-ONLY + offline re-verify + client-side export. Note in-screen: "Attack-path / asset
graphs are per-run — see the World Model on the Findings screen" (this panel does not fabricate one).

---

#### 23. `settings` — **"Settings"** *(owner plane)*
*Sub-title: "The model the AI reasons with. API keys have moved to their own screen."* — `app.js:2778-2800`

Owner banner: *"Owner plane — every change is signed with your key on the server. The browser never holds
or receives key material."*

**Five cards:**
1. **Reasoning model (OWNER)** (`drawModelCard`, `app.js:3156`) — a choice list of available models, each
   with a label, `current` pill, `no key needed` pill for keyless options, and a note. Button: **Use this
   model** → `SOV /api/action` `set_model`. Hint: mechanical helpers (memory extraction) always use a fast
   model; a running engine picks up the change on the next `vigil up`.
2. **API keys (OWNER)** — a hint + a **Manage API keys** button → `#/apikeys`
3. **Reasoning effort (OWNER)** (`drawEffortCard`, `app.js:2870`) — a select over `low / medium / high /
   xhigh / max` plus "Model default", and an **Apply effort** button → `set_effort`. Hint states it applies
   to the offense reasoning engine, the sovereign think step, and the Strix codebase agent (our `max` maps
   to Strix's `xhigh`), and that older models ignore it.
4. **Bring your own model (OWNER)** (`drawProviderCard`, `app.js:2898`) — a provider select; then the
   provider's model field (with suggested model ids), its config fields, a "Needs: …" line showing which
   keys that provider requires with their live health, a link to `#/apikeys`, and a **Use this provider**
   button → `set_provider`. A keyless provider says "This provider uses your local session — no model id
   needed."
5. **System configuration (OWNER)** (`drawConfigCard`, `app.js:2822`) — every non-secret operational env
   var the server exposes (`CONFIG_META`), grouped by subsystem, each rendered as an enum select / bool
   checkbox / text input with its own **Save** button → `set_config` `{env, value}`. Blank clears the var
   back to its built-in default. The server type-validates each value (int ranges, url/cidr/host/ports/
   enum) and refuses an unknown var — the UI cannot write arbitrary env.

**Status:** WIRED, actionable (owner plane).

---

#### 24. `governance` — **"Governance & Gate Audit"**
*Sub-title: "Read-only: whether exploitation runs GOVERNED (capability entitlement enforced) or UNGOVERNED, the sovereignty tier, the safety-gate conjuncts every action must clear, and the m-of-n destruction quorum. This screen cannot provision, authorize, or fire anything."* — `app.js:996-1090`

**Four cards:**
- **Posture** — a confirmed/refuted badge and the sentence **"GOVERNED — capability entitlement is
  ENFORCED"** or **"UNGOVERNED — entitlement not enforced"**, plus the entitlement's granted tier and an
  explanation
- **Sovereignty** — the tier pill and `SEALED (latched)` / `not sealed`
- **Safety gate** — the conjuncts every target-touching action must clear, as pills; "fail-closed"
- **Destruction authority (read-only audit)** — the m-of-n threshold (`m of n`), the authorizer key ids,
  the **consumed nonce count** ("spent single-use authorizations"), and any pending authorizations with
  their action id, blast class, target and `k of m signatures`. When no trust root exists: "No destruction
  trust root provisioned — no m-of-n quorum exists on this host."

**Data:** `GET OFF /api/governance` (`console/api.py:769`).

**Status:** **READ-ONLY, by design.** In-screen: "the UI cannot provision, authorize, or fire a
destructive action. Minting and consuming an authorization happen only via the gated CLI with m-of-n
independent signatures."

*(Note: `screens.yaml` marks `governance` `owner: false`; `docs/FEATURES.md:189` lists it as
`governance(owner)`. The code — `app.js` NAV — has no `owner: true` flag on it. The four owner-flagged
screens are `safety`, `charter`, `apikeys`, `settings`.)*

---

### Group LEARN (4 screens)

---

#### 25. `trust` — **"Trust Center"**
*Sub-title: "VIGIL's signed, offline-verifiable certificates — rendered as certificates: trust root, out-of-band fingerprint pin, and a live offline PASS/FAIL verification."* — `app.js:476-664`

**Sees:** a doctrine block, then a 2-column grid of certificate cards. Each card shows: kind label, name,
run pill, **Schema**, **Signed digest** (truncated), **Trust root** (`m-of-n threshold X of Y`),
**Authorizers** (key id pill + truncated public key), and either:
- **"Fingerprint pin (out-of-band)"** for a source-pinned cert, with the note "This trust root is pinned
  in SOURCE — a re-sign under a fresh key fails the pin"; or
- **"Fingerprint (self-asserted, in-bundle — NOT a pin)"** for a per-run cert, with the explicit caveat
  that it "proves tamper-after-signing only" and an optional **out-of-band pin input**

A `recall`-kind cert additionally shows per-tool recall / precision / F1 / tp / fp / fn and the ground-
truth count. A `coverage` / `plan-integrity` cert shows scope, target host and a summary line.
A not-yet-produced cert shows an idle badge and "run a scan / make bench to mint and sign this
certificate."

**Action:** **Verify offline** → `POST OFF /api/verify-cert` `{name, run_id, oob_pin}`. Result renders:
- **PASS — signature re-verified offline** or **FAIL — did not verify**
- **Trust root vs out-of-band pin** as a *three-state* row: **matches the out-of-band pin** (confirmed) /
  **does NOT match the pin** (refuted) / **trust root UNPINNED — no out-of-band pin supplied (origin not
  bound)** (idle — *deliberately never green*)
- Signed-by authorizers, digest, pin source

**Data:** `GET OFF /api/certs` (`console/api.py:1318`).

**Status:** WIRED (read + a pure offline re-computation).

---

#### 26. `posture` — **"Proof of Posture"**
*Sub-title: "The Certificate of Non-Exploitability — a signed, coverage-bounded, offline-verifiable proof that, over the surface the scanner REACHED, an applicable oracle had a live channel and did not fire. The boundary (denominator + residual) is the point."* — `app.js:667-908`

**Sees:** **Refresh** and **Download certificate (JSON)** buttons, a doctrine block, then one card per
present posture certificate containing:
- header: target, engagement pill, run pill
- a **freshness** caveat, stated honestly: "the signed certificate core is deterministic (no wall-clock);
  the freshness bound is the bundle's external RFC3161 time anchor (a sidecar), not a field of the signed
  bytes"
- four tiles: **Closed** ("oracle had a channel & did NOT fire"), **Open** ("an oracle FIRED (a
  finding)"), **Unproven** ("payload sent, no oracle adjudicated"), **Re-executable** (`X / Y` — "CLOSED
  that re-fire offline; the rest are binding-only (need VIGIL)")
- a **coverage denominator** panel: surfaces reached, insertion points probed, distinct classes probed,
  crawl bound (pages + depth), frontier truncated, budget exhausted — closing with a red-toned line:
  *"CLOSED is bounded to the surface the scanner REACHED … Undiscovered endpoints/parameters are
  discovery/recall — OUT of this denominator, NOT covered. A CLOSED certificate is never a claim of
  security against everything."*
- the **residual** (the honest boundary), rendered verbatim from the certificate
- **posture claims by surface**: per-surface tables with columns *Parameter · Class · Status · Evidence
  oracle(s) · Verification · Probes*; status badges **CLOSED** / **OPEN** / **UNPROVEN**; the
  Verification column is a two-value pill — **re-executable** (raw bytes embedded, a pinned oracle kernel
  re-runs them) vs **binding** (the offline verifier re-checks the signed verdict + projection but
  re-firing the oracle needs VIGIL). Code comment: *"Never dress binding up as re-exec."*
- **trust root & out-of-band pin**: schema, signed digest, m-of-n threshold, authorizers, fingerprint
  pin, owner pubkey, plus publication guidance
- **verify offline (no VIGIL, no trust in us)**: the exact multi-line command with a **Copy** button, and
  a precise statement of what exit 0 does and does **not** prove — "It does NOT re-fire the oracle (that
  needs VIGIL) — the certificate states this residual on its face."
- when a portable bundle exists, its path with a **Copy path** button

**Empty state is explicitly non-fabricating:** "Nothing here is fabricated. Mint a signed Certificate of
Non-Exploitability with `python -m vigil_integration.posture attest --out <dir>`."

**Data:** `GET OFF /api/posture` (`console/api.py:1443`).

**Status:** READ-ONLY + a client-side JSON export.

---

#### 27. `manual` — **"Manual"**
*Sub-title: "How every part of VIGIL works — in plain language."* — `app.js:218-244`

A two-column layout: a sticky **CONTENTS** index and the sections themselves. Content is a **static**
array `window.VIGIL_MANUAL` (`packages/vigil-ui/manual.js:8`) — documentation, **no runtime/target data**.

**13 sections** (`manual.js`): `overview` "What VIGIL COMMAND is" · `safety` "The safety model (read this
first)" · `assess` "Running an assessment" · `live` "Watching it live" · `findings` "Findings & evidence"
· `fixes` "Fixes" · `arming-autofix` "Arming live auto-patch (opening real PRs)" · `defense` "Defense —
AEGIS" · `safety-screen` "Approvals & Safety" · `settings` "Settings — keys & model" · `brain` "Brain —
memory, benchmark & catalog" · `deploy` "Deploying — local & hosted" · `glossary` "Glossary".

**Status:** READ-ONLY. **Coverage gap worth flagging:** the manual has no section for `terminal`, `chat`,
`sessions`, `proof`, `report`, `compliance`, `assurance`, `charter`, `apikeys`, `knowledge`, `mcp`,
`system`, `governance`, `trust`, `posture`, or `replay`.

---

#### 28. `knowledge` — **"Knowledge Engine"** — `app.js:4726-5093`

Intro hint: "An auto-updating feed of vulnerability intelligence from trusted sources (NVD, OSV,
CISA-KEV), alongside the defensive knowledge catalog. **Every feed entry is an intel-tier LEAD, never a
fact** — only a fired oracle confirms. The live pull is a gated, opt-in egress act; offline is the
default."

An **Engagement** select drives everything. **Eight cards:**

| Card | Contents | Actions |
|---|---|---|
| **Propose-to-learn (OWNER)** | autolearn latch chip (`enabled` / `disabled` / `unknown (sovereign offline)`); ranked proposals with KEV badges, severity and rationale | **Activate / Deactivate autolearn** (`enable_autolearn`/`disable_autolearn`); **STOP (emergency halt)** / **Release kill-switch** (`kill`/`release`); per proposal **Queue for approval** (`queue_learn`) or, once queued, **Accept** / **Deny** (`approve`/`deny` on the spine seq) |
| **Add & learn a source (OWNER)** *(only shown when autolearn is on)* | a CVE input and a URL input | **Add to learn queue** (`queue_learn`); **Learn from URL** (`start_learn`) → renders "Last learn" with **N grounded** / **N advisory** counts, the host, page count, and up to 4000 chars of extracted text. In-screen: "URL-learn fetches PUBLIC pages through the scope / robots / SSRF gate; nothing a page asserts becomes a fact — grounded claims are verbatim source spans, everything else is advisory." |
| **Self-evolve** | badge **studied everything in scope** / **in progress**; horizon gaps, coverage gaps (bug-class pills), draft-proposal count, unlearned leads, calibration (resolved count + Brier score) | per unlearned lead **Draft skills (deep-learn)** → `POST OFF /api/knowledge/<slug>/deeplearn`; **Run evolve tick** → `POST OFF /api/evolve/<slug>/tick`. Both disabled while the kill-switch is engaged. Hint: "drafts only, never merges or applies, mints no fact." |
| **Feed sources** | per source: name, mode pill, apex host | READ-ONLY |
| **Vuln-feed pull** | egress-default chip ("egress offline by default") | **Pull now** → `POST OFF /api/feed/<slug>/pull` (one-shot, kill-switch gated). **Recurring feed sidecar** sub-panel: an **Interval (s)** number input (60–86400, default 3600), **Start** → `POST /api/feed/<slug>/start`, **Stop** → `POST /api/feed/<slug>/stop`; status shows `running · pid N · every Xs` or `stopped`. In-screen: "There is no persisted schedule — only the live pid and the interval you choose." |
| **Vulnerability leads** | per CVE: a `KEV` (danger) or `lead` pill, id, severity, summary, feed | READ-ONLY |
| **Defensive knowledge catalog** | operator count; per operator id, name and ATT&CK/CWE technique pills (first 200) | READ-ONLY ("Never facts.") |
| **knowledge/ folder → git (OWNER)** | — | **Status** → `POST OFF /api/knowledge/gitsync {action:"status"}`; **Regenerate + commit** → `{action:"sync"}`. In-screen: "Regenerate the system-map, SECRET-SCAN the knowledge/ folder, and commit it locally. A hit REFUSES the commit and lists the files to redact. **Pushing to GitHub stays a deliberate `vigil knowledge push` CLI act — this never pushes.**" |

**Data:** `GET OFF /api/engagements` + a 4-way federated fetch: `OFF /api/vulnintel/<slug>`,
`SOV /api/snapshot`, `OFF /api/evolve/<slug>`, `OFF /api/feed/status` — one failing plane is tolerated.

**Status:** WIRED, actionable (gated, leads-only).

---

## 3. Screens that exist but are NOT normally reachable

| Surface | Where | Reality |
|---|---|---|
| **`renderStub`** — a "This surface is part of the plan" placeholder | `app.js:4585-4596` | **Unreachable for any current NAV id.** All 28 NAV items are `ready: true` and all 28 have an explicit `route()` branch, so the fallback path (`app.js:5684-5685`) only fires for an *unknown* hash id (`item === null`), where it renders "Not found — arriving in undefined". Confirmed by reading NAV + `route()`. |
| **Command palette (⌘K)** | `openPalette`, `app.js:146` | Present in the top bar on every screen; clicking it only shows a toast saying it is "on the roadmap". **A visible, non-functional control.** |
| **MCP start/stop** | `app.js:4012` (comment) | The MCP screen is read-only; there is no UI control to start or stop the stdio server. |
| **Legacy console + cockpit SPAs** | `console/static/`, `apps/sigil/sigil/ui/static/` | Still committed and still served on their own ports, but they are **not** the unified app (see §0.1). |

**Screenshot coverage gap (not a defect, just a fact):** `docs/screenshots/` holds **32** captures
(01-home … 32-trust-center) covering 26 of the 28 screens plus 4 sub-tabs and a benchmark/planner view.
**No screenshot exists for `mcp`, `system`, or `posture`** — the three most recently added screens.

---

## 4. Legacy UI #2 — CRUCIBLE Ops Console (22 screens, served at `:8787/`)

Source: `engine/crucible/framework/v2/console/static/app.js:26-51` (`SCREENS`). Hash-routed
(`#<id>`), with a top bar carrying an **engagement select**, a **safety** indicator and a **theme
toggle**; a nav sidebar grouped in four; and a right-hand **detail drawer**.

| Group | Screens |
|---|---|
| **OPERATIONS** | `overview` Overview · `live` Live Run · `engagements` Engagements · `findings` Findings · `graph` Attack Graph · `evidence` Evidence · `timeline` Timeline · `coverage` Coverage |
| **INTELLIGENCE** | `reasoning` Reasoning Brain · `intel` Intelligence · `planner` Planner · `memory` Memory · `kernel` Kernel |
| **ASSURANCE** | `benchmark` Benchmark · `analysis` Analysis · `improve` Improve · `intake` Intake |
| **GOVERNANCE** | `authority` Authority & Safety · `defender` Defender · `socialdef` Social Defense · `reports` Reports · `status` System Status |

Notes: it uses `innerHTML` with inline `onclick` handlers, which is exactly why the strict `'self'` CSP
is **deliberately not** sent on the console's static HTML responses (`console/server.py:155-159`). Its
attack-graph renderer is a separate `graph.js`. Four of its screens (`analysis`, `improve`, `intake`,
`defender`, `socialdef`) are generic `subsystem(m, '<name>')` views.

**Status: NOT VERIFIED at runtime by me** — inventoried from source only.

---

## 5. Legacy UI #3 — SIGIL cockpit (one page, served at `:8733/`)

Source: `apps/sigil/sigil/ui/static/index.html` + `app.js`. Title bar "◆ SIGIL · glass cockpit ·
loopback · provenance-first" with a kill-switch chip. **Five panels:**

1. **Approval queue** — per item `seq · tier · kind · agent` + subject, with **Approve** / **Deny**
   buttons
2. **Agent activity (recent)** + **Budget today** (actions / interrupts per agent) + **Ingest lag**
   (head, records since checkpoint)
3. **Capabilities · settings** — a state chip and toggle per capability (`gesture`, `voice`) plus
   **Disable both** / **Enable both**
4. **Live event stream** — "click any atom to verify its provenance"; each row is chipped `anchored` /
   `tail` / `broken`
5. **Detail overlay** — clicking a record fetches `/api/record/<seq>` and shows seq, kind, truncated
   `entry_hash`, an **integrity verified / INTEGRITY BROKEN** chip, the integrity reason, and the raw
   payload JSON

**Sovereign plane HTTP surface** (`apps/sigil/sigil/ui/server.py:152-175, 317`):
`GET /api/ask` · `/api/snapshot` · `/api/settings` · `/api/record/<seq>` · `/api/stream` (SSE) ·
`/api/sigil/hud` (SSE) · `/api/graph` · `/api/graph/entity` · `/api/classify`; `POST /api/action`.

**The `POST /api/action` allowlist** (`apps/sigil/sigil/ui/actions.py:13-21`) — **fail-closed; anything
else is refused**:
`approve` · `deny` · `kill` · `release` · `promote` · `revoke` · `queue_learn` · `start_learn` ·
`disable_gesture` · `enable_gesture` · `disable_voice` · `enable_voice` · `disable_autolearn` ·
`enable_autolearn` · `disable_both` · `enable_both` · `set_secret` · `set_model` · `set_provider` ·
`set_effort` · `check_secret` · `check_secrets` · `set_cloud_config` · `set_cloud_file_secret` ·
`set_config`. **25 actions.**

Design invariant (module docstring): "The browser never holds key material: it sends an authenticated
REQUEST … and the SERVER signs with the persisted owner key."

---

## 6. Vendored UI #4 — Strix TUI (third party)

`vendor/strix/strix/interface/` — a Textual terminal app. Entry point `strix` console-script
(`vendor/strix/pyproject.toml:53-54`), reachable from VIGIL as `vigil strix …`.

- App class `StrixTUIApp` (`tui/app.py:757`)
- Modal screens: `SplashScreen` (`:102`), `HelpScreen` (`:226`), `StopAgentScreen` (`:242`),
  `VulnerabilityDetailScreen` (`:290`), `QuitScreen` (`:713`)
- 15 renderers under `tui/renderers/`: agent_message, agents_graph, base, filesystem, finish,
  load_skill, notes, proxy, reporting, shell, thinking, todo, user_message, web_search, registry
- Also has a non-TUI CLI mode (`strix/interface/cli/`)

**This is vendored third-party code, not VIGIL-authored.** Inventoried from source; NOT VERIFIED at
runtime.

---

## 7. Command-line surface

### 7.1 `vigil` — the super-CLI (`integration/vigil_integration/cli.py`, entry point `vigil_integration.cli:main`)

**26 native verbs** (each with its own flags; the ones below are named exactly as `sub.add_parser(...)`
declares them):

| Verb | What it does (from its own `help=`) |
|---|---|
| `engage <url>` | run an engagement against an owner-authorized target (loopback or remote). Key flags: `--slug`, `--objective`, `--scope` (comma-separated **literal hosts / `*.wildcards`, no CIDR** — a wildcard is called out as "a deliberate BROAD grant"), `--base-dir`, `--session`, `--connect`, `--replay`, `--access-log`/`--auth-log`/`--conn-log`, `--max-iterations` (default 12), `--brain hexstrike`, `--approve-offense` |
| `engage-instruct <slug> <text>` | add a mid-run natural-language instruction to a LIVE engagement (advisory; every action it prompts still waits for approval) |
| `ledger who\|when` | query the usage-attestation ledger |
| `verify-ledger` | verify the usage-attestation ledger integrity |
| `verify` | verify the offense spine segments (per-segment, owner-tie-aware). `--owner-pubkey`, `--delegation`, `--governance-delegation`, `--scope` |
| `provision` | mint + sign a CRUCIBLE authority for a **loopback** slug (`--scope` literal hosts, `--environment`, `--hours`, `--max-actions`) |
| `identity` | export the offense stable identity PUBLIC keys (spine + governance) for owner delegation |
| `patch` | run the gated auto-patch ladder over a **provenance-grounded** confirmed finding. Source must be `--finding-envelope` **or** `--from-spine` (a raw-JSON finding is never accepted). `--apply-edits` works in a **disposable clone**; `--open-pr` is OFF by default and needs `--signed-authorization` + `--authority-trust-root` + `--mandatory-signer` + `--ledger` (single-use nonce) |
| `remediate --prove` | the four-state LIVE remediation proof over a provenance-grounded finding (`--prove` is required — the only mode) |
| `reprove` | the continuous re-proof service: loop the four-state live re-proof (`--once`, `--cycles N`, `--interval`) |
| `witness` | the deployable loopback witness co-sign service (`witness serve --port P`) |
| `provision-destruction` | mint the m-of-n destruction quorum keys for `vigil patch --open-pr` (prints keys ONCE) |
| `authorize-destruction` | sign ONE destructive action → a single-use signed authorization |
| `approve {provision-authority \| list \| sign}` | per-action owner approval for offense tools. `sign` uses `VIGIL_APPROVAL_OWNER_KEY` |
| `proof-export` | assemble a client-verifiable proof bundle from a run's oracle-confirmed FACTs |
| `dossier` | compile everything a run produced into ONE self-contained tamper-evident `.zip`; `--session <id>` packages a whole session |
| `detect` | run the Detection Mirror over log files (`--access-log`, `--auth-log`, `--conn-log`) |
| `up` | bring the whole unified UI up at one origin. Flags: `--port` (8770), `--host`, `--domain`, `--no-browser`, `--insecure-no-api-key`, `--base-dir`, `--with-feed` + `--feed-slug` + `--feed-interval`, `--with-voice`, `--with-gesture`, `--with-telemetry` + `--telemetry-interval`, `--services` |
| `down` | stop a running `vigil up` (backends + proxy) |
| `services {up \| status \| down \| render}` | docker bring-up of the egress gateway + qdrant/neo4j/otel, idempotent (`--with-graph`, `--with-observability`, `--all`) |
| `doctor` | read-only readiness report (binaries, both venvs, writable dirs, UI ports, docker services). `--json`. Non-zero exit on a hard prerequisite gap |
| `telemetry --out P` | live assurance/metrics collector over the signed spine (`--interval`, `--once`) |
| `knowledge {sync \| push \| status}` | operator-gated git sync of `knowledge/` (regenerate + secret-scan + commit; **push is separate**) |
| `learn-drain --spool --owner-pubkey` | drain the sovereign→offense learn-grant spool (`--watch`, `--interval`) |
| `terminal <command…>` | a governed LOCAL read/inspect command through the gate. Classifies **A2 → QUEUES for approval, never auto**; `--approve` runs it. Allowlisted binaries only (no network, no writers, no interpreters) |
| `sandbox <command…>` | an ARBITRARY command inside a network-isolated, workspace-confined **bwrap** sandbox. Classifies **A3 → QUEUES**; `--approve` runs it. Needs `bwrap` |

**5 passthrough subsystem verbs** (`integration/vigil_integration/dispatch.py:23-31`) — each `exec`'d in
its **own venv**, so a single interpreter never co-loads the two trust domains:

| Verb | Environment | Console-script |
|---|---|---|
| `vigil sigil …` | sovereign (`.venv-sovereign`) | `sigil` |
| `vigil crucible …` | offense (`.venv-offense`) | `crucible` |
| `vigil aegis …` | offense | `aegis` |
| `vigil strix …` | offense | `strix` |
| `vigil gateway …` | offense | `vigil-gateway` |

### 7.2 `crucible` — the offense arsenal (`framework.v2.__main__:main`)

**31 subcommands** (`_DISPATCH`, verified verbatim): `analysis` · `api` · `attack-paths` · `aegis` ·
`authority` · `benchmark` · `calibration` · `capabilities` · `collaborator` · `console` · `defender` ·
`drift` · `engage` · `entitlement` · `eval` · `evidence` · `imports` · `improve` · `intake` · `intel` ·
`kernel` · `knowledge` · `mcp` · `memory` · `plan` · `plan-integrity` · `report` · `scan` ·
`socialdefense` · `status` · `verify`.

Also invocable as `python3 -m framework.v2 <subcommand>`.

### 7.3 `aegis` — the defensive dual (`framework.v2.aegis.cli:main`)

**3 subcommands** (`aegis/cli.py:183-219`):
- `detect` — detect over one `TelemetryEnvelope` JSON (file or `-`)
- `gateway` — run the inline reverse-proxy provable firewall in front of your app (`--upstream`,
  `--host`, `--port` default 8080, `--slug` default `aegis-gateway`, mode/honeypot/secret flags)
- `demo` — run the class-1 canary-disclosure flow end-to-end

### 7.4 `vigil-gateway` — the host egress gate (`gateway/vigil_gateway/cli.py:44-55`)

**6 subcommands:** `serve-proxy` · `render-firewall` · `check-firewall` · `apply-firewall` ·
`render-compose` · `ensure-networks`.

### 7.5 `sigil` — the sovereign core (`apps/sigil/sigil/cli.py`)

**38 verbs** (36 declared directly + `approve`/`deny` added in a loop at `:1301`):
`agents` · `approve` · `audit` · `backup` · `bridge` · `budget` · `capability` · `checkpoint` ·
`consolidate` · `dashboard` · `delegate-offense` · `deny` · `doctor` · `floor` · `gesture-nav` ·
`graph` · `host` · `inbound` · `index` · `ingest` · `kernel` · `knowledge` · `mesh` · `owner-pubkey` ·
`restore` · `scrape` · `search` · `serve` · `settings` · `sign` · `spine` · `status` · `vault` ·
`verify` · `voice` · `warden` · `warden-anchor-get` · `warden-anchor-set`.

`sigil serve` is what starts the sovereign cockpit (loopback by default; private bind allowed).

### 7.6 `strix` — the agent body (vendored)

`strix` console-script → `strix.interface.main:main`; runs either the TUI or a plain CLI mode. Requires
Docker (it checks the Docker connection at start-up). Third-party.

---

## 8. Backend endpoint map (what each screen actually talks to)

### 8.1 Offense console read plane — `GET`, loopback `:8787`, mounted at `/offense/*`

Exact routes (`console/server.py:62-83`): `/api/status` · `/api/engagements` · `/api/runs` ·
`/api/sessions` · `/api/benchmark` · `/api/memory` · `/api/kernel` · `/api/tools` · `/api/toolprofiles` ·
`/api/capabilities` · `/api/aegis/status` · `/api/feed/status` · `/api/telemetry` ·
`/api/terminal/history` · `/api/certs` · `/api/posture` · `/api/brain/decision` · `/api/governance` ·
`/api/mcp` · `/api/services`.

Prefixed routes (`:92-108`): `/api/inbox/` · `/api/approvals/` · `/api/report/` · `/api/worldmodel/` ·
`/api/coverage/` · `/api/charter/` · `/api/planner/` · `/api/intel/` · `/api/vulnintel/` · `/api/evolve/`
· `/api/compliance/` · `/api/drift/` · `/api/evidence/` · `/api/proof/` · `/api/remediate/` ·
`/api/toolresearch/`.

Special GETs: `/api/events` (SSE) · `/api/blackboard` (SSE, with `id:` cursor) · `/api/chat/sessions` ·
`/api/chat/session/<id>` · `/api/aegis/verdicts` (SSE) · `/api/dossier/<run>.zip` (download).

**Cross-checked:** every console route above has at least one consumer in `packages/vigil-ui/app.js`.
There are currently **no orphaned (routed-but-unconsumed) console routes** — three earlier orphans
(`POST /api/launch/scan`, `GET /api/authority/<slug>`, `GET /api/session/<id>`) were removed in the "B7"
cleanup while their provider functions were kept; pinned by
`console/tests/test_orphan_routes_b7.py`.

### 8.2 Offense console action plane — `POST` (each CSRF/rebind-gated)

`/api/launch/assessment` · `/api/launch/cloud` · `/api/replay` · `/api/reverify/<run>` ·
`/api/remediate/<run>/<ref>/apply` · `/api/proof/export` · `/api/dossier/<run>/build` ·
`/api/authority/provision` · `/api/verify-cert` · `/api/authority/ledger` · `/api/knowledge/gitsync` ·
`/api/evolve/<slug>/tick` · `/api/knowledge/<slug>/deeplearn` · `/api/feed/<slug>/pull` ·
`/api/feed/<slug>/start` · `/api/feed/<slug>/stop` · `/api/killswitch/<slug>/trip` ·
`/api/tools/install` · `/api/services/up` · `/api/benchmark/run` · `/api/planner/run` · `/api/intel/run`
· `/api/session/create` · `/api/session/rename` · `/api/session/delete` · `/api/session/connect` ·
`/api/session/disconnect` · `/api/chat/send` · `/api/aegis/setup` · `/api/aegis/stop` ·
`/api/terminal/dryrun` · `/api/terminal/propose` · `/api/terminal/run`. (`console/server.py:397-592`.)

### 8.3 Sovereign plane — mounted at `/sovereign/*`

Reads: `/api/snapshot` · `/api/settings` · `/api/record/<seq>` · `/api/stream` (SSE) · `/api/sigil/hud`
(SSE) · `/api/graph` · `/api/graph/entity` · `/api/classify` · `/api/ask`.
Writes: `POST /api/action` — the 25-action fail-closed allowlist listed in §5.

---

## 9. Cloud / Kubernetes exploitation confirmations (the "E-series") — how a user reaches them

This matters for writers because the capability is **complete in the engine but has no screen of its
own**. Stating it wrongly in either direction would be a real error.

**What exists, verified in the tree at this HEAD.** Six achieved-effect confirmations are wired end to
end — an offline deterministic *oracle* plus a VIGIL-owned *producer/admission* module each:

| Confirmation | Oracle (offense engine) | Producer / admission module |
|---|---|---|
| Instance-metadata (IMDS) credential capture | `verify/oracles.py` `imds_credential_capture_oracle`; capture shape `verify/imds_capture.py` | `integration/vigil_integration/live/imds_runner.py` (the only component that reaches the metadata endpoint) + `live/imds_verify.py` |
| Exposed-secret validity | `verify/oracles.py:5145` `exposed_secret_validity_oracle`; capture shape `verify/secret_capture.py` | `live/secret_verify.py` |
| GCP service-account impersonation | `verify/oracles.py:5368` `gcp_sa_impersonation_oracle`; capture shape `verify/gcp_impersonation_capture.py` | `live/gcp_impersonation_verify.py` |
| IAM privilege-escalation primitive | `verify/oracles.py` (E2 branch — "achieved strict-gain, not reachability") | `live/iam_escalation_verify.py` |
| Kubernetes RBAC **tier 1** — anonymous subject bound to a dangerous built-in ClusterRole | `verify/oracles.py:2275-2290` (`anonymous_dangerous_rbac`) | `live/k8s_rbac_verify.py` |
| Kubernetes RBAC **tier 2** — dangerous-verb / default-service-account grant (rule-parsing) | `verify/k8s_rbac_grant.py` + its oracle branch | `live/k8s_rbac_grant_verify.py` |

**How a user reaches them today — three honest statements:**

1. **There is no dedicated screen.** No NAV id, no tab, no button in `packages/vigil-ui/app.js` names
   IMDS, secret-validity, impersonation, IAM privilege-escalation, or K8s RBAC. Verified by grep across
   `app.js` and the console route tables.
2. **There is no dedicated `vigil` CLI verb.** `imds_verify` / `secret_verify` /
   `gcp_impersonation_verify` / `iam_escalation_verify` / `k8s_rbac_verify` / `k8s_rbac_grant_verify`
   have **no** reference outside `integration/vigil_integration/live/` and their own tests — they are
   Python library entry points called by the engine's verification path, not console-script verbs.
   Verified by grep across `*.py`, `*.js` and `*.md`.
3. **What the UI *does* offer for cloud is the seedless posture path**, and it is honest about being
   posture rather than exploitation: the New Assessment wizard's `cloud` target type →
   `POST OFF /api/launch/cloud` → `console/actions.py:155` `launch_cloud`, which requires a **signed
   charter** for the slug, validates the target *label* (explicitly "NOT a URL, CIDR, or path — never a
   seed"), writes the offline sensor task into `targets/<slug>/fusion.json`, and spawns the gated
   `engage <slug> --fuse-only --spine`. The wizard's own field hint says the sensor "reads your imported
   inventory, never the live account."

**The deferral, stated exactly.** For several of these cloud confirmations what remains outstanding is
**real-world live fire against a third-party cloud account**, which waits on the customer supplying
their own cloud credentials. The detection logic, the evidence handling, the certificates and the safety
gates are built and proven offline with fixtures. The code says so itself: `imds_runner.py`'s module
docstring records that the transport is injected so the module is unit-tested with a mock, and that "its
live-fire is a thin real-transport binding (httpx with proxies disabled + redirects disabled + TLS
verification on), **deferred until an authorized lab credential is available**." Writers should say
plainly: built and proven offline; not yet pointed at a live third-party account; that step is the
customer's credential, by design.

**Where a confirmed cloud fact *would* appear once fired:** the same places every other FACT appears —
Live (as a `finding` event with `verified_by_oracle`), Findings (table + Evidence tab certificate),
Proof Studio, Report, Compliance, and the drift diff on Assurance. Nothing bespoke.

---

## 10. Build & release safeguards (supply chain) — current tree state

Writers asked about "dependency hash-locking, container base-image pinning, SBOM, and a vulnerability
gate that blocks on CRITICAL" should note this is a **build/CI property, not a screen**: there is no UI
control for it anywhere in the 28 screens, and no `vigil` verb for it. What the working tree shows at
this HEAD:

- **Environments** are declared in `envs/offense.txt` and `envs/sovereign.txt` and built by
  `envs/build_envs.sh`. At this HEAD neither file carries `sha256:` hashes — **dependency hash-locking
  is not yet visible in the tree** (`grep -c "sha256:"` → 0 in both).
- **Container base image**: `gateway/Dockerfile:14-15` pins by **tag** via a build arg
  (`ARG PYTHON_BASE=python:3.13-slim`), not by digest. The gateway runtime is deliberately
  stdlib-only ("no third-party RUNTIME packages"), which is a real supply-chain reduction independent
  of pinning.
- **CI** (`.github/workflows/ci.yml`) has 8 jobs: `vigil-core`, `crucible-core`, `gateway`,
  `integration`, `strix-vigil`, `sigil-governor`, `formal-verification`, `warden-kernel`. There is a
  test named `integration/tests/test_sbom.py` in the `integration` job — but read what it covers before
  describing it (next bullet).
- **"SBOM" in this repo currently means an OFFENSE CAPABILITY, not a build artifact.**
  `integration/vigil_integration/live/sbom.py` parses a **target's** manifest/lockfile for concrete
  package versions and looks them up in a pinned, vendored OSV snapshot
  (`docs/capability-matrix/osv-snapshot.json`) to drive the deterministic `version_range` oracle. Its
  own docstring is explicit that a grype/syft/trivy/osv-scanner run "is only a PROPOSER of where to
  look — its CVE match never mints a FACT," and that a conclusive out-of-range non-fire is demoted to
  INCONCLUSIVE because the `version_range` branch is declared `clean_capable: false` in
  `docs/capability-matrix/evidence-branches.json`. **Do not describe this as an SBOM of VIGIL itself.**

**Guidance:** if hash-locking, digest-pinned base images, a VIGIL-own SBOM and a CRITICAL-blocking
vulnerability gate land after this inventory was written, they should be described as build and release
safeguards in the CI pipeline — and a writer must re-verify them in the tree before claiming them, since
at this HEAD only the target-side SBOM capability and the tag-pinned, dependency-free gateway image are
present. **NOT VERIFIED** here beyond what is listed above.

---

## 11. Honesty notes for downstream writers

Things that must **not** be overstated. Each is grounded in a specific place in the code.

1. **The unified UI is only reachable via `vigil up`.** The `sync.sh` vendoring into the two plane static
   dirs has not been performed in the current tree (PR #220 reverted by #221). Anyone pointing a browser
   at `:8787` or `:8733` gets a *legacy* UI. (§0.1)
2. **The command palette (⌘K) is a stub.** It is visible on every screen and only toasts "on the
   roadmap". (`app.js:146`)
3. **The MCP screen cannot start or stop anything** — it lists a fixed, two-tool, fail-closed allowlist
   (`reverify_finding`, `declared_service`) and tells you the CLI command. (`mcp/server.py:67`)
4. **The Governance screen is read-only by construction** — it cannot provision, authorize, or fire a
   destructive action; m-of-n minting/consumption is CLI-only. (`app.js:1077-1088`)
5. **The offense-side "Pending approvals" list is keyless.** It lists queued actions and shows a copyable
   `vigil approve sign` command; there is **no POST route** for it — the console can never sign.
   (`app.js:3316-3320`, GET-only)
6. **The Charter screen can provision a loopback authority only.** A remote charter requires an
   out-of-band ceremony on a host holding the owner key; the screen's client-side "authorized for this
   target?" check is explicitly labelled *advisory — the gate enforces*. (`app.js:5273-5320`)
7. **Fixes never open a PR.** The `Apply fix (gated)` button runs the non-destructive ladder; `--open-pr`
   is a separate CLI leg requiring an m-of-n signed authorization and a single-use nonce ledger.
   (`app.js:3746-3752`; `cli.py` `patch --open-pr`)
8. **AEGIS `enforce` mode can silently downgrade** — and the UI says so: without the `AEGIS_RESPOND`
   entitlement it runs in observe and *nothing is blocked*. (`app.js:3492-3495`)
9. **The AEGIS "deployment secret" is not request auth** — it is identifier pseudonymisation on the SDK
   ingest path. The UI states this. (`app.js:3543-3545`)
10. **Canary / prompt-injection detection is the in-process SDK path, not the reverse proxy.**
    (`app.js:3548-3550`)
11. **"Clear" in Defense is not proof of safety.** The screen leads with this. (`app.js:3430-3432`)
12. **A CLOSED posture claim is bounded to the surface actually reached.** The Posture screen renders the
    coverage denominator and the residual prominently, and distinguishes **re-executable** from
    **binding** verification — the latter needs VIGIL to re-fire the oracle. (`app.js:787-800`, `:855-864`)
13. **A per-run certificate's fingerprint is not an out-of-band pin.** Trust Center labels it
    "self-asserted, in-bundle — NOT a pin" and renders an unpinned trust root as a **neutral, never
    green** state. (`app.js:551-562`, `:616-625`)
14. **The telemetry collector is off by default** (`vigil up --with-telemetry`); the Assurance screen
    says "collector not running" rather than showing zeros as if they were measurements.
    (`app.js:5514-5518`)
15. **Vuln-feed egress is off by default**; "Pull now" and the recurring sidecar are conscious, kill-
    switch-gated opt-ins, and everything they produce is an intel-tier **LEAD**. (`app.js:4795-4800`)
16. **Brain > Intel "Run offline recon" cannot egress** — it ingests bundled fixtures. Live collection is
    a charter-gated engagement decision. (`app.js:4443-4445`)
17. **Voice and gesture navigation are opt-in and A1-signal only** (`vigil up --with-voice` /
    `--with-gesture`); they navigate to a known in-app screen id and inject nothing into the OS. Local
    camera gesture is **not functional** — gesture input is the phone companion (`uiproxy.py:938-943`).
18. **The Manual covers 13 topics, not all 28 screens** (§2, screen 27).
19. **No screenshots exist for `mcp`, `system`, or `posture`.** (§3)
20. **Doc drift to fix or avoid repeating:** `packages/vigil-ui/README.md` says "21 screens";
    `docs/FEATURES.md:284-285` says "22 `screens.yaml` ids". Both are stale — the verified number is
    **28**, and `docs/FEATURES.md:189` already says 28.
21. **The six cloud / Kubernetes exploitation confirmations have no screen and no CLI verb.** They are
    complete and wired end to end in the engine (oracle + VIGIL-owned producer, proven offline with
    fixtures), and a confirmed one surfaces through the ordinary FACT path (Live → Findings → Proof →
    Report). What the **UI** offers for cloud is the seedless, charter-gated *posture* launch, which
    reads an imported inventory rather than the live account. Do not write "click here to run a cloud
    exploit" — there is no such button. (§9)
22. **What is deferred for those cloud capabilities is real-world live fire against a third-party cloud
    account, pending customer-supplied credentials — nothing else.** The detection logic, evidence
    handling, certificates and safety gates are built and proven. `imds_runner.py`'s own docstring
    records the live-fire binding as "deferred until an authorized lab credential is available." Say
    this plainly rather than implying either that it is unbuilt or that it has already run in the
    field. (§9)
23. **"SBOM" in this repo currently means scanning a *target's* dependencies, not publishing VIGIL's
    own bill of materials.** And at this HEAD `envs/*.txt` carry no dependency hashes and
    `gateway/Dockerfile` pins its base image by tag, not digest. Any claim about hash-locking,
    digest-pinning, a VIGIL-own SBOM or a CRITICAL-blocking vulnerability gate must be re-verified in
    the tree at the time of writing — none of it is a UI feature in any case. (§10)
24. **The Live "Facts / Leads / Refusals" tiles count what has streamed into *this browser session*,**
    not a server-side total: `counts()` folds `L.events`, the array the SSE has delivered so far
    (`app.js:1580-1588`). A reconnect resumes from `Last-Event-ID`, so the numbers converge, but they
    are a view of the stream, not an authoritative tally.
25. **Run-scoped screens auto-select "the newest run" for you.** Findings, Report, Proof Studio,
    Compliance and Assurance all fall back to `runs[0]` when nothing is chosen (e.g.
    `if (!RPT.run && RPT.runs.length) RPT.run = RPT.runs[0].run_id`). If a reader sees an empty report,
    the likeliest cause is that the newest run is a `blackboard`- or `none`-stream run that saves no
    rendered report — the screens say so honestly rather than showing zeros.

---

## 12. Summary counts (all verified against source)

| Thing | Count | Source |
|---|---|---|
| Web UIs in the repo | **3** (+1 vendored terminal UI) | §0 |
| **VIGIL COMMAND top-level screens** | **28** | `app.js` NAV, `route()`, `screens.yaml` — all three agree |
| … of which owner-plane (`owner: true`) | 4 (`safety`, `charter`, `apikeys`, `settings`) | `app.js:19-53` |
| … of which fully read-only | 8 (`home`, `activity`, `mcp`, `compliance`, `manual`, `governance`, `posture`*, `report`*) | *`posture`/`report` add a client-side export / dossier download |
| Sub-tabs inside screens | 5 (Findings) + 6 (Brain) = **11** | `P3_TABS`, `BRAIN_TABS` |
| Live SSE streams the UI opens | 6 distinct (`/api/blackboard`, `/api/events`, `/api/aegis/verdicts`, `SOV /api/stream`, `SOV /api/sigil/hud`) | §8 |
| Legacy CRUCIBLE Ops Console screens | **22** | `console/static/app.js:26-51` |
| Legacy SIGIL cockpit panels | **5** | `apps/sigil/sigil/ui/static/index.html` |
| Strix TUI modal screens | 5 + 15 renderers | `vendor/strix/.../tui/` |
| `vigil` native CLI verbs | **26** (+5 subsystem passthrough) | `cli.py` `build_parser`, `dispatch.py` |
| `crucible` subcommands | **31** | `framework/v2/__main__.py` `_DISPATCH` |
| `aegis` subcommands | **3** | `aegis/cli.py` |
| `vigil-gateway` subcommands | **6** | `gateway/vigil_gateway/cli.py` |
| `sigil` subcommands | **38** | `apps/sigil/sigil/cli.py` |
| Console GET routes | 36 (20 exact + 16 prefixed) + 6 special | `console/server.py:62-108`, `:235-272` |
| Console POST actions | **33** | `console/server.py:397-592` |
| Sovereign `POST /api/action` allowlist | **25** | `apps/sigil/sigil/ui/actions.py:13-21` |
| MCP tools exposed to external clients | **2** | `framework/v2/mcp/server.py:67` |
| Screenshots on disk | 32 (+ README) | `docs/screenshots/` |
| Cloud / K8s exploitation confirmations wired end to end | **6** (IMDS credential capture · exposed-secret validity · GCP SA impersonation · IAM privilege-escalation · K8s RBAC tier 1 · K8s RBAC tier 2) | §9 |
| … of which have a dedicated screen or CLI verb | **0** — they reach the user through the ordinary FACT path | §9 |
| Capability packs offered in the wizard's tool picker | **8** (`recon`, `domxss`, `browser-xss`, `spa`, `sso`, `access-control`, `graphql-dos`, `arsenal`) | `console/actions.py:240-257` `ENGAGE_CAPABILITIES` |
| Wizard target types / cloud sub-modes | **6** / **3** (`cloud`, `k8s`, `infra`) | `app.js` `TARGET_TYPES`, `CLOUD_MODES` |
| CI jobs | **8** (`vigil-core`, `crucible-core`, `gateway`, `integration`, `strix-vigil`, `sigil-governor`, `formal-verification`, `warden-kernel`) | `.github/workflows/ci.yml` |
