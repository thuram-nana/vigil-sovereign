# VIGIL browser E2E harness (`tests/e2e/`)

A **real** Python + Playwright browser harness for the unified VIGIL UI
(`packages/vigil-ui/app.js`, 35 screens) served by the uiproxy on
`http://127.0.0.1:8770`.

> **Why this exists.** Before this harness the only "UI tests" were the
> `docs/tests/test_*.py` files. Those read `app.js`/`components.css` as **text**
> and assert substrings — a headless **jsdom** structural guard. **No browser is
> ever launched, no backend call is ever made.** This harness is the opposite:
> it drives a real Chromium against a real running stack and asserts that a
> **button press fires a real backend HTTP call**, not merely that the DOM
> changed.

This directory is **author-only** here: it does not create the venv, download
Chromium, or run against a live stack. The parent/CI provisions the browser and
runs it live.

---

## 1. Isolation from the two FATAL-2 venvs

VIGIL keeps **two** process venvs that must never be merged and never import each
other's code (`framework`/`strix` must never be imported from sovereign code):

- the **sovereign** venv (sigil cockpit),
- the **offense** venv (CRUCIBLE console + gated api).

This harness runs in a **third, fully separate** venv — **`.venv-e2e`** — created
by `tools/e2e/setup-e2e-venv.sh`. It is **not** either FATAL-2 venv and must stay
out of both:

- It installs **only** a browser/HTTP client (`playwright` + `pytest`), never
  `framework`, never `strix`, never any sovereign package.
- It talks to the stack **only over the network** (`http://127.0.0.1:8770`),
  exactly as a browser would. It never imports VIGIL Python and never touches
  the spine, keys, or governor in-process.
- CI must run it as its own job with its own venv, never by installing playwright
  into the sovereign or offense environment.

A static guard enforces the no-import rule: `test_no_fatal2_import.py` asserts no
file under `tests/e2e/` imports `framework`, `strix`, or `vigil_integration`.

## 2. Air-gapped / vendored Chromium

`python -m playwright install chromium` is the **one** network/vendor step and it
is isolated in `tools/e2e/setup-e2e-venv.sh`. For an air-gapped host:

1. On a connected machine, set `PLAYWRIGHT_BROWSERS_PATH=/some/vendor/dir` and run
   `python -m playwright install chromium` — this materialises a pinned Chromium
   build under that dir.
2. Vendor (copy) that directory to the air-gapped host.
3. Export the same `PLAYWRIGHT_BROWSERS_PATH` before running pytest; Playwright
   resolves the vendored build instead of downloading.

The playwright **Python package** and the **Chromium build** are both pinned (see
below) so the air-gapped build is byte-reproducible.

## 3. Pinned versions

- **playwright == 1.49.1** (pinned exactly in
  `tests/e2e/requirements-e2e.txt` and in `tools/e2e/setup-e2e-venv.sh`). A given
  playwright release pins a specific Chromium revision, so pinning playwright pins
  the browser.
- **pytest / pytest-playwright** pinned alongside it.

Bump deliberately (new playwright ⇒ new Chromium ⇒ re-vendor), never float.

## 4. How it runs

```bash
# one-time, parent/CI provisions this (the ONLY network step is inside it):
bash tools/e2e/setup-e2e-venv.sh

# bring the stack up on 127.0.0.1:8770 by hand (NOT this harness's job):
#   vigil up            # the harness never starts/stops the stack

# run against the live stack:
.venv-e2e/bin/python -m pytest tests/e2e -v

# provide the owner bearer so authed_page can log in without reading it off the page:
VIGIL_E2E_TOKEN="<the token vigil up printed>" .venv-e2e/bin/python -m pytest tests/e2e -v
```

`base_url` defaults to `http://127.0.0.1:8770` and is overridable with
`VIGIL_E2E_BASE_URL`.

## 5. The login handshake (grounded in source)

The harness reproduces the SPA's own bootstrap, grounded in:

- **`packages/vigil-ui/app.js` `renderLoginGate` (line 333)** — the gate posts
  `V.postJSON(SOV("/api/login"), { token, totp? })` i.e. **`POST
  /sovereign/api/login`** with body `{ "token": "<bearer>" }` (TOTP optional). On
  a response with `authenticated === true` it calls `V.setSessionToken(token)` and
  routes to `#/home`.
- **`apps/sigil/sigil/ui/server.py` `_login` (~line 680) and `_login_pop`** — the
  cockpit verifier. Bearer branch: body `{token}` → resolves the per-user bearer
  (or the legacy owner token) → returns `{ ok: true, authenticated: true,
  username, role, permissions }`. It is one of the pre-token bootstrap routes
  (`/api/whoami`, `/api/login`, `/api/login/challenge`, `/api/oidc/login`;
  `_EXACT_ROUTES` at server.py:74).
- **`integration/vigil_integration/uiproxy.py` `route()` (line 925)** — maps
  `/sovereign/*` → sigil cockpit (`8733`), `/offense/api/v1/*` → gated api
  (`8799`), `/offense/*` → console (`8787`), `/__vigil/plane/*` → proxy-local,
  else static.
- **`packages/vigil-ui/index.html:16`** — `<body data-token="__VIGIL_TOKEN__" …>`.
  For the owner physically at the host, `vigil up` injects the owner bearer into
  that `data-token` attribute; `packages/vigil-ui/ui.js` reads it into
  `VIGIL_CFG.token`. The uiproxy **blanks** `data-token` for any relayed HTML
  (`_TOKEN_ATTR_RE`, uiproxy.py:293) so a remote viewer never receives it.
- **`packages/vigil-ui/ui.js` `token()`/`_headers()`/`authUrl()`** — the single
  token source. `token()` prefers the per-user bearer in
  `sessionStorage["vigil.session.token"]` over `VIGIL_CFG.token`. Every `fetch`
  carries it as the **`X-SIGIL-Token`** header (`_headers`, ui.js:85); SSE and
  download links carry it as **`?token=`** (`authUrl`, ui.js:222).

The `authed_page` fixture obtains a session two ways, in order:

1. If **`VIGIL_E2E_TOKEN`** is set (the parent/CI provides the token `vigil up`
   printed), the fixture performs the real bootstrap `POST /sovereign/api/login`
   with `{token}` and, on `authenticated`, seeds
   `sessionStorage["vigil.session.token"]` exactly as `V.setSessionToken` does —
   so every subsequent `X-SIGIL-Token` / `?token=` is identical to the SPA's.
2. Otherwise it falls back to whatever the page already carries (the owner
   `data-token` when running directly on the host). If neither yields an
   authenticated principal the fixture fails loudly — an unauthenticated run is
   not a silent pass.

## 6. `assert_calls(page, method, path_substr)` — "button → real backend call"

The core assertion. It is a **context manager** that uses Playwright's request
interception (`page.expect_request`) to wait for a backend request matching
`method` + `path_substr` **while an action runs inside the block**, and raises
`AssertionError` if no such request fires inside the timeout:

```python
from helpers import assert_calls

with assert_calls(page, "GET", "/offense/api/status"):
    page.click("text=System")            # the action under test
# past this line, the GET provably fired — not "the DOM changed", the call fired.
```

It asserts the **call**, not the DOM: the request is observed at the network
layer (method + URL substring), so a screen that renders from stale state without
hitting the backend **fails** the assertion. See `helpers.py`.

## 7. Discipline: what is run for real vs. what is only gate-checked

Two pytest markers, **mandatory** on every test:

- **`@pytest.mark.real_flow`** — full detection / proof / read flows that are safe
  to run for real. These run against the **MERIDIAN loopback range (`:19010`)**
  — never a third party, never a production host — and against the stack's own
  read APIs. A `real_flow` test may legitimately fire a scan/proof call and wait
  on its result.

- **`@pytest.mark.assert_gate`** — **destructive / offense controls**: panic,
  kill-switch, destruction-quorum, live-target engage, weaponized offense. These
  are **NEVER fired**. The test asserts the **gate engages**: the ceremony /
  owner-approval / confirm step is *demanded*, and the action is *blocked* without
  it. The pass condition is "the system refused / demanded approval", never "the
  destructive action completed". A `assert_gate` test that observed the action
  actually execute is a **failing** test.

Rule of thumb for Wave 3 authors: if firing the control for real could mutate a
live host, destroy data, or trip the kill-switch, it is `assert_gate` and you
assert the refusal. Everything else — reads, MERIDIAN detection, proof replay —
is `real_flow`.

The markers are registered in `conftest.py` (`pytest_configure`), so
`-m assert_gate` / `-m real_flow` select each class and `--strict-markers` is
honoured.

## 8. Loopback only

Everything is `127.0.0.1`: the UI (`:8770`), the backends it proxies (`8733` /
8787 / 8799), and the only authorized detection target, the MERIDIAN range
(`:19010`). The harness must never be pointed at a non-loopback host.

## 9. File map

```
tests/e2e/
  README.md                  # this file
  conftest.py                # pytest + playwright fixtures: base_url, page, authed_page; marker registration
  helpers.py                 # assert_calls() request-interception context manager + login helper
  screens.py                 # the 35-screen coverage matrix scaffold (hash route + control TODOs) for Wave 3
  test_smoke.py              # loads :8770, authenticates, navigates one screen, asserts one GET fired + rendered
  test_no_fatal2_import.py   # static guard: no framework/strix/vigil_integration import under tests/e2e
  requirements-e2e.txt       # pinned playwright/pytest
tools/e2e/
  setup-e2e-venv.sh          # creates .venv-e2e, installs pinned playwright, installs Chromium (the one network step)
```
