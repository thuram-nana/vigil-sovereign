"""E2E helpers: the request-interception assertion and the login handshake.

Pure browser/HTTP-client code. Imports ONLY the playwright client and stdlib —
never `framework`, never `strix`, never any sovereign package (FATAL-2).
"""
from __future__ import annotations

import contextlib
from typing import Iterator

# Playwright sync API types are imported lazily inside functions so this module
# also imports cleanly for the static no-FATAL-2-import guard without a browser.

# The SPA's own constants, grounded in packages/vigil-ui/ui.js + app.js:
#   SOV(p) -> "/sovereign" + p   (app.js)
#   per-user bearer lives in sessionStorage under this key (ui.js _SESSION_TOKEN_KEY)
SOVEREIGN_BASE = "/sovereign"
OFFENSE_BASE = "/offense"
SESSION_TOKEN_KEY = "vigil.session.token"

# The bootstrap login route the login gate posts to (app.js renderLoginGate:333 ->
# V.postJSON(SOV("/api/login"), {token, totp?})).
LOGIN_PATH = f"{SOVEREIGN_BASE}/api/login"
WHOAMI_PATH = f"{SOVEREIGN_BASE}/api/whoami"

DEFAULT_CALL_TIMEOUT_MS = 10_000


@contextlib.contextmanager
def assert_calls(page, method: str, path_substr: str,
                 timeout_ms: int = DEFAULT_CALL_TIMEOUT_MS) -> Iterator:
    """Assert that a backend HTTP call FIRES while the wrapped action runs.

    This is the core of "button -> real backend call". It observes the request at
    the NETWORK layer via Playwright request interception (`page.expect_request`),

    WARNING — never assert on a BACKGROUND-POLLED endpoint. `page.expect_request`
    resolves on the first match regardless of initiator, so an endpoint on a
    setInterval (e.g. /sovereign/api/snapshot, polled every 4s by pboxApprovalPoll
    app.js:10937; or /offense/api/events on live/strix/defense screens) would satisfy
    the match from a background poll even if the action under test fired nothing —
    green-washing the assertion. Assert only a nav-driven read that NO setInterval
    touches (grep app.js for setInterval to confirm).
    so it proves the call happened — not merely that the DOM changed. A screen
    that re-renders from stale state WITHOUT hitting the backend will NOT satisfy
    this assertion and the test fails.

        with assert_calls(page, "GET", "/offense/api/status"):
            page.click("text=System")
        # here the GET provably fired

    method       -- HTTP method, case-insensitive ("GET", "POST", ...).
    path_substr  -- substring that must appear in the request URL (e.g. a route
                    prefix like "/offense/api/status" or "/sovereign/api/snapshot").
    timeout_ms   -- how long to wait for the matching request after entering the
                    block. On timeout, raises AssertionError (not a bare
                    TimeoutError) naming the method + substring that never fired.
    """
    want = method.upper()

    def _match(request) -> bool:
        return request.method.upper() == want and path_substr in request.url

    # Lazy import so module import needs no playwright present (static guards).
    from playwright.sync_api import Error as PWError  # noqa: WPS433

    try:
        with page.expect_request(_match, timeout=timeout_ms) as request_info:
            yield request_info
    except PWError as exc:  # TimeoutError is a subclass of playwright Error
        raise AssertionError(
            f"expected a {want} request whose URL contains {path_substr!r} to fire "
            f"within {timeout_ms}ms, but none did ({type(exc).__name__}: {exc})"
        ) from exc


def login_via_api(page, base_url: str, token: str, totp: str | None = None) -> dict:
    """Reproduce the SPA bootstrap login and seed the session exactly as the UI does.

    Grounded in:
      * app.js renderLoginGate:333 -> V.postJSON(SOV("/api/login"), {token, totp?})
        and, on `authenticated`, V.setSessionToken(token).
      * apps/sigil/sigil/ui/server.py _login: bearer branch resolves {token} and
        returns {ok, authenticated, username, role, permissions}.
      * ui.js token(): the per-user bearer in sessionStorage[SESSION_TOKEN_KEY]
        takes precedence and is sent as the X-SIGIL-Token header on every call.

    Returns the principal dict on success. Raises AssertionError if the token is
    not accepted (an unauthenticated run must never silently pass).
    """
    body: dict = {"token": token}
    if totp:
        body["totp"] = totp

    # Use the page's own fetch so the request is same-origin and identical to the
    # SPA's postJSON (X-Requested-With header, JSON body).
    result = page.evaluate(
        """async ([url, body]) => {
            const r = await fetch(url, {
                method: "POST",
                credentials: "same-origin",
                headers: { "Content-Type": "application/json", "X-Requested-With": "vigil-ui" },
                body: JSON.stringify(body),
            });
            let data = null;
            try { data = await r.json(); } catch (e) { data = null; }
            return { status: r.status, data: data };
        }""",
        [base_url.rstrip("/") + LOGIN_PATH, body],
    )

    data = result.get("data") or {}
    if not data.get("authenticated"):
        raise AssertionError(
            f"login was not accepted (status={result.get('status')}, "
            f"body={data!r}); set VIGIL_E2E_TOKEN to a valid bearer"
        )

    # Seed sessionStorage exactly like V.setSessionToken(token) so every later
    # X-SIGIL-Token / ?token= the SPA sends is identical to a real logged-in user.
    page.evaluate(
        """([key, tok]) => { try { sessionStorage.setItem(key, tok); } catch (e) {} }""",
        [SESSION_TOKEN_KEY, token],
    )
    return data


def current_principal(page, base_url: str) -> dict:
    """GET /sovereign/api/whoami with the page's current credentials (token-optional).

    Used to confirm an authenticated principal after seeding the session, or to
    read the owner token the page already carries (data-token / VIGIL_CFG.token).
    """
    return page.evaluate(
        """async ([url, key]) => {
            let tok = "";
            try { tok = sessionStorage.getItem(key) || ""; } catch (e) {}
            if (!tok && window.VIGIL_CFG && window.VIGIL_CFG.token) tok = window.VIGIL_CFG.token;
            const headers = { "X-Requested-With": "vigil-ui" };
            if (tok) headers["X-SIGIL-Token"] = tok;
            const r = await fetch(url, { credentials: "same-origin", headers });
            try { return await r.json(); } catch (e) { return {}; }
        }""",
        [base_url.rstrip("/") + WHOAMI_PATH, SESSION_TOKEN_KEY],
    )
