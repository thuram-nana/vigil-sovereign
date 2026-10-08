"""Smoke test: load :8770, authenticate, navigate ONE screen, assert ONE GET fired.

This is the end-to-end proof that the harness works: a real Chromium loads the
real UI through the uiproxy, a real session is established, a screen renders, and
a real backend GET is observed at the network layer (not "the DOM changed").

Marked `real_flow`: it only reads (status/snapshot) and touches no destructive
control and no external host.
"""
from __future__ import annotations

import pytest

from helpers import assert_calls
from screens import BY_ID


@pytest.mark.real_flow
def test_smoke_authenticates_and_renders_home(authed_page, base_url):
    page = authed_page

    # The shell mounts #main > #screen (app.js setupShell). Its presence is the
    # minimal "the SPA booted and rendered" signal.
    page.wait_for_selector("#screen", timeout=15_000)

    # Navigate to System and assert the readiness GET actually fires. /offense/api/status
    # is a zero-arg read route (console server.py _EXACT_ROUTES:143) reached via the
    # uiproxy /offense/* -> console mapping.
    with assert_calls(page, "GET", "/offense/api/status"):
        page.evaluate("location.hash = '#/system'")

    # And the sovereign snapshot the home/topbar reads (sigil server.py:443).
    with assert_calls(page, "GET", "/sovereign/api/snapshot"):
        page.evaluate("location.hash = '#/home'")

    # Sanity: the smoke target screen is a known screen in the matrix.
    assert "system" in BY_ID and "home" in BY_ID


@pytest.mark.real_flow
def test_smoke_status_endpoint_reachable(authed_page, base_url):
    """A direct same-origin GET /offense/api/status returns 2xx under the session.

    Cross-checks that the authenticated carrier (X-SIGIL-Token) actually reaches
    the console through the proxy — independent of any button.
    """
    page = authed_page
    result = page.evaluate(
        """async ([url, key]) => {
            let tok = "";
            try { tok = sessionStorage.getItem(key) || ""; } catch (e) {}
            if (!tok && window.VIGIL_CFG && window.VIGIL_CFG.token) tok = window.VIGIL_CFG.token;
            const headers = { "X-Requested-With": "vigil-ui" };
            if (tok) headers["X-SIGIL-Token"] = tok;
            const r = await fetch(url, { credentials: "same-origin", headers });
            return { status: r.status };
        }""",
        [base_url + "/offense/api/status", "vigil.session.token"],
    )
    assert 200 <= result["status"] < 300, f"/offense/api/status -> {result['status']}"
