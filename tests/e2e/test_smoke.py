"""Smoke test: load :8770, authenticate, navigate screens, assert nav-driven GETs fire.

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
def test_smoke_authenticates_and_renders_system_and_users(authed_page, base_url):
    page = authed_page

    # The shell mounts #main > #screen (app.js setupShell). Its presence is the
    # minimal "the SPA booted and rendered" signal.
    page.wait_for_selector("#screen", timeout=15_000)

    # Navigate to System and assert its readiness GET fires at the NETWORK layer.
    # renderSystem (app.js:6399) reads GET /offense/api/services (console server.py:162)
    # on nav; it is on NO setInterval, so only the navigation itself can satisfy this
    # (it fails for the right reason if the nav fired nothing).
    with assert_calls(page, "GET", "/offense/api/services"):
        page.evaluate("location.hash = '#/system'")

    # And a SOVEREIGN-plane nav read, through the /sovereign/* proxy mapping.
    # renderSettings (app.js:4575) reads GET /sovereign/api/settings at the TOP of the
    # render on nav; it is NOT background-polled. We deliberately do NOT assert
    # /sovereign/api/snapshot here: pboxApprovalPoll hits it every 4s (app.js:10937),
    # so a poll would satisfy the match regardless of the action (green-washing).
    # Assert only nav-driven, unpolled reads.
    with assert_calls(page, "GET", "/sovereign/api/settings"):
        page.evaluate("location.hash = '#/settings'")

    # Sanity: the smoke target screens are known screens in the matrix.
    assert "system" in BY_ID and "settings" in BY_ID


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
