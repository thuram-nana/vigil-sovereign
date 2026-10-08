"""Pytest + Playwright fixtures for the VIGIL browser E2E harness.

Isolation (FATAL-2): this file and everything under tests/e2e/ import ONLY the
playwright client, pytest, and stdlib. Never `framework`, never `strix`, never a
sovereign package. The harness is a network client of http://127.0.0.1:8770.

The `page`/`context`/`browser` fixtures come from pytest-playwright (pinned in
requirements-e2e.txt). `base_url` (below) is consumed by pytest-playwright for
relative `page.goto`, and is where the stack is reached.
"""
from __future__ import annotations

import os

import pytest

from helpers import current_principal, login_via_api

DEFAULT_BASE_URL = "http://127.0.0.1:8770"   # loopback-only, uiproxy


def pytest_configure(config):
    """Register the two mandatory discipline markers (README §7).

    real_flow   -- full detection/proof/read flows run FOR REAL, only ever against
                   the MERIDIAN loopback range (:19010) and the stack's own read
                   APIs. Never a third party, never production.
    assert_gate -- destructive/offense controls (panic, kill-switch,
                   destruction-quorum, live-target, weaponized offense). NEVER
                   fired. The test asserts the GATE ENGAGES (ceremony/approval/
                   confirm demanded, action blocked without it).
    """
    config.addinivalue_line(
        "markers",
        "real_flow: safe flow executed for real against the MERIDIAN loopback "
        "range (:19010) / stack read APIs",
    )
    config.addinivalue_line(
        "markers",
        "assert_gate: destructive/offense control — NEVER fired; assert the "
        "gate/ceremony/approval engages and blocks without it",
    )


@pytest.fixture(scope="session")
def base_url() -> str:
    """Where the unified UI (uiproxy) is reached. Loopback by default.

    pytest-playwright consumes this fixture for relative navigation, and the
    harness uses it to build absolute API URLs. Override with VIGIL_E2E_BASE_URL;
    it must remain a loopback/authorized host.
    """
    return os.environ.get("VIGIL_E2E_BASE_URL", DEFAULT_BASE_URL).rstrip("/")


@pytest.fixture
def e2e_token() -> str | None:
    """The owner bearer the parent/CI provides (the token `vigil up` printed).

    When absent, `authed_page` falls back to whatever the page already carries
    (the owner data-token when running directly on the host).
    """
    tok = os.environ.get("VIGIL_E2E_TOKEN", "").strip()
    return tok or None


@pytest.fixture
def authed_page(page, base_url: str, e2e_token: str | None):
    """A Playwright page with an authenticated VIGIL session.

    Reproduces the SPA bootstrap grounded in app.js renderLoginGate:333 and
    sigil server.py _login:
      1. Navigate to base_url so same-origin fetch + the injected data-token are
         available.
      2. If VIGIL_E2E_TOKEN is set, POST /sovereign/api/login {token} and, on
         `authenticated`, seed sessionStorage["vigil.session.token"] exactly as
         V.setSessionToken does.
      3. Otherwise fall back to the page's existing credential (owner data-token /
         VIGIL_CFG.token) and verify it via /sovereign/api/whoami.
    Fails loudly if no authenticated principal is obtained — an unauthenticated
    run never silently passes.
    """
    # The unified Command UI is served at "/" (uiproxy route() -> None -> static,
    # assemble_serve_dir). "/sovereign/" proxies to the sigil cockpit's OWN standalone
    # SPA and the proxy BLANKS the relayed data-token (uiproxy.py:293,1945) -> load "/".
    page.goto(base_url + "/", wait_until="domcontentloaded")

    if e2e_token:
        principal = login_via_api(page, base_url, e2e_token)
    else:
        principal = current_principal(page, base_url)
        if not principal.get("authenticated"):
            pytest.fail(
                "no VIGIL_E2E_TOKEN provided and the page carries no authenticated "
                "owner token (data-token); cannot establish a session"
            )

    assert principal.get("authenticated"), f"authentication failed: {principal!r}"
    # Reload so the SPA boots with the seeded session and renders as the logged-in
    # principal (nav/permission gating reflects whoami).
    page.goto(base_url + "/#/home", wait_until="domcontentloaded")
    return page
