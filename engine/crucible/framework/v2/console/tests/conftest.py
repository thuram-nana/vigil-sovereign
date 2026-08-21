"""Console test fixtures.

The Ops Console now requires a SESSION TOKEN on every ``/api/*`` request (the audit gap: it
previously had no credential at all). ``server.serve()`` mints one unless ``$VIGIL_CONSOLE_TOKEN``
supplies it, so the HTTP-level tests pin a known value here and present it as the ``X-SIGIL-Token``
header (or ``?token=`` for the SSE / download carriers that cannot set a header).

This does NOT relax the check — every request in these tests goes through the same constant-time
comparison a browser's does; the tests simply hold the credential the operator's browser holds.
``test_auth.py`` covers the negative side (no token / wrong token / token-free static bootstrap).
"""

from __future__ import annotations

from collections.abc import Generator

import pytest

CONSOLE_TEST_TOKEN = "console-test-token-a1b2c3"

#: the header a same-origin fetch presents (the sovereign cockpit's carrier, reused)
AUTH_HEADERS = {"X-SIGIL-Token": CONSOLE_TEST_TOKEN}


@pytest.fixture(autouse=True)
def _pin_console_token(monkeypatch: pytest.MonkeyPatch) -> Generator[None, None, None]:
    """Pin the console's session token for the whole console suite so the HTTP helpers can present
    it. Autouse + monkeypatch, so nothing leaks into another suite's environment."""
    monkeypatch.setenv("VIGIL_CONSOLE_TOKEN", CONSOLE_TEST_TOKEN)
    yield


def auth_url(url: str) -> str:
    """Append the token as a query parameter — the carrier EventSource / a download navigation must
    use, since neither can set a request header."""
    sep = "?" if "?" not in url else "&"
    return f"{url}{sep}token={CONSOLE_TEST_TOKEN}"

@pytest.fixture(autouse=True)
def _healthy_strix_sandbox_gate(monkeypatch):
    """S2: pretend the VIGIL egress gateway is up, so console tests exercise CONSOLE behaviour.

    A Strix launch now refuses unless the gateway container is running and the gated sandbox network
    exists, and it pins the sandbox onto that network. That is correct — before it, every sandbox was
    created on Docker's default bridge — but it makes every console launch test depend on live Docker,
    which they must not.

    So these tests get a healthy gate. The gate itself is NOT stubbed out of existence: its refusals, its
    override, its fail-closed behaviour and the fact that BOTH spawn sites consult it are covered by
    integration/tests/test_strix_sandbox_gate.py and by invariant 2 in
    integration/tests/test_production_invariants.py. A test here that wants the refusal path should
    monkeypatch this back.
    """
    try:
        from framework.v2.console import actions as _actions
    except Exception:  # pragma: no cover - console not importable in this leg
        return
    if hasattr(_actions, "_strix_sandbox_gate"):
        monkeypatch.setattr(
            _actions, "_strix_sandbox_gate",
            lambda: ({"STRIX_DOCKER_SANDBOX_NETWORK": "vigil_sandbox"}, "", ""))
