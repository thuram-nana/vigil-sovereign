"""Slice S1 — per-action RBAC inside the offense console.

The `vigil up` proxy is the per-user auth boundary: it resolves the caller against the sovereign accounts
spine and STAMPS `X-VIGIL-Role` on the offense hop, bound under a per-run hop secret it shares ONLY with
the console child (`VIGIL_CONSOLE_HOP_KEY`). This suite drives the console HTTP surface directly and proves
`do_POST` enforces `role_can(stamped_role, required)` per route:

  * a viewer-stamped (validly HMAC'd) POST to an OWNER route → 403;
  * an operator-stamped (validly HMAC'd) POST to an operator route → reaches the handler (not 403);
  * an owner-stamped POST to an owner route → reaches the handler (not 403);
  * a FORGED `X-VIGIL-Role: owner` WITHOUT a valid HMAC → 403 (never lifts the role);
  * a request with NO hop headers but a valid console token → FULL access (direct token-holder = owner-
    equivalent; the no-regression path);
  * an UNMAPPED POST route WITH a valid hop assertion → default-deny 403 (even for owner);
  * FATAL-2: importing `console.server` co-loads no `sigil.*`.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Generator
from contextlib import contextmanager

import pytest

from framework.v2.console import server

from .conftest import CONSOLE_TEST_TOKEN

HOP_KEY = "hop-key-test-9f8e7d6c5b4a"

# A concrete route from each tier (see vigil_core.rbac.OFFENSE_ACTION_PERM).
OWNER_ROUTE = "/api/authority/provision"           # offense_authority (owner-only) — genuine owner route
OPERATOR_ROUTE = "/api/terminal/dryrun"            # run_engagement (operator+), no filesystem setup needed
KILLSWITCH_ROUTE = "/api/killswitch/testslug/trip" # read-tier — protective emergency-stop (viewer+ may halt)
UNMAPPED_ROUTE = "/api/launch/scan"                # not in the map → default-deny
LAUNCH_PREVIEW_ROUTE = "/api/launch/preview"        # operator-tier preflight (mirrors sibling launches)


@pytest.fixture(autouse=True)
def _pin_hop_key(monkeypatch: pytest.MonkeyPatch) -> Generator[None, None, None]:
    """Pin the console's hop secret so the test can forge the SAME HMAC the proxy would. Read at serve()
    time by `_resolve_hop_key`, so it must be set before `_running` builds the server."""
    monkeypatch.setenv("VIGIL_CONSOLE_HOP_KEY", HOP_KEY)
    yield


@contextmanager
def _running():
    httpd = server.serve(host="127.0.0.1", port=0)
    port = httpd.server_address[1]
    th = threading.Thread(target=httpd.serve_forever, daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        th.join(timeout=5)


def _hop_headers(role: str, path: str, *, principal: str = "alice", hop_key: str = HOP_KEY,
                 ts: str | None = None, method: str = "POST") -> dict:
    """Build the exact identity headers the proxy stamps: principal/role + the HMAC over
    `principal\\nrole\\nmethod\\npath\\nts` under the hop key + the ts."""
    ts = ts if ts is not None else str(int(time.time()))
    msg = f"{principal}\n{role}\n{method}\n{path}\n{ts}".encode("utf-8")
    sig = base64.b64encode(hmac.new(hop_key.encode("utf-8"), msg, hashlib.sha256).digest()).decode("ascii")
    return {"X-VIGIL-Principal": principal, "X-VIGIL-Role": role,
            "X-VIGIL-Role-Sig": sig, "X-VIGIL-Role-Ts": ts}


def _post(base: str, path: str, *, extra_headers: dict | None = None, token: str = CONSOLE_TEST_TOKEN):
    req = urllib.request.Request(base + path, method="POST", data=b"{}")
    req.add_header("X-Requested-With", "vigil-ui")     # the same-origin custom header the SPA sets
    if token:
        req.add_header("X-SIGIL-Token", token)         # the shared console credential
    for k, v in (extra_headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310 (loopback test)
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


# --- the six enforcement scenarios --------------------------------------------------------------
def test_viewer_stamped_post_to_owner_route_is_forbidden():
    with _running() as base:
        st = _post(base, OWNER_ROUTE, extra_headers=_hop_headers("viewer", OWNER_ROUTE))
        assert st == 403


def test_operator_stamped_post_to_operator_route_reaches_handler():
    # operator carries run_engagement → the RBAC gate passes; any non-403 status means it reached the
    # handler (the point is that auth did NOT refuse it).
    with _running() as base:
        st = _post(base, OPERATOR_ROUTE, extra_headers=_hop_headers("operator", OPERATOR_ROUTE))
        assert st != 403, f"operator on an operator route must pass RBAC, got {st}"


def test_operator_stamped_post_to_launch_preview_reaches_handler():
    # W17-9: /api/launch/preview is operator-tier (run_engagement), matching its sibling launch endpoints.
    # A per-user proxied OPERATOR carries run_engagement → the RBAC gate passes (any non-403 = it reached
    # the read-only handler). Regression guard: the preflight must never be silently default-denied for a
    # legitimate operator now that it is mapped.
    with _running() as base:
        st = _post(base, LAUNCH_PREVIEW_ROUTE,
                   extra_headers=_hop_headers("operator", LAUNCH_PREVIEW_ROUTE))
        assert st != 403, f"operator on the launch-preview route must pass RBAC, got {st}"


def test_analyst_stamped_post_to_launch_preview_is_forbidden():
    # the other half: a per-user proxied principal WITHOUT run_engagement (analyst/viewer) is refused on
    # the preview route — it is NOT silently (un)authorized. Mirrors the sibling-launch RBAC exactly.
    with _running() as base:
        for role in ("analyst", "viewer"):
            st = _post(base, LAUNCH_PREVIEW_ROUTE,
                       extra_headers=_hop_headers(role, LAUNCH_PREVIEW_ROUTE))
            assert st == 403, f"{role} lacking run_engagement must be refused on launch-preview, got {st}"


def test_operator_stamped_post_to_owner_route_is_forbidden():
    # the sharp per-action distinction the coarse proxy floor cannot make: operator+ but NOT owner.
    with _running() as base:
        st = _post(base, OWNER_ROUTE, extra_headers=_hop_headers("operator", OWNER_ROUTE))
        assert st == 403


def test_owner_stamped_post_to_owner_route_reaches_handler():
    with _running() as base:
        st = _post(base, OWNER_ROUTE, extra_headers=_hop_headers("owner", OWNER_ROUTE))
        assert st != 403, f"owner on an owner route must pass RBAC, got {st}"


def test_viewer_may_trip_the_killswitch_protective_emergency_stop():
    # the emergency-stop is read-tier (mirrors sovereign `kill: read`): a viewer's VALID hop assertion must
    # NOT be refused for tripping the kill-switch — halting is protective and must be broadly available, never
    # gated above the operator watching a live engagement. (Regression guard for the killswitch privilege
    # inversion: killswitch-trip must never be owner-tier.)
    with _running() as base:
        st = _post(base, KILLSWITCH_ROUTE, extra_headers=_hop_headers("viewer", KILLSWITCH_ROUTE))
        assert st != 403, f"viewer must be allowed to trip the protective kill-switch, got {st}"


def test_forged_owner_role_without_valid_hmac_does_not_lift_the_role():
    with _running() as base:
        # a bare, unsigned X-VIGIL-Role: owner (an attacker who guesses the header name but lacks the key)
        st = _post(base, OWNER_ROUTE, extra_headers={"X-VIGIL-Role": "owner"})
        assert st == 403
        # a role WITH a signature computed under the WRONG key is likewise refused
        bad = _hop_headers("owner", OWNER_ROUTE, hop_key="not-the-real-hop-key")
        assert _post(base, OWNER_ROUTE, extra_headers=bad) == 403
        # a role with a STALE timestamp (outside the freshness window) is refused
        stale = _hop_headers("owner", OWNER_ROUTE, ts=str(int(time.time()) - 120))
        assert _post(base, OWNER_ROUTE, extra_headers=stale) == 403
        # a valid signature bound to a DIFFERENT path cannot be re-aimed at the owner route
        wrong_path = _hop_headers("owner", "/api/terminal/dryrun")
        assert _post(base, OWNER_ROUTE, extra_headers=wrong_path) == 403


def test_no_hop_headers_but_valid_token_keeps_full_access():
    # the direct token-holder (on-host operator / legacy client): no X-VIGIL-* headers at all → owner-
    # equivalent, full access. Both an operator-tier and an owner-tier route must be reachable (not 403).
    with _running() as base:
        assert _post(base, OPERATOR_ROUTE) != 403
        assert _post(base, OWNER_ROUTE) != 403


def test_unmapped_route_with_valid_hop_assertion_is_default_deny():
    # even an owner stamp cannot pass an UNMAPPED route — fail-closed. (A direct token-holder, by contrast,
    # would reach the 404 'unknown action' — that is the no-regression path, covered above.)
    with _running() as base:
        st = _post(base, UNMAPPED_ROUTE, extra_headers=_hop_headers("owner", UNMAPPED_ROUTE))
        assert st == 403


def test_console_with_no_hop_key_refuses_any_stamped_role_but_allows_direct_token(monkeypatch):
    # fail-closed: a console started WITHOUT a hop key cannot verify any stamped role, so a proxy-style
    # request is refused — but the direct token-holder path still works (no regression).
    monkeypatch.delenv("VIGIL_CONSOLE_HOP_KEY", raising=False)
    with _running() as base:
        assert _post(base, OPERATOR_ROUTE, extra_headers=_hop_headers("operator", OPERATOR_ROUTE)) == 403
        assert _post(base, OPERATOR_ROUTE) != 403          # direct token-holder still allowed


# --- FATAL-2 ------------------------------------------------------------------------------------
def test_importing_console_server_loads_no_sigil():
    __import__("framework.v2.console.server")
    leaked = [m for m in sys.modules if m == "sigil" or m.startswith("sigil.")]
    assert not leaked, f"FATAL-2: offense console co-loaded sovereign modules {leaked}"
