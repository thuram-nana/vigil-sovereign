"""AS-2k — the edge write path the Monitoring SETTINGS screen drives, over the REAL edge -> cockpit hop.

The settings screen shortens a host's armed telemetry window by reusing the EXISTING monitoring/authorize action with
a `window_s` (the only monitoring-authority dimension the Monitoring dashboard never exercised). This pins that edge
contract end to end:

* A manager shortens an armed host's window: POST monitoring/authorize {host, mode, window_s} re-mints the authority
  with the SHORTER window (not_after - not_before == window_s), for the SESSION org only.
* The window may only be SHORTENED: a window_s far beyond the server window is capped (never extends past the server
  ceiling), and a non-positive / non-finite / boolean window_s is refused (400) and changes nothing.
* The org is the SESSION's, never a body field: a body org_id cannot aim the window at another workspace.
* With VIGIL_CUSTOMER_MONITORING_ENABLED off, the authorize-with-window write is an unknown route (404) and nothing
  is published — exactly like every other monitoring route (AS-2f/AS-2g).
"""
from __future__ import annotations

import time

import pytest
from test_custui import _scrub_shared_owner_state  # noqa: F401  (autouse: keep the shared SIGIL_HOME pristine)
from test_custui import _get, _opener, _post, _stack
from test_customer_monitoring_hop import _aegis_plan, _iss, _mon_env, _prove, _signup  # noqa: F401  (_mon_env autouse)

from sigil import config

_WINDOW = config.MONITORING_WINDOW_SECONDS       # the SERVER-decided ceiling; window_s may only shorten it


def _grant(op, ep, host: str) -> dict:
    c, d = _get(op, ep, "/api/customer/monitoring")
    assert c == 200, (c, d)
    for g in d["grants"]:
        if g["host"] == host:
            return g
    raise AssertionError(f"no grant for {host} in {d['grants']}")


def test_shortening_the_armed_window_over_the_hop(tmp_path, monkeypatch):
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        a = _signup(op, ep, "admin@acme.com", "Acme")
        org, host = a["org_id"], "shop.acme.example"
        _prove(sov.store(), org, host)
        _aegis_plan(sov.store(), org)                                # aegis_respond_5h: block allowed, period ~30d
        # a full-window grant first (no window_s) — the dashboard's write; its window is ~the server ceiling
        c, r = _post(op, ep, "/api/customer/monitoring/authorize", {"host": host, "mode": "block"})
        assert c == 200, (c, r)
        g0 = _grant(op, ep, host)
        assert g0["mode"] == "block"
        # now the settings screen shortens it: SAME action, with a window_s (3600s). not_after moves IN to +window_s.
        c, r = _post(op, ep, "/api/customer/monitoring/authorize",
                     {"host": host, "mode": "block", "window_s": 3600})
        assert c == 200 and (r["org_id"], r["host"], r["mode"]) == (org, host, "block"), (c, r)
        g = _grant(op, ep, host)
        assert abs((g["not_after"] - g["not_before"]) - 3600.0) < 2.0, g       # armed for exactly the asked window
        assert g["not_after"] < g0["not_after"]                                # strictly shorter than the full window
    finally:
        sov.shutdown(); edge.shutdown()


def test_the_window_can_only_be_shortened_never_extended(tmp_path, monkeypatch):
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        a = _signup(op, ep, "admin@acme.com", "Acme")
        org, host = a["org_id"], "shop.acme.example"
        _prove(sov.store(), org, host)
        _aegis_plan(sov.store(), org)
        # a window_s far beyond the server ceiling is CAPPED at the ceiling (or the plan period, whichever is first) —
        # it never extends the armed window past what the owner decided.
        huge = _WINDOW * 100
        c, r = _post(op, ep, "/api/customer/monitoring/authorize",
                     {"host": host, "mode": "observe", "window_s": huge})
        assert c == 200, (c, r)
        g = _grant(op, ep, host)
        assert (g["not_after"] - g["not_before"]) <= _WINDOW + 2.0, g         # capped, never extended
        # a non-positive / non-finite / boolean window_s is refused (ProvisionError -> 400) and changes nothing
        for bad in (0, -5, "lots", True):
            c, r = _post(op, ep, "/api/customer/monitoring/authorize",
                         {"host": host, "mode": "observe", "window_s": bad})
            assert c == 400, (bad, c, r)
    finally:
        sov.shutdown(); edge.shutdown()


def test_window_s_is_scoped_to_the_session_org_never_a_body_field(tmp_path, monkeypatch):
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        aop, bop = _opener(), _opener()
        a = _signup(aop, ep, "a@acme.com", "Acme")
        b = _signup(bop, ep, "b@beta.com", "Beta")
        store = sov.store()
        for org, host in ((a["org_id"], "shop.acme.example"), (b["org_id"], "www.beta.example")):
            _prove(store, org, host)
            _aegis_plan(store, org)
        assert _post(aop, ep, "/api/customer/monitoring/authorize", {"host": "shop.acme.example"})[0] == 200
        # B shortens with a body org_id aimed at A's host: the edge scopes org from B's session, so it only ever
        # touches B's own workspace — A's grant is untouched, and B cannot arm A's host (B holds no proof of it).
        c, r = _post(bop, ep, "/api/customer/monitoring/authorize",
                     {"host": "shop.acme.example", "mode": "observe", "window_s": 60, "org_id": a["org_id"]})
        assert c == 403 and "ownership" in r["error"], (c, r)
        g = _grant(aop, ep, "shop.acme.example")                             # A's full-window grant is unchanged
        assert (g["not_after"] - g["not_before"]) > 60.0 + 2.0, g
    finally:
        sov.shutdown(); edge.shutdown()


def test_with_the_flag_off_the_window_write_is_an_unknown_route(tmp_path, monkeypatch):
    monkeypatch.delenv("VIGIL_CUSTOMER_MONITORING_ENABLED")
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        _signup(op, ep, "off@acme.com", "Off")
        unknown = _post(op, ep, "/api/customer/no/such", {"host": "acme.example"})
        assert unknown[0] == 404
        got = _post(op, ep, "/api/customer/monitoring/authorize",
                    {"host": "acme.example", "mode": "observe", "window_s": 3600})
        assert got == unknown                                                # byte-identical to any unknown route
        assert not (tmp_path / "published").exists()                         # nothing was ever published
    finally:
        sov.shutdown(); edge.shutdown()
