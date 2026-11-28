"""AS-21a — the RETEST GUARD's edge write path (re-arm / renew), over the REAL edge -> cockpit hop.

The Monitoring settings screen's Re-arm renews a host's armed window back to VIGIL's full standard window by reusing
the EXISTING monitoring/authorize action with NO window_s. AS-2k's edge suite pins the SHORTEN direction (window_s
only ever shortens); this pins the RENEW direction end to end — the re-arm contract AS-21a adds:

* After a host's window has been SHORTENED, Re-arm (authorize with no window_s) renews not_after back out to the full
  server window (never beyond it — the sovereign cap, clamped to the plan period), in the host's mode, SESSION-scoped.
* The renew is never LONGER than the server ceiling: a re-arm cannot lengthen the armed window past what the owner
  decided, even though it resets it to full.
* The org is the SESSION's, never a body field: a body org_id cannot aim a re-arm at another workspace.
* With VIGIL_CUSTOMER_MONITORING_ENABLED off, the authorize-without-window write is an unknown route (404) and
  nothing is published — exactly like every other monitoring route (AS-2f/AS-2g/AS-2k).
"""
from __future__ import annotations

from test_custui import _scrub_shared_owner_state  # noqa: F401  (autouse: keep the shared SIGIL_HOME pristine)
from test_custui import _get, _opener, _post, _stack
from test_customer_monitoring_hop import _aegis_plan, _iss, _mon_env, _prove, _signup  # noqa: F401  (_mon_env autouse)

from sigil import config

_WINDOW = config.MONITORING_WINDOW_SECONDS       # the SERVER-decided ceiling; a re-arm renews to it, never beyond


def _grant(op, ep, host: str) -> dict:
    c, d = _get(op, ep, "/api/customer/monitoring")
    assert c == 200, (c, d)
    for g in d["grants"]:
        if g["host"] == host:
            return g
    raise AssertionError(f"no grant for {host} in {d['grants']}")


def test_rearming_renews_a_shortened_window_back_to_full_over_the_hop(tmp_path, monkeypatch):
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        a = _signup(op, ep, "admin@acme.com", "Acme")
        org, host = a["org_id"], "shop.acme.example"
        _prove(sov.store(), org, host)
        _aegis_plan(sov.store(), org)                                # aegis_respond_5h: block allowed, period ~30d
        # the settings screen first SHORTENS the window to one hour (AS-2k): the host is armed for ~3600s.
        c, r = _post(op, ep, "/api/customer/monitoring/authorize",
                     {"host": host, "mode": "observe", "window_s": 3600})
        assert c == 200, (c, r)
        short = _grant(op, ep, host)
        assert abs((short["not_after"] - short["not_before"]) - 3600.0) < 2.0, short
        # now Re-arm: the SAME action with NO window_s renews it back to the full server window, same mode.
        c, r = _post(op, ep, "/api/customer/monitoring/authorize", {"host": host, "mode": "observe"})
        assert c == 200 and (r["org_id"], r["host"], r["mode"]) == (org, host, "observe"), (c, r)
        g = _grant(op, ep, host)
        span = g["not_after"] - g["not_before"]
        assert span > 20 * 86400.0, (span, g)                       # renewed to ~the full standard window, not 3600s
        assert span <= _WINDOW + 2.0, (span, g)                     # but NEVER beyond the server ceiling
        assert g["not_after"] > short["not_after"]                  # strictly later than the shortened window
    finally:
        sov.shutdown(); edge.shutdown()


def test_a_rearm_is_scoped_to_the_session_org_never_a_body_field(tmp_path, monkeypatch):
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        aop, bop = _opener(), _opener()
        a = _signup(aop, ep, "a@acme.com", "Acme")
        b = _signup(bop, ep, "b@beta.com", "Beta")
        store = sov.store()
        for org, host in ((a["org_id"], "shop.acme.example"), (b["org_id"], "www.beta.example")):
            _prove(store, org, host)
            _aegis_plan(store, org)
        # A arms its host with a SHORT window, so a successful re-arm would be visible as a longer window.
        assert _post(aop, ep, "/api/customer/monitoring/authorize",
                     {"host": "shop.acme.example", "mode": "observe", "window_s": 3600})[0] == 200
        # B re-arms with a body org_id aimed at A's host: the edge scopes org from B's session, so it only ever touches
        # B's own workspace — A's grant is untouched, and B cannot re-arm A's host (B holds no proof of it).
        c, r = _post(bop, ep, "/api/customer/monitoring/authorize",
                     {"host": "shop.acme.example", "mode": "observe", "org_id": a["org_id"]})
        assert c == 403 and "ownership" in r["error"], (c, r)
        g = _grant(aop, ep, "shop.acme.example")                    # A's shortened grant is unchanged (not renewed)
        assert abs((g["not_after"] - g["not_before"]) - 3600.0) < 2.0, g
    finally:
        sov.shutdown(); edge.shutdown()


def test_with_the_flag_off_the_rearm_write_is_an_unknown_route(tmp_path, monkeypatch):
    monkeypatch.delenv("VIGIL_CUSTOMER_MONITORING_ENABLED")
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        _signup(op, ep, "off@acme.com", "Off")
        unknown = _post(op, ep, "/api/customer/no/such", {"host": "acme.example"})
        assert unknown[0] == 404
        got = _post(op, ep, "/api/customer/monitoring/authorize", {"host": "acme.example", "mode": "observe"})
        assert got == unknown                                       # byte-identical to any unknown route
        assert not (tmp_path / "published").exists()                # nothing was ever published
    finally:
        sov.shutdown(); edge.shutdown()
