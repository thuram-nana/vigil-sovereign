"""AS-29 — ENFORCE RELEASE's edge write path (release into / stand-down from enforce), over the REAL edge -> cockpit hop.

The Monitoring settings screen's Release to enforce moves a host from the always-safe Observe base into enforce
(Respond) by reusing the EXISTING monitoring/authorize action in the enforce mode ("block") with NO window_s. AS-2k's
edge suite pins the SHORTEN direction (window_s only ever shortens) and AS-21a's pins the RENEW direction (no window_s
renews to full, never beyond the cap); this pins the RELEASE direction end to end — the enforce-release contract AS-29
adds:

* Releasing an armed Observe host to enforce (authorize {host, mode: "block"}, no window_s) flips the mode to enforce
  AND keeps the armed window BOUNDED by the server ceiling (config.MONITORING_WINDOW_SECONDS, clamped to the plan
  period) — never extended beyond it, even from a shortened window — and the release is REVERSIBLE (authorize back to
  observe stands the host down).
* Enforce is RELEASE-GATED by the Respond entitlement: a workspace on an Observe-only plan cannot release a host to
  enforce (403, "respond"); Observe is the always-safe base and never needs a release.
* The org is the SESSION's, never a body field: a body org_id cannot aim a release at another workspace.
* With VIGIL_CUSTOMER_MONITORING_ENABLED off, the authorize-to-enforce write is an unknown route (404) and nothing is
  published — exactly like every other monitoring route (AS-2f/AS-2g/AS-2k/AS-21a).
"""
from __future__ import annotations

from test_custui import _scrub_shared_owner_state  # noqa: F401  (autouse: keep the shared SIGIL_HOME pristine)
from test_custui import _get, _opener, _post, _stack
from test_customer_monitoring_hop import _aegis_plan, _iss, _mon_env, _prove, _signup  # noqa: F401  (_mon_env autouse)

from sigil import config

_WINDOW = config.MONITORING_WINDOW_SECONDS       # the SERVER-decided ceiling; a release renews to it, never beyond


def _grant(op, ep, host: str) -> dict:
    c, d = _get(op, ep, "/api/customer/monitoring")
    assert c == 200, (c, d)
    for g in d["grants"]:
        if g["host"] == host:
            return g
    raise AssertionError(f"no grant for {host} in {d['grants']}")


def test_releasing_an_observe_host_to_enforce_flips_the_mode_and_stays_bounded_and_is_reversible(tmp_path, monkeypatch):
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        a = _signup(op, ep, "admin@acme.com", "Acme")
        org, host = a["org_id"], "shop.acme.example"
        _prove(sov.store(), org, host)
        _aegis_plan(sov.store(), org)                                # aegis_respond_5h: block allowed, period ~30d
        # the host is first armed in the always-safe OBSERVE base, with a SHORTENED window (AS-2k): ~3600s.
        c, r = _post(op, ep, "/api/customer/monitoring/authorize",
                     {"host": host, "mode": "observe", "window_s": 3600})
        assert c == 200, (c, r)
        obs = _grant(op, ep, host)
        assert obs["mode"] == "observe"
        assert abs((obs["not_after"] - obs["not_before"]) - 3600.0) < 2.0, obs
        # RELEASE TO ENFORCE: the SAME action in the enforce mode ("block") with NO window_s. The mode flips to enforce
        # and the window renews to the full server window — bounded by the server ceiling, never beyond it.
        c, r = _post(op, ep, "/api/customer/monitoring/authorize", {"host": host, "mode": "block"})
        assert c == 200 and (r["org_id"], r["host"], r["mode"]) == (org, host, "block"), (c, r)
        enf = _grant(op, ep, host)
        assert enf["mode"] == "block"                               # now enforcing (Respond)
        span = enf["not_after"] - enf["not_before"]
        assert span > 20 * 86400.0, (span, enf)                     # renewed up from the shortened 3600s
        assert span <= _WINDOW + 2.0, (span, enf)                   # but NEVER beyond the server ceiling (bounded)
        # REVERSIBLE: standing the host back down to Observe is the same action in observe mode.
        c, r = _post(op, ep, "/api/customer/monitoring/authorize", {"host": host, "mode": "observe"})
        assert c == 200 and r["mode"] == "observe", (c, r)
        assert _grant(op, ep, host)["mode"] == "observe"
    finally:
        sov.shutdown(); edge.shutdown()


def test_enforce_release_needs_the_respond_entitlement(tmp_path, monkeypatch):
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        a = _signup(op, ep, "admin@acme.com", "Acme")
        org, host = a["org_id"], "app.acme.example"
        _prove(sov.store(), org, host)
        _aegis_plan(sov.store(), org, "aegis_observe_1h")           # an Observe-only plan: respond NOT entitled
        # the host is armed in Observe (the always-safe base, no release needed).
        assert _post(op, ep, "/api/customer/monitoring/authorize", {"host": host, "mode": "observe"})[0] == 200
        # a release to enforce is REFUSED without the Respond entitlement, and the host stays in Observe (unchanged).
        c, r = _post(op, ep, "/api/customer/monitoring/authorize", {"host": host, "mode": "block"})
        assert c == 403 and "respond" in r["error"], (c, r)
        assert _grant(op, ep, host)["mode"] == "observe"
    finally:
        sov.shutdown(); edge.shutdown()


def test_a_release_is_scoped_to_the_session_org_never_a_body_field(tmp_path, monkeypatch):
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        aop, bop = _opener(), _opener()
        a = _signup(aop, ep, "a@acme.com", "Acme")
        b = _signup(bop, ep, "b@beta.com", "Beta")
        store = sov.store()
        for org, host in ((a["org_id"], "shop.acme.example"), (b["org_id"], "www.beta.example")):
            _prove(store, org, host)
            _aegis_plan(store, org)                                 # both hold a Respond plan
        # A arms its host in Observe, so a successful release would be visible as a mode flip to enforce.
        assert _post(aop, ep, "/api/customer/monitoring/authorize",
                     {"host": "shop.acme.example", "mode": "observe"})[0] == 200
        # B releases-to-enforce with a body org_id aimed at A's host: the edge scopes org from B's session, so it only
        # ever touches B's own workspace — A's grant is untouched, and B cannot release A's host (B holds no proof of it).
        c, r = _post(bop, ep, "/api/customer/monitoring/authorize",
                     {"host": "shop.acme.example", "mode": "block", "org_id": a["org_id"]})
        assert c == 403 and "ownership" in r["error"], (c, r)
        assert _grant(aop, ep, "shop.acme.example")["mode"] == "observe"   # A's host is still in Observe (not released)
    finally:
        sov.shutdown(); edge.shutdown()


def test_with_the_flag_off_the_release_write_is_an_unknown_route(tmp_path, monkeypatch):
    monkeypatch.delenv("VIGIL_CUSTOMER_MONITORING_ENABLED")
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        _signup(op, ep, "off@acme.com", "Off")
        unknown = _post(op, ep, "/api/customer/no/such", {"host": "acme.example"})
        assert unknown[0] == 404
        got = _post(op, ep, "/api/customer/monitoring/authorize", {"host": "acme.example", "mode": "block"})
        assert got == unknown                                       # byte-identical to any unknown route
        assert not (tmp_path / "published").exists()                # nothing was ever published
    finally:
        sov.shutdown(); edge.shutdown()
