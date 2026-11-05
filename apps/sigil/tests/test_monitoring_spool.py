"""AEGIS-SaaS AE-4b — the sovereign drain of gateway monitoring reports + the tenant events read.

Pinned: MAC verified under the (org, host) secret (wrong secret / cross-tenant forgery refused); stale / future
ts refused; no ACTIVE MonitoringAuthorityRegistry grant refused (incl. revoked); content + report_id dedup;
hostile files quarantined (nothing spined); monitoring_events strictly org-scoped; edge GET flag-gated + session org.
"""
from __future__ import annotations

import hashlib
import hmac
import itertools
import json
import os
import re
import tempfile
from pathlib import Path

import pytest

from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.monitoring_authority import MonitoringAuthorityRegistry
from sigil.inbound import monitoring_spool as ms
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
NOW = 1_000_000.0
SECRETS = {("org_a", "apme.cm"): b"A" * 32, ("org_b", "beta.cm"): b"B" * 32}
_n = itertools.count(1)


def _store():
    return SpineStore(os.path.join(tempfile.mkdtemp(), "spine.jsonl"))


def _grant(store, org, host):
    own = AssetOwnershipRegistry(store, owner_key=OWNER, trusted_pubkey=OWNER.public_key_b64)
    ch = own.issue_challenge(org, host, issued_at=NOW - 100)
    own.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=NOW - 99, ttl_seconds=1e9)
    reg = MonitoringAuthorityRegistry(store, owner_key=OWNER, trusted_pubkey=OWNER.public_key_b64)
    reg.grant(org, host, not_before=NOW - 50, not_after=NOW + 1e6, now=NOW - 50)
    return reg


def _rig(grants=(("org_a", "apme.cm"), ("org_b", "beta.cm"))):
    s = _store()
    reg = MonitoringAuthorityRegistry(s, owner_key=OWNER, trusted_pubkey=OWNER.public_key_b64)
    for o, h in grants:
        reg = _grant(s, o, h)
    w = ms.MonitoringSpoolWatcher(s, spool_dir=tempfile.mkdtemp(), secret_for=lambda o, h: SECRETS.get((o, h)),
                                  authority=reg, now_fn=lambda: NOW)
    return s, reg, w


def _report(org="org_a", host="apme.cm", **kw):
    rep = {"schema": ms.REPORT_SCHEMA, "org_id": org, "host": host, "ts": NOW - 10, "decision": "confirmed",
           "attack_class": "sqli", "action": "observe", "confidence": 0.9, "provenance_tier": "certified",
           "certificate_sha256": "c" * 64, "report_id": f"r{next(_n)}"}
    rep.update(kw)
    return rep


def _seal(rep, secret=None):
    body = json.dumps(rep, sort_keys=True, separators=(",", ":"))
    key = secret if secret is not None else SECRETS[(rep["org_id"], rep["host"])]
    mac = hmac.new(key, ms.REPORT_DOMAIN + body.encode(), hashlib.sha256).hexdigest()
    return {"schema": ms.REPORT_SCHEMA, "body": body, "mac": mac}


def _drop(w, env, name=None):
    data = env if isinstance(env, (bytes, str)) else json.dumps(env)
    p = w.incoming / (name or f"{next(_n)}.json")
    (p.write_bytes if isinstance(data, bytes) else p.write_text)(data)
    return p


def _events(s, org):
    return ms.monitoring_events(s, org)


# --- happy path + cross-plane pin -------------------------------------------------------------------------
def test_valid_report_recorded_once_with_metadata_only():
    s, _, w = _rig()
    rep = _report()
    _drop(w, _seal(rep))
    r = w.drain()
    assert (r["recorded"], r["rejected"], r["deduped"]) == (1, 0, 0)
    ev = _events(s, "org_a")
    assert len(ev) == 1 and ev[0]["report_id"] == rep["report_id"] and ev[0]["source_class"] == "gateway_reported"
    assert ev[0]["certificate_sha256"] == "c" * 64
    assert os.listdir(w.incoming) == [] and len(os.listdir(w.processed)) == 1


def test_constants_match_the_gateway_reporter():
    src = (Path(__file__).resolve().parents[3] / "engine/crucible/framework/v2/aegis/monitoring_report.py").read_text()
    assert f'REPORT_SCHEMA = "{ms.REPORT_SCHEMA}"' in src
    assert re.search(r'REPORT_DOMAIN = b"vigil\.aegis\.monitoring-report\.v1\\x00"', src)
    assert ms.REPORT_DOMAIN == b"vigil.aegis.monitoring-report.v1\x00"


# --- MAC per (org, host) --------------------------------------------------------------------------------
def _rejected_one(w, env):
    _drop(w, env)
    r = w.drain()
    assert (r["recorded"], r["rejected"]) == (0, 1), r
    reasons = [f for f in os.listdir(w.rejected) if f.endswith(".reason")]
    return (w.rejected / reasons[-1]).read_text()


def test_wrong_secret_refused():
    s, _, w = _rig()
    assert "MAC" in _rejected_one(w, _seal(_report(), secret=b"Z" * 32))
    assert _events(s, "org_a") == []


def test_tenant_a_cannot_forge_report_for_tenant_b():
    s, _, w = _rig()
    forged = _seal(_report(org="org_b", host="beta.cm"), secret=SECRETS[("org_a", "apme.cm")])
    assert "MAC" in _rejected_one(w, forged)
    assert _events(s, "org_b") == []


def test_secret_is_per_host_not_per_org():
    s, _, w = _rig()
    rep = _report(host="other.cm")
    assert "no report secret" in _rejected_one(w, _seal(rep, secret=SECRETS[("org_a", "apme.cm")]))


def test_tampered_body_refused():
    s, _, w = _rig()
    env = _seal(_report())
    env["body"] = env["body"].replace("sqli", "xss")
    assert "MAC" in _rejected_one(w, env)


def test_short_secret_refused():
    s, reg, _ = _rig()
    w = ms.MonitoringSpoolWatcher(s, spool_dir=tempfile.mkdtemp(), secret_for=lambda o, h: b"short",
                                  authority=reg, now_fn=lambda: NOW)
    assert "no report secret" in _rejected_one(w, _seal(_report(), secret=b"short"))


# --- freshness ------------------------------------------------------------------------------------------
@pytest.mark.parametrize("ts", [NOW - 7 * 24 * 3600 - 1, NOW + 301, "nope", None])
def test_stale_future_or_unreadable_ts_refused(ts):
    s, _, w = _rig()
    assert re.search("stale|timestamp", _rejected_one(w, _seal(_report(ts=ts))))
    assert _events(s, "org_a") == []


@pytest.mark.parametrize("ts", [NOW - 7 * 24 * 3600, NOW + 300])
def test_freshness_boundaries_accepted(ts):
    s, _, w = _rig()
    _drop(w, _seal(_report(ts=ts)))
    assert w.drain()["recorded"] == 1


def test_non_reportable_decision_refused():
    s, _, w = _rig()
    assert "decision" in _rejected_one(w, _seal(_report(decision="benign")))


# --- authority -----------------------------------------------------------------------------------------
def test_no_grant_refused():
    s, _, w = _rig(grants=(("org_b", "beta.cm"),))
    assert "authority" in _rejected_one(w, _seal(_report()))


def test_revoked_grant_refused():
    s, reg, w = _rig()
    reg.revoke("org_a", "apme.cm")
    assert "authority" in _rejected_one(w, _seal(_report()))


def test_constructor_requires_resolver_and_registry():
    with pytest.raises(ValueError):
        ms.MonitoringSpoolWatcher(_store(), spool_dir=tempfile.mkdtemp(), secret_for=None, authority=object())
    with pytest.raises(ValueError):
        ms.MonitoringSpoolWatcher(_store(), spool_dir=tempfile.mkdtemp(), secret_for=lambda o, h: None,
                                  authority=None)


# --- dedup --------------------------------------------------------------------------------------------
def test_identical_file_deduped():
    s, _, w = _rig()
    env = _seal(_report())
    _drop(w, env)
    assert w.drain()["recorded"] == 1
    _drop(w, env)
    r = w.drain()
    assert (r["recorded"], r["deduped"]) == (0, 1)
    assert len(_events(s, "org_a")) == 1


def test_same_report_id_reencoded_shows_once():
    s, _, w = _rig()
    rep = _report()
    _drop(w, _seal(rep))
    env2 = _seal(rep)
    env2 = json.dumps(env2, indent=1)          # different bytes, same report
    _drop(w, env2)
    assert w.drain()["recorded"] == 2
    assert len(_events(s, "org_a")) == 1


# --- hostile files ----------------------------------------------------------------------------------
@pytest.mark.parametrize("payload", [b"\xff\xfe", b"x" * (16 * 1024 + 1), b"not json", b"[]",
                                     json.dumps({"schema": "other"}).encode(),
                                     json.dumps({"schema": ms.REPORT_SCHEMA, "body": "", "mac": ""}).encode(),
                                     json.dumps({"schema": ms.REPORT_SCHEMA, "body": "{", "mac": "a"}).encode()])
def test_hostile_files_quarantined(payload):
    s, _, w = _rig()
    _drop(w, payload)
    r = w.drain()
    assert (r["recorded"], r["rejected"]) == (0, 1)
    assert any(f.endswith(".reason") for f in os.listdir(w.rejected))
    assert _events(s, "org_a") == [] and os.listdir(w.working) == []


def test_symlink_and_fifo_quarantined():
    s, _, w = _rig()
    real = Path(tempfile.mkdtemp()) / "real.json"
    real.write_text(json.dumps(_seal(_report())))
    os.symlink(real, w.incoming / "link.json")
    os.mkfifo(w.incoming / "fifo.json")
    r = w.drain()
    assert (r["recorded"], r["rejected"]) == (0, 2)
    assert _events(s, "org_a") == []


def test_body_without_tenant_refused():
    s, _, w = _rig()
    rep = _report()
    rep["org_id"] = ""
    body = json.dumps(rep)
    env = {"schema": ms.REPORT_SCHEMA, "body": body, "mac": "a" * 64}
    assert "tenant" in _rejected_one(w, env)


# --- org scoping ---------------------------------------------------------------------------------
def test_monitoring_events_org_scoped():
    s, _, w = _rig()
    _drop(w, _seal(_report()))
    _drop(w, _seal(_report(org="org_b", host="beta.cm")))
    assert w.drain()["recorded"] == 2
    a, b = _events(s, "org_a"), _events(s, "org_b")
    assert [e["org_id"] for e in a] == ["org_a"] and [e["org_id"] for e in b] == ["org_b"]
    assert ms.monitoring_events(s, "") == [] and ms.monitoring_events(s, None) == []
    assert ms.monitoring_events(s, "org_c") == []


# --- provisioner + edge -------------------------------------------------------------------------
class _Orgs:
    def __init__(self, ok):
        self.ok = ok

    def admit_customer(self, *, username, org_id, permission):
        return self.ok(username, org_id)


def _prov(store, ok):
    import threading

    from sigil.ui.provision import Provisioner
    p = object.__new__(Provisioner)
    p.store, p.orgs, p._lock = store, _Orgs(ok), threading.RLock()
    p._audit = lambda *a, **k: None
    return p


def test_provisioner_monitor_events_session_org_and_flag(monkeypatch):
    from sigil.ui.provision import ProvisionDenied
    s, _, w = _rig()
    _drop(w, _seal(_report()))
    _drop(w, _seal(_report(org="org_b", host="beta.cm")))
    w.drain()
    p = _prov(s, lambda u, o: (u, o) in {("alice", "org_a"), ("bob", "org_b")})
    monkeypatch.setenv("VIGIL_CUSTOMER_MONITORING_ENABLED", "1")
    r = p.monitor_events("alice", "org_a")
    assert [e["org_id"] for e in r["events"]] == ["org_a"]
    with pytest.raises(ProvisionDenied):
        p.monitor_events("alice", "org_b")
    monkeypatch.delenv("VIGIL_CUSTOMER_MONITORING_ENABLED")
    with pytest.raises(ProvisionDenied):
        p.monitor_events("alice", "org_a")


def test_server_dispatch_events_flag_gated(monkeypatch):
    from sigil.ui.server import Handler
    calls = []

    class P:
        def monitor_events(self, *a, **k):
            calls.append((a, k))
            return {"ok": True}
    monkeypatch.delenv("VIGIL_CUSTOMER_MONITORING_ENABLED", raising=False)
    assert Handler._provision_dispatch(None, P(), "monitor_events", "alice", {"org_id": "org_a"}) is None
    assert calls == []
    monkeypatch.setenv("VIGIL_CUSTOMER_MONITORING_ENABLED", "1")
    Handler._provision_dispatch(None, P(), "monitor_events", "alice", {"org_id": "org_a"})
    assert calls[0][0] == ("alice", "org_a")


def _edge(session):
    from sigil.ui.custui import CustomerHandler
    h = object.__new__(CustomerHandler)
    sent = {}
    h._session = lambda: session
    h._ip = lambda: "1.2.3.4"
    h._provision = lambda action, principal, body: (sent.update(action=action, principal=principal,
                                                                body=body) or (200, {"ok": True}))
    h._json = lambda obj, code=200: sent.update(code=code, out=obj)
    h._deny = lambda code=403, msg="forbidden": sent.update(code=code, out={"error": msg})
    return h, sent


def test_edge_events_route_session_org_and_flag(monkeypatch):
    monkeypatch.setenv("VIGIL_CUSTOMER_MONITORING_ENABLED", "1")
    h, sent = _edge({"username": "alice", "org_id": "org_a"})
    h.path = "/api/customer/monitoring/events?org_id=org_b"
    h.do_GET()
    assert sent["action"] == "monitor_events" and sent["principal"] == "alice"
    assert sent["body"]["org_id"] == "org_a"
    h, sent = _edge(None)
    h.path = "/api/customer/monitoring/events"
    h.do_GET()
    assert sent["code"] == 401 and "action" not in sent
    monkeypatch.delenv("VIGIL_CUSTOMER_MONITORING_ENABLED")
    h, sent = _edge({"username": "alice", "org_id": "org_a"})
    h.path = "/api/customer/monitoring/events"
    h.do_GET()
    assert sent == {"code": 404, "out": {"error": "not found"}}


def test_outer_schema_mismatch_refused_even_with_valid_mac():
    s, _, w = _rig()
    env = _seal(_report())
    env["schema"] = "vigil.aegis.monitoring.v0"
    assert "schema" in _rejected_one(w, env)


def test_fifo_reason_names_non_regular_file():
    s, _, w = _rig()
    os.mkfifo(w.incoming / "fifo.json")
    assert w.drain()["rejected"] == 1
    assert "not a regular file" in (w.rejected / "fifo.json.reason").read_text()


def test_missing_ts_refused():
    s, _, w = _rig()
    rep = _report()
    del rep["ts"]
    assert "timestamp" in _rejected_one(w, _seal(rep))
