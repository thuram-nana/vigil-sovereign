"""AEGIS-SaaS AE-3 — per-request enforcement gating for a SaaS (tenant-bound) gateway.

Over REAL loopback sockets, with a request that the legacy enforce-mode gateway provably BLOCKS (a confirmed,
certificate-carrying path-traversal verdict), each gate term below must turn that block into a forward:
  * no published authority, a grant for another host/tenant, an expired grant, or a grant revoked mid-run
    → plain PASS-THROUGH (not even inspected: no verdict emitted);
  * an OBSERVE grant → inspected (verdict emitted) but NEVER blocked;
  * a BLOCK grant still needs: the default-OFF production flag, enforce mode, the AEGIS_RESPOND entitlement,
    and an untripped kill-switch — all of them;
  * only with every term satisfied does the attack get 403 + an offline-re-runnable certificate, while benign
    traffic is still forwarded. A legacy gateway (no tenant) is unchanged.
"""
from __future__ import annotations

import http.client
import http.server
import socketserver
import threading
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

import pytest
from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
from vigil_core.monitoring_authority import MonitoringAuthority, MonitoringMode, sign_monitoring_authority

from framework.v2.aegis import gateway as G
from framework.v2.aegis.gateway import serve_gateway
from framework.v2.aegis.models import AegisConfig, Verdict
from framework.v2.aegis.monitoring_authority_check import MonitoringDecision, monitoring_filename

OWNER = generate_keypair()
ROOT = TrustRoot(threshold=1, authorizers=[AuthorizerKey(key_id="owner", name="owner",
                                                         public_key_b64=OWNER.public_key_b64)])
TENANT, HOST = "org_a", "apme.cm"
ATTACK = "/download?file=" + urllib.parse.quote("../../../../etc/passwd")
BENIGN = "/assets?file=" + urllib.parse.quote("../styles/app.css")


class _Upstream(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_a):
        return

    def do_GET(self):
        body = b"UPSTREAM-OK"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def upstream():
    srv = socketserver.TCPServer(("127.0.0.1", 0), _Upstream)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()


@pytest.fixture()
def pub(tmp_path, monkeypatch):
    d = tmp_path / "pub"
    d.mkdir()
    monkeypatch.setenv("VIGIL_MONITORING_PUBLISH_DIR", str(d))
    monkeypatch.setattr("framework.v2.authority.store.load_authority_root", lambda: ROOT)
    monkeypatch.delenv(G.SAAS_ENFORCE_ENV, raising=False)
    return d


def _grant(d: Path, *, mode="block", host=HOST, org=TENANT, nb=0.0, na=4.0e9):
    doc = MonitoringAuthority(org_id=org, host=host, mode=MonitoringMode(mode),
                              not_before=datetime.fromtimestamp(nb, tz=timezone.utc),
                              not_after=datetime.fromtimestamp(na, tz=timezone.utc), issued_by="owner")
    s = sign_monitoring_authority(doc, {"owner": OWNER.private_key_b64})
    p = d / monitoring_filename(org, host)
    p.write_bytes(s.model_dump_json().encode())
    return p


def _gw(upstream_port, *, mode="enforce", tenant=TENANT, sink=None):
    cfg = AegisConfig(deployment_secret="k", mode=mode)
    gw = serve_gateway(f"http://127.0.0.1:{upstream_port}", config=cfg, host="127.0.0.1", port=0,
                       on_verdict=(sink.append if sink is not None else None), saas_tenant=tenant)
    threading.Thread(target=gw.serve_forever, daemon=True).start()
    return gw, gw.server_address[1]


def _req(port, path, host=HOST):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request("GET", path, headers={"Host": host})
    r = c.getresponse()
    out = (r.status, dict(r.getheaders()), r.read())
    c.close()
    return out


def _run(upstream_port, path=ATTACK, **kw):
    sink: list[Verdict] = []
    gw, port = _gw(upstream_port, sink=sink, **{k: v for k, v in kw.items() if k in ("mode", "tenant")})
    try:
        return _req(port, path, host=kw.get("host", HOST)), sink, gw
    finally:
        gw.shutdown()


# ---- baseline: legacy gateway unchanged ---------------------------------------------------------------
def test_legacy_gateway_without_tenant_still_blocks(upstream, pub):
    (status, hdr, _), sink, _ = _run(upstream, tenant=None)
    assert status == 403 and hdr.get("X-Aegis-Block") == "path_traversal_attempt"


# ---- the fully-satisfied SaaS block ----------------------------------------------------------------------
def test_block_grant_with_every_term_blocks_with_certificate(upstream, pub, monkeypatch):
    _grant(pub, mode="block")
    monkeypatch.setenv(G.SAAS_ENFORCE_ENV, "1")
    (status, hdr, _), sink, _ = _run(upstream)
    assert status == 403 and hdr.get("X-Aegis-Block") == "path_traversal_attempt"
    v = next(v for v in sink if v.decision == "confirmed")
    assert v.certificate is not None and v.certificate.reverify() is True


def test_benign_traffic_still_forwarded_under_full_block(upstream, pub, monkeypatch):
    _grant(pub, mode="block")
    monkeypatch.setenv(G.SAAS_ENFORCE_ENV, "1")
    (status, _, body), _, _ = _run(upstream, path=BENIGN)
    assert status == 200 and body == b"UPSTREAM-OK"


# ---- each missing term turns the block into a forward ------------------------------------------------------
def test_production_flag_off_by_default_never_blocks(upstream, pub):
    _grant(pub, mode="block")
    (status, _, body), sink, _ = _run(upstream)
    assert status == 200 and body == b"UPSTREAM-OK"
    assert any(v.decision == "confirmed" for v in sink), "still inspected + alerted, just not enforced"


@pytest.mark.parametrize("val", ["0", "false", "maybe", "", "enable"])
def test_production_flag_is_strict(upstream, pub, monkeypatch, val):
    _grant(pub, mode="block")
    monkeypatch.setenv(G.SAAS_ENFORCE_ENV, val)
    (status, _, _), _, _ = _run(upstream)
    assert status == 200


def test_observe_grant_never_blocks_even_with_flag_and_enforce(upstream, pub, monkeypatch):
    _grant(pub, mode="observe")
    monkeypatch.setenv(G.SAAS_ENFORCE_ENV, "1")
    (status, _, body), sink, _ = _run(upstream)
    assert status == 200 and body == b"UPSTREAM-OK"
    assert sink and all(v.action != "block" for v in sink)


def test_observe_mode_gateway_never_blocks_a_block_grant(upstream, pub, monkeypatch):
    _grant(pub, mode="block")
    monkeypatch.setenv(G.SAAS_ENFORCE_ENV, "1")
    (status, _, _), _, _ = _run(upstream, mode="observe")
    assert status == 200


def test_missing_entitlement_never_blocks(upstream, pub, monkeypatch):
    _grant(pub, mode="block")
    monkeypatch.setenv(G.SAAS_ENFORCE_ENV, "1")
    monkeypatch.setattr(G.GatewaySettings, "_authorize_enforce", lambda self: False)
    (status, _, _), _, _ = _run(upstream)
    assert status == 200


def test_tripped_kill_switch_never_blocks(upstream, pub, monkeypatch):
    _grant(pub, mode="block")
    monkeypatch.setenv(G.SAAS_ENFORCE_ENV, "1")
    monkeypatch.setattr(G.GatewaySettings, "_killswitch_tripped", lambda self: True)
    (status, _, _), _, _ = _run(upstream)
    assert status == 200


# ---- no valid authority → plain pass-through, NOT inspected ------------------------------------------------
@pytest.mark.parametrize("setup", ["none", "other_host", "other_tenant", "expired", "not_yet"])
def test_no_valid_authority_is_uninspected_pass_through(upstream, pub, monkeypatch, setup):
    monkeypatch.setenv(G.SAAS_ENFORCE_ENV, "1")
    if setup == "other_host":
        _grant(pub, host="other.cm")
    elif setup == "other_tenant":
        _grant(pub, org="org_b")
    elif setup == "expired":
        _grant(pub, nb=0.0, na=10.0)
    elif setup == "not_yet":
        _grant(pub, nb=3.9e9, na=4.0e9)
    (status, _, body), sink, _ = _run(upstream)
    assert status == 200 and body == b"UPSTREAM-OK"
    assert sink == [], "no authority => AEGIS must not inspect or record this tenant's traffic"


def test_request_for_another_host_header_is_pass_through(upstream, pub, monkeypatch):
    _grant(pub, mode="block")
    monkeypatch.setenv(G.SAAS_ENFORCE_ENV, "1")
    (status, _, _), sink, _ = _run(upstream, host="unrelated.example")
    assert status == 200 and sink == []


def test_per_request_reauthorization_revocation_takes_effect_immediately(upstream, pub, monkeypatch):
    p = _grant(pub, mode="block")
    monkeypatch.setenv(G.SAAS_ENFORCE_ENV, "1")
    sink: list[Verdict] = []
    gw, port = _gw(upstream, sink=sink)
    try:
        assert _req(port, ATTACK)[0] == 403
        p.unlink()                                                       # sovereign revoke ⇒ unpublished
        assert _req(port, ATTACK)[0] == 200
    finally:
        gw.shutdown()


def test_unreadable_owner_root_is_pass_through(upstream, pub, monkeypatch):
    _grant(pub, mode="block")
    monkeypatch.setenv(G.SAAS_ENFORCE_ENV, "1")
    monkeypatch.setattr("framework.v2.authority.store.load_authority_root", lambda: None)
    (status, _, _), sink, _ = _run(upstream)
    assert status == 200 and sink == []


# ---- the per-request term in isolation --------------------------------------------------------------------
def _settings(**kw):
    return G.GatewaySettings("http://127.0.0.1:1", AegisConfig(deployment_secret="k", mode="enforce"), **kw)


def test_effective_enforce_matrix(monkeypatch):
    legacy = _settings()
    assert legacy.saas_decision("apme.cm") is None
    assert legacy.effective_enforce(None) == legacy.enforce
    s = _settings(saas_tenant=TENANT)
    blk = MonitoringDecision(ok=True, mode="block", reason="authorized")
    obs = MonitoringDecision(ok=True, mode="observe", reason="authorized")
    bad = MonitoringDecision(ok=False, mode=None, reason="x")
    monkeypatch.delenv(G.SAAS_ENFORCE_ENV, raising=False)
    assert s.effective_enforce(blk) is False                              # flag off
    monkeypatch.setenv(G.SAAS_ENFORCE_ENV, "on")
    assert s.effective_enforce(blk) is True
    assert s.effective_enforce(obs) is False
    assert s.effective_enforce(bad) is False
    assert s.effective_enforce(MonitoringDecision(ok=False, mode="block", reason="x")) is False


def test_saas_decision_is_total_when_the_check_itself_fails(monkeypatch):
    import framework.v2.aegis.monitoring_authority_check as M

    def boom(*a, **k):
        raise RuntimeError("x")
    monkeypatch.setattr(M, "check_monitoring_authority", boom)
    d = _settings(saas_tenant=TENANT).saas_decision("apme.cm")
    assert d is not None and d.ok is False
