"""AEGIS-SaaS AE-7 — end-to-end acceptance across BOTH planes, over real loopback sockets.

  provisioner monitor_authorize (sovereign, owner-signed) -> published SignedMonitoringAuthority
  -> keyless tenant gateway (offense process, verify-only) -> sealed metadata-only report in the spool
  -> sovereign MonitoringSpoolWatcher drain -> the tenant's monitoring_events.

Plus: a hard block happens ONLY with a BLOCK grant AND the default-OFF production flag AND enforce mode (and
the AEGIS_RESPOND entitlement + untripped kill-switch the gateway already requires); revoke -> uninspected
pass-through on the very next request; tenant A's gateway / reports / events never reach tenant B.

``framework`` and ``sigil`` cannot co-load (assert_no_offense), so this process holds the gateway and drives the
sovereign plane through fixtures/aegis_saas_sovereign_side.py in a child process. Runs in the OFFENSE leg.
"""
from __future__ import annotations

import http.client
import http.server
import json
import os
import socketserver
import subprocess
import sys
import threading
import urllib.parse
from pathlib import Path

import pytest

pytest.importorskip("framework.v2.aegis.gateway", reason="CRUCIBLE (offense) not importable here")

from vigil_core import AuthorizerKey, TrustRoot                     # noqa: E402

from framework.v2.aegis import gateway as G                         # noqa: E402
from framework.v2.aegis.models import AegisConfig                   # noqa: E402

_REPO = Path(__file__).resolve().parents[2]
_SIDE = Path(__file__).resolve().parent / "fixtures" / "aegis_saas_sovereign_side.py"
ATTACK = "/download?file=" + urllib.parse.quote("../../../../etc/passwd")
SECRET_A, SECRET_B = b"a" * 32, b"b" * 32


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


class _Sovereign:
    def __init__(self, tmp: Path):
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(("VIGIL_", "SIGIL_"))}
        self.env.update({
            "PYTHONPATH": os.pathsep.join(str(_REPO / p) for p in ("apps/sigil", "packages/core/vigil_core")),
            "SIGIL_HOME": str(tmp / "sigil_home"), "VIGIL_BASE_DIR": str(tmp / "base"),
            "SIGIL_SPINE_DIR": str(tmp / "spine"), "VIGIL_MONITORING_PUBLISH_DIR": str(tmp / "pub"),
            "VIGIL_CUSTOMER_MONITORING_ENABLED": "1", "AEGIS_ACC_STORE": str(tmp / "spine.jsonl")})
        self.secrets = tmp / "secrets.json"
        self.secrets.write_text(json.dumps({"org_a\x00apme.cm": SECRET_A.hex(), "org_b\x00beta.cm": SECRET_B.hex()}))
        os.chmod(self.secrets, 0o600)

    def __call__(self, *argv: str) -> dict:
        r = subprocess.run([sys.executable, str(_SIDE), *argv], env=self.env, capture_output=True, text=True,
                           timeout=120)
        assert r.returncode == 0, r.stderr[-3000:]
        return json.loads(r.stdout.strip().splitlines()[-1])


@pytest.fixture()
def rig(tmp_path, monkeypatch):
    sov = _Sovereign(tmp_path)
    try:
        subprocess.run([sys.executable, "-c", "import sigil.ui.provision"], env=sov.env, check=True,
                       capture_output=True, timeout=120)
    except subprocess.CalledProcessError as e:      # pragma: no cover — named, never silent (-rs)
        pytest.skip(f"sovereign plane not importable in a child process: {e.stderr[-300:]!r}")
    pub = sov.env["VIGIL_MONITORING_PUBLISH_DIR"]
    owner = sov("setup")["owner_public_key_b64"]
    root = TrustRoot(threshold=1, authorizers=[AuthorizerKey(key_id="owner", name="owner", public_key_b64=owner)])
    monkeypatch.setenv("VIGIL_MONITORING_PUBLISH_DIR", pub)          # the gateway reads the SAME publish dir
    monkeypatch.setattr("framework.v2.authority.store.load_authority_root", lambda: root)
    monkeypatch.delenv(G.SAAS_ENFORCE_ENV, raising=False)
    return sov, tmp_path


class _Gateway:
    """ONE long-lived tenant gateway (as deployed): authority changes must take effect on the SAME process."""

    def __init__(self, upstream_port, spool: Path, *, tenant="org_a", host="apme.cm", secret=SECRET_A,
                 mode="enforce"):
        self.host = host
        self.gw = G.serve_gateway(f"http://127.0.0.1:{upstream_port}",
                                  config=AegisConfig(deployment_secret="k", mode=mode), host="127.0.0.1", port=0,
                                  saas_tenant=tenant, saas_host=host, monitoring_spool=str(spool),
                                  monitoring_secret=secret)
        threading.Thread(target=self.gw.serve_forever, daemon=True).start()

    def get(self, path=ATTACK):
        c = http.client.HTTPConnection("127.0.0.1", self.gw.server_address[1], timeout=5)
        try:
            c.request("GET", path, headers={"Host": self.host})
            r = c.getresponse()
            return r.status, r.getheader("X-Aegis-Block"), r.read()
        finally:
            c.close()

    def close(self):
        self.gw.shutdown()
        self.gw.server_close()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()


def _hit(upstream_port, spool: Path, *, path=ATTACK, **kw):
    with _Gateway(upstream_port, spool, **kw) as gw:
        return gw.get(path)


def _spooled(spool: Path) -> list[Path]:
    return sorted((spool / "incoming").glob("*.json")) if (spool / "incoming").exists() else []


# ---- the observe pipeline, end to end -----------------------------------------------------------------------
def test_authorize_publish_gateway_report_drain_reaches_only_the_tenant(rig, upstream):
    sov, tmp = rig
    assert sov("authorize", "org_a", "alice", "apme.cm", "observe")["ok"]
    spool = tmp / "spool"
    status, blocked, body = _hit(upstream, spool)
    assert status == 200 and blocked is None and body == b"UPSTREAM-OK"      # OBSERVE never blocks
    assert len(_spooled(spool)) >= 1
    assert "etc/passwd" not in "".join(p.read_text() for p in _spooled(spool))
    out = sov("drain", str(spool), str(sov.secrets))
    assert out["drain"]["recorded"] >= 1 and out["drain"]["rejected"] == 0
    ev = out["events"]["org_a"]
    assert ev and all(e["org_id"] == "org_a" and e["host"] == "apme.cm" for e in ev)
    assert any(e["decision"] == "confirmed" and e["source_class"] == "gateway_reported" for e in ev)
    assert out["events"]["org_b"] == []                                      # cross-tenant isolation (read side)
    again = sov("drain", str(spool), str(sov.secrets))                       # idempotent
    assert again["drain"]["recorded"] == 0 and len(again["events"]["org_a"]) == len(ev)


def test_no_authority_is_pass_through_and_spools_nothing(rig, upstream):
    _, tmp = rig
    spool = tmp / "spool"
    assert _hit(upstream, spool)[0] == 200 and _spooled(spool) == []


# ---- block only with every flag -----------------------------------------------------------------------------
def test_block_grant_alone_never_blocks_flag_off_by_default(rig, upstream):
    sov, tmp = rig
    assert sov("authorize", "org_a", "alice", "apme.cm", "block")["ok"]
    assert _hit(upstream, tmp / "s")[0] == 200


def test_observe_grant_with_flag_never_blocks(rig, upstream, monkeypatch):
    sov, tmp = rig
    assert sov("authorize", "org_a", "alice", "apme.cm", "observe")["ok"]
    monkeypatch.setenv(G.SAAS_ENFORCE_ENV, "1")
    assert _hit(upstream, tmp / "s")[0] == 200


def test_block_grant_flag_but_observe_mode_never_blocks(rig, upstream, monkeypatch):
    sov, tmp = rig
    assert sov("authorize", "org_a", "alice", "apme.cm", "block")["ok"]
    monkeypatch.setenv(G.SAAS_ENFORCE_ENV, "1")
    assert _hit(upstream, tmp / "s", mode="observe")[0] == 200


def test_block_with_every_flag_blocks_then_revoke_is_pass_through(rig, upstream, monkeypatch):
    sov, tmp = rig
    assert sov("authorize", "org_a", "alice", "apme.cm", "block")["ok"]
    monkeypatch.setenv(G.SAAS_ENFORCE_ENV, "1")
    spool = tmp / "s1"
    with _Gateway(upstream, spool) as gw:                                     # ONE long-lived gateway
        status, blocked, _ = gw.get()
        assert status == 403 and blocked == "path_traversal_attempt"
        benign = "/assets?file=" + urllib.parse.quote("../styles/app.css")
        assert gw.get(benign)[0] == 200
        r = sov("revoke", "org_a", "alice", "apme.cm")
        assert r["revoked"] is True and r["unpublished"]
        before = _spooled(spool)
        status, blocked, body = gw.get()                                      # SAME gateway, next request
        assert status == 200 and blocked is None and body == b"UPSTREAM-OK"  # uninspected pass-through
        assert _spooled(spool) == before                                      # nothing spooled after revoke
    # reports sealed while the grant was live but drained AFTER revoke are dropped (re-bound at receipt).
    out = sov("drain", str(spool), str(sov.secrets))
    assert out["drain"]["recorded"] == 0 and out["drain"]["rejected"] >= 1 and out["events"]["org_a"] == []


def test_grant_after_gateway_start_takes_effect_on_the_same_gateway(rig, upstream, monkeypatch):
    sov, tmp = rig
    monkeypatch.setenv(G.SAAS_ENFORCE_ENV, "1")
    spool = tmp / "s"
    with _Gateway(upstream, spool) as gw:
        assert gw.get()[:2] == (200, None) and _spooled(spool) == []          # no authority yet: pass-through
        assert sov("authorize", "org_a", "alice", "apme.cm", "block")["ok"]
        status, blocked, _ = gw.get()                                         # SAME gateway picks up the grant
        assert status == 403 and blocked == "path_traversal_attempt"
        assert _spooled(spool)


# ---- cross-tenant isolation ----------------------------------------------------------------------------------
def test_cross_tenant_isolation(rig, upstream):
    sov, tmp = rig
    assert sov("authorize", "org_a", "alice", "apme.cm", "observe")["ok"]
    # org_b cannot mint authority over org_a's host (no ownership proof / session org decides).
    assert sov("authorize", "org_b", "bob", "apme.cm", "observe")["ok"] is False
    # a gateway bound to org_b but fronting org_a's host has no authority: pass-through, nothing spooled.
    spool = tmp / "spool"
    assert _hit(upstream, spool, tenant="org_b", host="apme.cm", secret=SECRET_B)[0] == 200
    assert _spooled(spool) == []
    # a deployment sealing org_a's reports under org_b's secret is refused at the drain, nothing recorded.
    _hit(upstream, spool, secret=SECRET_B)
    assert _spooled(spool)
    out = sov("drain", str(spool), str(sov.secrets))
    assert out["drain"]["recorded"] == 0 and out["drain"]["rejected"] >= 1
    assert out["events"] == {"org_a": [], "org_b": []}
