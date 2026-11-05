"""AEGIS-SaaS AE-4 (data-plane half) — sealed, metadata-only monitoring reports spooled by a tenant gateway."""
from __future__ import annotations

import hashlib
import hmac
import http.client
import http.server
import json
import os
import socketserver
import stat
import threading
import urllib.parse
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
from vigil_core.monitoring_authority import MonitoringAuthority, MonitoringMode, sign_monitoring_authority

from framework.v2.aegis import monitoring_report as R
from framework.v2.aegis.gateway import serve_gateway
from framework.v2.aegis.models import AegisConfig
from framework.v2.aegis.monitoring_authority_check import monitoring_filename

SECRET = b"s" * 32
OWNER = generate_keypair()
ROOT = TrustRoot(threshold=1, authorizers=[AuthorizerKey(key_id="owner", name="owner",
                                                         public_key_b64=OWNER.public_key_b64)])


def _v(decision="confirmed", cls="sqli_attempt", action="observe", conf=0.97, cert=None, prov="grounded:x"):
    return SimpleNamespace(decision=decision, attack_class=cls, action=action, confidence=conf,
                           certificate=cert, provenance=prov,
                           path="/secret?token=abc", body="password=hunter2", actor="203.0.113.9")


def _mac_ok(env, secret=SECRET):
    want = hmac.new(secret, R.REPORT_DOMAIN + env["body"].encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, env["mac"])


# ---- report content: metadata only ---------------------------------------------------------------------
def test_report_is_metadata_only():
    rep = R.build_report(_v(cert={"oracle": "x"}), org_id="org_a", host="apme.cm", ts=5.0)
    assert set(rep) == {"schema", "org_id", "host", "ts", "decision", "attack_class", "action", "confidence",
                        "provenance_tier", "certificate_sha256", "report_id"}
    blob = json.dumps(rep)
    for leak in ("secret?token", "hunter2", "203.0.113.9", "/secret"):
        assert leak not in blob
    assert rep["provenance_tier"] == "grounded" and len(rep["certificate_sha256"]) == 64


def test_seal_mac_roundtrip_and_tamper_detection():
    env = R.seal_report(R.build_report(_v(), org_id="org_a", host="apme.cm", ts=1.0), SECRET)
    assert env["schema"] == R.REPORT_SCHEMA and _mac_ok(env)
    body = json.loads(env["body"])
    body["org_id"] = "org_b"
    forged = {**env, "body": json.dumps(body, sort_keys=True, separators=(",", ":"))}
    assert not _mac_ok(forged)
    assert not _mac_ok(env, secret=b"t" * 32)


@pytest.mark.parametrize("bad", [b"", b"short", "not-bytes", None])
def test_secret_must_be_bytes_and_long_enough(bad):
    with pytest.raises(ValueError):
        R.seal_report({"a": 1}, bad)
    with pytest.raises(ValueError):
        R.SpoolReporter("/tmp/x", org_id="o", host="h", secret=bad)


# ---- reporter -------------------------------------------------------------------------------------------
def test_reporter_spools_confirmed_and_lead_but_not_clear(tmp_path):
    rp = R.SpoolReporter(tmp_path, org_id="org_a", host="apme.cm", secret=SECRET, now_fn=lambda: 100.0)
    rp(_v("confirmed"))
    rp(_v("lead", action="observe"))
    rp(_v("clear"))
    rp(None)
    files = sorted((tmp_path / "incoming").glob("*.json"))
    assert len(files) == 2 and rp.written == 2
    for f in files:
        assert stat.S_IMODE(f.stat().st_mode) == 0o600
        env = json.loads(f.read_bytes())
        assert _mac_ok(env)
        body = json.loads(env["body"])
        assert body["org_id"] == "org_a" and body["host"] == "apme.cm"
    assert stat.S_IMODE((tmp_path / "incoming").stat().st_mode) == 0o700


def test_reporter_rate_cap_drops_and_counts(tmp_path):
    rp = R.SpoolReporter(tmp_path, org_id="o", host="h", secret=SECRET, max_per_minute=3, now_fn=lambda: 60.0)
    for _ in range(10):
        rp(_v())
    assert rp.written == 3 and rp.dropped == 7


def test_reporter_never_raises(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    rp = R.SpoolReporter(blocker, org_id="o", host="h", secret=SECRET)   # spool path is a FILE -> write fails
    rp(_v())
    assert rp.errors == 1 and rp.written == 0


def test_compose_sinks_isolates_failures():
    seen = []

    def bad(_v):
        raise RuntimeError("x")
    fan = R.compose_sinks(None, bad, seen.append)
    fan("v")
    assert seen == ["v"]
    assert R.compose_sinks(None, None) is None


# ---- through a real tenant gateway ------------------------------------------------------------------------
class _Up(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_a):
        return

    def do_GET(self):
        b = b"OK"
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b)


@pytest.fixture()
def up():
    srv = socketserver.TCPServer(("127.0.0.1", 0), _Up)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()
    srv.server_close()


@pytest.fixture()
def pub(tmp_path, monkeypatch):
    d = tmp_path / "pub"
    d.mkdir()
    monkeypatch.setenv("VIGIL_MONITORING_PUBLISH_DIR", str(d))
    monkeypatch.setattr("framework.v2.authority.store.load_authority_root", lambda: ROOT)
    return d


def _grant(d, mode="observe"):
    doc = MonitoringAuthority(org_id="org_a", host="apme.cm", mode=MonitoringMode(mode),
                              not_before=datetime.fromtimestamp(0, tz=timezone.utc),
                              not_after=datetime.fromtimestamp(4e9, tz=timezone.utc), issued_by="owner")
    (d / monitoring_filename("org_a", "apme.cm")).write_bytes(
        sign_monitoring_authority(doc, {"owner": OWNER.private_key_b64}).model_dump_json().encode())


def _hit(up, spool):
    gw = serve_gateway(f"http://127.0.0.1:{up}", config=AegisConfig(deployment_secret="k", mode="enforce"),
                       host="127.0.0.1", port=0, saas_tenant="org_a", saas_host="apme.cm",
                       monitoring_spool=str(spool), monitoring_secret=SECRET)
    threading.Thread(target=gw.serve_forever, daemon=True).start()
    try:
        c = http.client.HTTPConnection("127.0.0.1", gw.server_address[1], timeout=5)
        c.request("GET", "/d?file=" + urllib.parse.quote("../../../../etc/passwd"))
        c.getresponse().read()
        c.close()
    finally:
        gw.shutdown()


def test_authorized_tenant_gateway_spools_a_sealed_report(up, pub, tmp_path):
    _grant(pub, "observe")
    spool = tmp_path / "spool"
    _hit(up, spool)
    files = list((spool / "incoming").glob("*.json"))
    assert files, "an authorized tenant gateway must report its verdicts"
    env = json.loads(files[0].read_bytes())
    assert _mac_ok(env)
    body = json.loads(env["body"])
    assert body["org_id"] == "org_a" and body["host"] == "apme.cm" and body["decision"] == "confirmed"
    assert "etc/passwd" not in files[0].read_text()


def test_unauthorized_tenant_gateway_spools_nothing(up, pub, tmp_path):
    spool = tmp_path / "spool"
    _hit(up, spool)                                      # no grant published => pass-through, no verdict
    assert not (spool / "incoming").exists() or not list((spool / "incoming").glob("*.json"))


def test_serve_gateway_monitoring_config_validation(up):
    cfg = AegisConfig(deployment_secret="k", mode="observe")
    with pytest.raises(ValueError, match="configured together"):
        serve_gateway(f"http://127.0.0.1:{up}", config=cfg, port=0, saas_tenant="org_a", saas_host="apme.cm",
                      monitoring_spool="/tmp/x")
    with pytest.raises(ValueError, match="tenant-bound gateway"):
        serve_gateway(f"http://127.0.0.1:{up}", config=cfg, port=0, monitoring_spool="/tmp/x",
                      monitoring_secret=SECRET)
