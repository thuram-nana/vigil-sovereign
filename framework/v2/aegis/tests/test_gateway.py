"""
AEGIS Gateway (G1/G2) — the inline reverse-proxy "provable firewall".

End-to-end over real loopback sockets: a trivial upstream app behind the gateway, driven through the
gateway with urllib. The properties that matter:

  * TRANSPARENT proxy — benign traffic reaches the upstream unchanged, in BOTH modes.
  * observe mode is READ-ONLY — a proven attack is inspected + emitted but STILL forwarded (never
    blocked); default availability-first.
  * enforce mode BLOCKS only a CONFIRMED verdict, returning 403 + a re-runnable certificate, and the
    malicious request never reaches the upstream (D1: block rides on a certificate).
  * FAIL-OPEN — an upstream that is down yields an honest 502, never a block; and an inspection error
    never manufactures a block.
  * NO forward-SSRF — only the request path+query is appended to the fixed upstream.
"""

from __future__ import annotations

import http.server
import socketserver
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator

import pytest

from framework.v2.aegis.gateway import serve_gateway
from framework.v2.aegis.models import AegisConfig, Verdict


class _Upstream(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_a):  # noqa: D401 - quiet
        return

    def _reply(self):
        body = f"UPSTREAM-OK path={self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = _reply
    do_POST = _reply


@pytest.fixture()
def upstream() -> Iterator[int]:
    srv = socketserver.TCPServer(("127.0.0.1", 0), _Upstream)
    srv.daemon_threads = True
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()


def _run_gateway(upstream_port: int, *, mode: str, sink: list | None = None,
                 honeypot_paths=None):
    cfg = AegisConfig(deployment_secret="k", mode=mode, honeypot_paths=honeypot_paths or [])
    gw = serve_gateway(f"http://127.0.0.1:{upstream_port}", config=cfg, host="127.0.0.1", port=0,
                       on_verdict=(sink.append if sink is not None else None))
    threading.Thread(target=gw.serve_forever, daemon=True).start()
    return gw, gw.server_address[1]


def _get(port: int, path: str):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
    return urllib.request.urlopen(req, timeout=5)


_SQLI = "/search?q=" + urllib.parse.quote("' OR '1'='1")


def test_benign_traffic_is_transparently_proxied(upstream):
    gw, port = _run_gateway(upstream, mode="observe")
    try:
        resp = _get(port, "/hello?q=world")
        body = resp.read().decode()
        assert resp.status == 200 and "UPSTREAM-OK" in body and "path=/hello?q=world" in body
    finally:
        gw.shutdown()


def test_observe_mode_forwards_even_a_proven_attack(upstream):
    """Default observe is read-only: it emits the confirmed verdict but STILL forwards (availability-
    first). Nothing is blocked without an explicit enforce opt-in."""
    sink: list[Verdict] = []
    gw, port = _run_gateway(upstream, mode="observe", sink=sink)
    try:
        body = _get(port, _SQLI).read().decode()
        assert "UPSTREAM-OK" in body, "observe mode must NOT block — it forwarded nothing"
        assert any(v.decision == "confirmed" and v.attack_class == "sqli_attempt" for v in sink)
    finally:
        gw.shutdown()


def test_enforce_mode_blocks_a_confirmed_attack_with_a_certificate(upstream):
    sink: list[Verdict] = []
    gw, port = _run_gateway(upstream, mode="enforce", sink=sink)
    try:
        with pytest.raises(urllib.error.HTTPError) as ei:
            _get(port, _SQLI)
        err = ei.value
        assert err.code == 403
        assert err.headers.get("X-Aegis-Block") == "sqli_attempt"
        cert = err.headers.get("X-Aegis-Certificate", "")
        assert cert.startswith("aegis-cert:")
        # the block is PROVABLE: the emitted verdict's certificate re-runs offline.
        v = next(v for v in sink if v.decision == "confirmed")
        assert v.certificate is not None and v.certificate.reverify() is True
    finally:
        gw.shutdown()


def test_enforce_mode_still_forwards_benign_traffic(upstream):
    gw, port = _run_gateway(upstream, mode="enforce")
    try:
        body = _get(port, "/hello?q=O%27Brien").read().decode()   # apostrophe must NOT trip a block
        assert "UPSTREAM-OK" in body
    finally:
        gw.shutdown()


def test_fail_open_on_upstream_down_returns_502_not_a_block(upstream):
    # point the gateway at a port with nothing listening -> forward fails -> honest 502, NOT a block.
    cfg = AegisConfig(deployment_secret="k", mode="enforce")
    gw = serve_gateway("http://127.0.0.1:1", config=cfg, host="127.0.0.1", port=0)
    threading.Thread(target=gw.serve_forever, daemon=True).start()
    port = gw.server_address[1]
    try:
        with pytest.raises(urllib.error.HTTPError) as ei:
            _get(port, "/hello")
        assert ei.value.code == 502   # bad gateway, not 403
    finally:
        gw.shutdown()


def test_honeypot_path_is_blocked_under_enforce(upstream):
    sink: list[Verdict] = []
    gw, port = _run_gateway(upstream, mode="enforce", sink=sink, honeypot_paths=["/.git/config"])
    try:
        with pytest.raises(urllib.error.HTTPError) as ei:
            _get(port, "/.git/config")
        assert ei.value.code == 403
        assert ei.value.headers.get("X-Aegis-Block") == "automated_access"
    finally:
        gw.shutdown()


def test_no_forward_ssrf_absolute_uri_uses_only_path(upstream):
    """A caller cannot redirect the forward to another host: only the path+query is appended to the
    fixed upstream base. (urllib sends origin-form, but the gateway's _forward_url discards any
    scheme/host regardless.)"""
    from framework.v2.aegis.gateway import AegisGatewayHandler, GatewaySettings

    st = GatewaySettings("http://127.0.0.1:9/app", AegisConfig(deployment_secret="k"))
    # a hostile absolute-form path must resolve to the CONFIGURED host, never evil.example.
    url = AegisGatewayHandler._forward_url.__get__(  # bind the unbound method to a stub
        type("S", (), {"settings": st, "path": ""})()
    )("http://evil.example/steal?x=1")
    assert url.startswith("http://127.0.0.1:9") and "evil.example" not in url


# --------------------------------------------------------------------------- G2: enforce gating

def test_governed_deployment_without_entitlement_downgrades_to_observe(upstream, monkeypatch):
    """A GOVERNED deployment that has not granted AEGIS_RESPOND must NOT block — enforce downgrades
    to observe (fail-closed to safe). The malicious request then forwards (availability preserved)."""
    monkeypatch.setattr("framework.v2.entitlement.policy.is_capability_available", lambda cap: False)
    gw, port = _run_gateway(upstream, mode="enforce")
    try:
        body = _get(port, _SQLI).read().decode()   # would be 403 if enforcement were active
        assert "UPSTREAM-OK" in body, "unentitled enforce must downgrade to observe, not block"
    finally:
        gw.shutdown()


def test_kill_switch_trips_enforcement_to_pass_through(upstream, monkeypatch):
    """A tripped kill-switch drops enforcement to pass-through per request — a misbehaving firewall is
    neutralised WITHOUT taking the app down (availability-first)."""
    monkeypatch.setattr("framework.v2.authority.killswitch.KillSwitch.is_tripped",
                        lambda self: True)
    gw, port = _run_gateway(upstream, mode="enforce")
    try:
        body = _get(port, _SQLI).read().decode()
        assert "UPSTREAM-OK" in body, "a tripped kill-switch must pass traffic through, not block"
    finally:
        gw.shutdown()


def test_enforce_property_is_fail_safe(monkeypatch):
    """Unit: the enforce gate is the AND of (configured enforce) AND (entitled) AND (kill-switch not
    tripped); every term fails toward NOT blocking."""
    from framework.v2.aegis.gateway import GatewaySettings

    # observe config never enforces regardless of entitlement/killswitch.
    s_obs = GatewaySettings("http://127.0.0.1:9", AegisConfig(deployment_secret="k", mode="observe"))
    assert s_obs.enforce is False

    # enforce + entitled + killswitch-clear => True
    s = GatewaySettings("http://127.0.0.1:9", AegisConfig(deployment_secret="k", mode="enforce"))
    monkeypatch.setattr(s, "_enforce_authorized", True)
    monkeypatch.setattr(s, "_killswitch_tripped", lambda: False)
    assert s.enforce is True
    # a tripped kill-switch flips it off
    monkeypatch.setattr(s, "_killswitch_tripped", lambda: True)
    assert s.enforce is False
    # unentitled flips it off even with a clear kill-switch
    monkeypatch.setattr(s, "_enforce_authorized", False)
    monkeypatch.setattr(s, "_killswitch_tripped", lambda: False)
    assert s.enforce is False
