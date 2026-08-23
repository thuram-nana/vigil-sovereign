"""W8-6 (#472) — the proxy→cockpit hop is encrypted (TLS), and refuses a plaintext hop in production.

These are REAL, offline tests: they stand up an ACTUAL TLS backend with a throwaway self-signed cert and
drive the proxy's OWN hop code (`_hop_connection`, `_whoami`, `make_proxy_server`) against it. Every gate
is paired with a NEGATIVE CONTROL asserted in the SAME run, so a no-op cannot pass:

  * PRODUCTION posture + a REMOTE plaintext hop → `make_proxy_server` / `resolve_hop_tls` REFUSE to start
    (fail-closed). This is the test that FAILS WITHOUT the change — the unfixed `make_proxy_server` builds
    the server and never raises. Negative controls that scope the gate to the real threat (not a blanket
    block): a LOOPBACK hop is still allowed in production, and a non-production remote hop is still allowed.
  * a TLS hop ROUND-TRIPS: a request over `_hop_connection` and the delegated `_whoami` reaches the TLS
    backend and returns; negative control: the SAME whoami over a PLAINTEXT hop to the TLS backend fails
    closed (returns None) — proving TLS is genuinely required, not incidental.
  * MUTUAL TLS: with a client cert the proxy authenticates to a client-cert-REQUIRING backend and the
    round-trip works; negative control: WITHOUT the client cert the same backend refuses the handshake.
  * cert/key loading FAILS CLOSED on a missing/invalid CA or client cert, and on a half-configured mTLS
    pair (exactly one of cert/key).

Run: PYTHONPATH=integration:packages/core/vigil_core pytest integration/tests/test_uiproxy_hop_tls.py -q
"""
from __future__ import annotations

import http.server
import json
import shutil
import ssl
import subprocess
import threading
from pathlib import Path

import pytest

from vigil_integration import uiproxy

# The three federation targets in the two shapes that matter to the production gate.
_REMOTE = {"sovereign": ("vigil-sovereign", 8733), "console": ("127.0.0.1", 8787), "api": ("127.0.0.1", 8799)}
_LOOPBACK = {"sovereign": ("127.0.0.1", 8733), "console": ("127.0.0.1", 8787), "api": ("127.0.0.1", 8799)}


# --------------------------------------------------------------------------------------------------
# A throwaway self-signed cert (SAN: localhost + 127.0.0.1), generated with openssl at test time (never
# committed — a committed private key trips secret scanners). One keypair does triple duty: the backend's
# server identity, the client identity for mTLS, AND its own CA (a self-signed cert verifies itself) — so a
# single cert exercises server-auth, client-auth, and CA verification.
# --------------------------------------------------------------------------------------------------
def _selfsigned(dirpath: Path) -> "tuple[str, str]":
    cert = dirpath / "hop-cert.pem"
    key = dirpath / "hop-key.pem"
    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("openssl not available to generate a throwaway hop test cert")
    proc = subprocess.run(
        [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "3650",
         "-subj", "/CN=localhost",
         "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
        capture_output=True, text=True)
    if proc.returncode != 0 or not cert.is_file() or not key.is_file():
        pytest.skip(f"openssl could not generate a test cert: {proc.stderr[-400:]}")
    return str(cert), str(key)


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_a):  # silence the test server
        pass

    def do_GET(self):  # noqa: N802
        body = json.dumps({"authenticated": True, "username": "op", "role": "owner",
                           "permissions": ["run_engagement"], "path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _TLSBackend:
    """A background HTTPS backend on 127.0.0.1. `require_client_cert=True` turns on mTLS (the server
    verifies the client's certificate against the same self-signed cert acting as CA)."""

    def __init__(self, cert: str, key: str, *, require_client_cert: bool = False):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert, keyfile=key)
        if require_client_cert:
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.load_verify_locations(cafile=cert)
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.socket.getsockname()[1]
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *_a):
        self.httpd.shutdown()
        self.httpd.server_close()


# --------------------------------------------------------------------------------------------------
# The PRODUCTION fail-closed rule (pure, env-dict driven — no sockets).
# --------------------------------------------------------------------------------------------------
def test_production_refuses_a_plaintext_remote_hop():
    with pytest.raises(ValueError) as ei:
        uiproxy.resolve_hop_tls(_REMOTE, env={"VIGIL_POSTURE": "production"})
    msg = str(ei.value).lower()
    assert "plaintext" in msg and "vigil-sovereign:8733" in str(ei.value)


def test_production_loopback_hop_is_allowed():
    # NEGATIVE CONTROL: the gate is scoped to a REMOTE hop, not a blanket block. A single-host `vigil up`
    # (loopback trio) stays plaintext even in production — its bytes never traverse a network.
    assert uiproxy.resolve_hop_tls(_LOOPBACK, env={"VIGIL_POSTURE": "production"}) is None


def test_nonproduction_remote_plaintext_hop_is_allowed():
    # NEGATIVE CONTROL: outside the production posture the default is byte-identical (plaintext), even to a
    # remote backend — the gate is armed by VIGIL_POSTURE, nothing else.
    assert uiproxy.resolve_hop_tls(_REMOTE, env={}) is None


def test_production_remote_hop_with_tls_is_allowed(tmp_path):
    cert, _key = _selfsigned(tmp_path)
    ctx = uiproxy.resolve_hop_tls(_REMOTE, env={"VIGIL_POSTURE": "production",
                                                "VIGIL_HOP_TLS": "require", "VIGIL_HOP_CA": cert})
    assert isinstance(ctx, ssl.SSLContext)


def test_unresolvable_host_is_treated_as_remote_fail_closed():
    # FAIL-CLOSED: a host that is neither loopback nor a parseable IP (a DNS name) is REMOTE, so the
    # production gate fires — it never assumes an unknown host is local.
    assert uiproxy._hop_is_loopback("vigil-sovereign") is False
    assert uiproxy._hop_is_loopback("127.0.0.1") is True
    assert uiproxy._hop_is_loopback("::1") is True
    assert uiproxy._hop_is_loopback("localhost") is True


# --------------------------------------------------------------------------------------------------
# make_proxy_server — the real server-build path (this is where the refuse-to-start bites).
# --------------------------------------------------------------------------------------------------
def test_make_proxy_server_refuses_plaintext_remote_hop_in_production(tmp_path, monkeypatch):
    # THE "fails-without-the-change" test: the unfixed make_proxy_server builds the server and never
    # raises. With the fix it refuses to start (a ValueError both run_up call sites turn into exit 2).
    monkeypatch.setenv("VIGIL_POSTURE", "production")
    monkeypatch.delenv("VIGIL_HOP_TLS", raising=False)
    with pytest.raises(ValueError) as ei:
        uiproxy.make_proxy_server("127.0.0.1", 0, tmp_path, backends=_REMOTE)
    assert "plaintext" in str(ei.value).lower()


def test_make_proxy_server_wires_the_tls_context_onto_the_server(tmp_path, monkeypatch):
    cert, _key = _selfsigned(tmp_path)
    monkeypatch.setenv("VIGIL_POSTURE", "production")
    monkeypatch.setenv("VIGIL_HOP_TLS", "require")
    monkeypatch.setenv("VIGIL_HOP_CA", cert)
    httpd = uiproxy.make_proxy_server("127.0.0.1", 0, tmp_path, backends=_REMOTE)
    try:
        assert isinstance(httpd.hop_tls, ssl.SSLContext)
    finally:
        httpd.server_close()


def test_make_proxy_server_default_loopback_hop_is_plaintext_even_in_production(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_POSTURE", "production")
    monkeypatch.delenv("VIGIL_HOP_TLS", raising=False)
    httpd = uiproxy.make_proxy_server("127.0.0.1", 0, tmp_path)  # backends=None ⇒ loopback trio
    try:
        assert httpd.hop_tls is None
    finally:
        httpd.server_close()


# --------------------------------------------------------------------------------------------------
# The TLS hop ROUND-TRIPS (and a plaintext hop to a TLS backend fails closed).
# --------------------------------------------------------------------------------------------------
def test_tls_hop_round_trips_via_hop_connection(tmp_path):
    cert, _key = _selfsigned(tmp_path)
    with _TLSBackend(cert, _key) as srv:
        ctx = uiproxy.build_hop_tls_context({"VIGIL_HOP_TLS": "require", "VIGIL_HOP_CA": cert})
        assert isinstance(ctx, ssl.SSLContext)
        conn = uiproxy._hop_connection("localhost", srv.port, timeout=5, tls_ctx=ctx)
        try:
            conn.request("GET", "/api/whoami")
            resp = conn.getresponse()
            data = json.loads(resp.read())
        finally:
            conn.close()
        assert resp.status == 200 and data["authenticated"] is True


def test_whoami_round_trips_over_tls_and_plaintext_fails_closed(tmp_path):
    cert, _key = _selfsigned(tmp_path)
    with _TLSBackend(cert, _key) as srv:
        ctx = uiproxy.build_hop_tls_context({"VIGIL_HOP_TLS": "require", "VIGIL_HOP_CA": cert})
        principal = uiproxy._whoami("a-bearer", host="localhost", port=srv.port, tls_ctx=ctx)
        assert principal is not None and principal["username"] == "op"
        # NEGATIVE CONTROL: a PLAINTEXT hop to the TLS backend fails closed (None), so the TLS round-trip
        # above is not passing by accident — TLS is genuinely required to talk to a TLS cockpit.
        assert uiproxy._whoami("a-bearer", host="localhost", port=srv.port,
                               timeout=4.0, tls_ctx=None) is None


def test_tls_hop_rejects_an_untrusted_server_cert(tmp_path):
    # The verifying client must REJECT a server cert it has no CA for (verification is real). The client
    # uses only the SYSTEM trust store (no VIGIL_HOP_CA), which does not trust our self-signed backend.
    cert, _key = _selfsigned(tmp_path)
    with _TLSBackend(cert, _key) as srv:
        ctx = uiproxy.build_hop_tls_context({"VIGIL_HOP_TLS": "require"})  # system CAs only
        conn = uiproxy._hop_connection("localhost", srv.port, timeout=5, tls_ctx=ctx)
        with pytest.raises((ssl.SSLError, ssl.SSLCertVerificationError, OSError)):
            conn.request("GET", "/api/whoami")
            conn.getresponse()
        conn.close()


# --------------------------------------------------------------------------------------------------
# MUTUAL TLS — the proxy authenticates itself; a peer with no client cert is refused.
# --------------------------------------------------------------------------------------------------
def test_mtls_client_cert_is_presented_and_absence_is_refused(tmp_path):
    cert, key = _selfsigned(tmp_path)
    with _TLSBackend(cert, key, require_client_cert=True) as srv:
        # WITH a client cert → the proxy authenticates to the backend; the round-trip works.
        ctx = uiproxy.build_hop_tls_context({
            "VIGIL_HOP_TLS": "mtls", "VIGIL_HOP_CA": cert,
            "VIGIL_HOP_CLIENT_CERT": cert, "VIGIL_HOP_CLIENT_KEY": key})
        assert uiproxy._whoami("b", host="localhost", port=srv.port, tls_ctx=ctx) is not None
        # NEGATIVE CONTROL: no client cert → the client-cert-REQUIRING backend refuses the handshake, so
        # the delegated whoami fails closed (None). "A peer without a valid client certificate is refused."
        ctx_noclient = uiproxy.build_hop_tls_context({"VIGIL_HOP_TLS": "on", "VIGIL_HOP_CA": cert})
        assert uiproxy._whoami("b", host="localhost", port=srv.port, tls_ctx=ctx_noclient) is None


# --------------------------------------------------------------------------------------------------
# Cert/key loading FAILS CLOSED (missing / invalid / half-configured).
# --------------------------------------------------------------------------------------------------
def test_context_is_none_when_hop_tls_disabled():
    assert uiproxy.build_hop_tls_context({}) is None
    assert uiproxy.build_hop_tls_context({"VIGIL_HOP_TLS": "off"}) is None
    assert uiproxy.build_hop_tls_context({"VIGIL_HOP_TLS": "0"}) is None


def test_missing_ca_file_fails_closed(tmp_path):
    with pytest.raises((FileNotFoundError, ssl.SSLError, OSError)):
        uiproxy.build_hop_tls_context({"VIGIL_HOP_TLS": "require",
                                       "VIGIL_HOP_CA": str(tmp_path / "nope.pem")})


def test_invalid_ca_file_fails_closed(tmp_path):
    bad = tmp_path / "bad-ca.pem"
    bad.write_text("this is not a certificate\n")
    with pytest.raises((ssl.SSLError, OSError, ValueError)):
        uiproxy.build_hop_tls_context({"VIGIL_HOP_TLS": "require", "VIGIL_HOP_CA": str(bad)})


def test_half_configured_mtls_is_refused(tmp_path):
    cert, key = _selfsigned(tmp_path)
    with pytest.raises(ValueError):
        uiproxy.build_hop_tls_context({"VIGIL_HOP_TLS": "on", "VIGIL_HOP_CLIENT_CERT": cert})
    with pytest.raises(ValueError):
        uiproxy.build_hop_tls_context({"VIGIL_HOP_TLS": "on", "VIGIL_HOP_CLIENT_KEY": key})


def test_invalid_client_cert_fails_closed(tmp_path):
    bad = tmp_path / "bad.pem"
    bad.write_text("nope\n")
    with pytest.raises((ssl.SSLError, OSError, ValueError)):
        uiproxy.build_hop_tls_context({"VIGIL_HOP_TLS": "on",
                                       "VIGIL_HOP_CLIENT_CERT": str(bad), "VIGIL_HOP_CLIENT_KEY": str(bad)})
