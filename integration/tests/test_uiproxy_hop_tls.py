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
import time
from pathlib import Path

import pytest
import yaml

from vigil_integration import uiproxy

REPO_ROOT = Path(__file__).resolve().parents[2]

# The three federation targets in the two shapes that matter to the production gate.
_REMOTE = {"sovereign": ("vigil-sovereign", 8733), "console": ("127.0.0.1", 8787), "api": ("127.0.0.1", 8799)}
_LOOPBACK = {"sovereign": ("127.0.0.1", 8733), "console": ("127.0.0.1", 8787), "api": ("127.0.0.1", 8799)}


# --------------------------------------------------------------------------------------------------
# A throwaway self-signed cert (SAN: localhost + 127.0.0.1), generated with openssl at test time (never
# committed — a committed private key trips secret scanners). One keypair does triple duty: the backend's
# server identity, the client identity for mTLS, AND its own CA (a self-signed cert verifies itself) — so a
# single cert exercises server-auth, client-auth, and CA verification.
# --------------------------------------------------------------------------------------------------
def _selfsigned(dirpath: Path, name: str = "hop") -> "tuple[str, str]":
    """Generate an INDEPENDENT self-signed cert (its own CA) for CN=localhost with SAN localhost+127.0.0.1.
    ``name`` distinguishes multiple cert/key pairs in one dir — two calls with different names yield two
    UNRELATED CAs for the SAME hostname, exactly what the trust-anchor / MITM tests need."""
    cert = dirpath / f"{name}-cert.pem"
    key = dirpath / f"{name}-key.pem"
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

    def __init__(self, cert: str, key: str, *, require_client_cert: bool = False, handler=None):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert, keyfile=key)
        if require_client_cert:
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.load_verify_locations(cafile=cert)
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler or _Handler)
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


# ==================================================================================================
# OBJ-1 (red-pen NEEDS-REWORK) — VIGIL_HOP_CA PINS to the operator CA; the system store is NOT trusted.
# The old code did create_default_context() (system store) + load_verify_locations(operator_ca), so a leaf
# mis-issued (or coerced) from ANY of the ~120 public CAs completed the handshake and MITM'd the hop. The
# fix builds ssl.SSLContext(PROTOCOL_TLS_CLIENT) + load_verify_locations(operator_ca) — only that CA is
# trusted. These two tests prove the pin at the handshake AND at the trust store.
# ==================================================================================================
def test_operator_ca_pin_rejects_a_same_host_cert_from_a_DIFFERENT_ca(tmp_path):
    # Two UNRELATED self-signed CAs, BOTH valid for the SAME backend hostname (localhost / 127.0.0.1).
    op_cert, op_key = _selfsigned(tmp_path, "operator-ca")
    rogue_cert, rogue_key = _selfsigned(tmp_path, "rogue-ca")   # models a mis-issued/coerced public-CA leaf
    pin_to_operator = {"VIGIL_HOP_TLS": "require", "VIGIL_HOP_CA": op_cert}

    # POSITIVE: a cert issued by the OPERATOR CA is accepted.
    with _TLSBackend(op_cert, op_key) as good:
        ctx = uiproxy.build_hop_tls_context(pin_to_operator)
        conn = uiproxy._hop_connection("localhost", good.port, timeout=5, tls_ctx=ctx)
        try:
            conn.request("GET", "/api/whoami")
            assert conn.getresponse().status == 200
        finally:
            conn.close()

    # THE MITM (the exact objection): the SAME operator pin must REJECT a leaf for the SAME hostname issued
    # by a DIFFERENT CA. Under the OLD code, if `rogue-ca` were any public CA the OS trusts, this handshake
    # would COMPLETE — the control-plane hop MITM'd. The pin makes it fail closed.
    with _TLSBackend(rogue_cert, rogue_key) as evil:
        ctx = uiproxy.build_hop_tls_context(pin_to_operator)
        conn = uiproxy._hop_connection("localhost", evil.port, timeout=5, tls_ctx=ctx)
        with pytest.raises((ssl.SSLError, ssl.SSLCertVerificationError, OSError)):
            conn.request("GET", "/api/whoami")
            conn.getresponse()
        conn.close()

    # CONTROL: pinning to the CA that ACTUALLY issued the rogue cert accepts it — proving the rejection
    # above is a CA-specific trust decision, not the backend merely being unreachable.
    with _TLSBackend(rogue_cert, rogue_key) as evil:
        ctx = uiproxy.build_hop_tls_context({"VIGIL_HOP_TLS": "require", "VIGIL_HOP_CA": rogue_cert})
        conn = uiproxy._hop_connection("localhost", evil.port, timeout=5, tls_ctx=ctx)
        try:
            conn.request("GET", "/api/whoami")
            assert conn.getresponse().status == 200
        finally:
            conn.close()


def test_operator_ca_pin_does_not_trust_the_system_store(tmp_path):
    op_cert, _key = _selfsigned(tmp_path, "operator-ca")
    pinned = uiproxy.build_hop_tls_context({"VIGIL_HOP_TLS": "require", "VIGIL_HOP_CA": op_cert})
    op_der = pinned.get_ca_certs(binary_form=True)
    # THE REGRESSION GUARD: exactly ONE trusted CA — the operator's. The ~120 public CAs of the system
    # store are NOT loaded. The OLD code (create_default_context + add-the-operator-CA) trusted
    # system ∪ {operator} (~121 CAs) here, so `len == 1` FAILS on that old code and passes only with the
    # PROTOCOL_TLS_CLIENT pin. The never-relaxed invariants ride along.
    assert len(op_der) == 1
    assert pinned.verify_mode == ssl.CERT_REQUIRED and pinned.check_hostname is True
    assert pinned.minimum_version >= ssl.TLSVersion.TLSv1_2

    # UNSET CA + TLS enabled ⇒ the documented default: the SYSTEM trust store (create_default_context),
    # honestly weaker. Where a real system CA bundle exists it loads many CAs and does NOT contain the
    # throwaway operator CA — proving unset != pinned.
    system = uiproxy.build_hop_tls_context({"VIGIL_HOP_TLS": "require"})
    system_der = system.get_ca_certs(binary_form=True)
    if system_der:                                   # a box with a real system CA bundle
        # The security property is that the operator CA is NOT in the system store — not the store's SIZE.
        # A minimal/single-CA system store legitimately has len==1 (audit F-08), so assert absence, not a
        # count.
        assert op_der[0] not in system_der
    assert system.verify_mode == ssl.CERT_REQUIRED and system.check_hostname is True


# ==================================================================================================
# OBJ-2 (default posture / honesty) — the shipped HA proxy manifest ARMS production posture, and a remote
# plaintext hop is never SILENT even outside production.
# ==================================================================================================
def test_ha_proxy_manifest_arms_production_posture_by_default():
    manifest = REPO_ROOT / "infra" / "ha" / "k8s" / "proxy-deployment.yaml"
    docs = [d for d in yaml.safe_load_all(manifest.read_text(encoding="utf-8")) if isinstance(d, dict)]
    deploy = next(d for d in docs if d.get("kind") == "Deployment")
    container = deploy["spec"]["template"]["spec"]["containers"][0]
    # This profile federates the credential-bearing hop to a REMOTE cockpit...
    cmd = " ".join(container.get("command", []))
    assert "--proxy-only" in cmd and "vigil-sovereign:8733" in cmd
    # ...so VIGIL_POSTURE=production must be an ACTIVE (parsed, not commented-out) env var. A commented line
    # never appears in the parsed env — this asserts the fix and would catch a regression to the shipped-
    # commented-out state that let an operator run the remote hop in cleartext with no refusal.
    env = {e["name"]: e.get("value") for e in container.get("env", []) if isinstance(e, dict) and "name" in e}
    assert env.get("VIGIL_POSTURE") == "production", (
        "the shipped HA proxy manifest MUST arm VIGIL_POSTURE=production so the remote credential-bearing "
        "hop is fail-closed (refuse-to-start) by default (W8-6)")


def test_remote_plaintext_hop_build_warns(tmp_path, monkeypatch, capsys):
    # OUTSIDE production a remote plaintext hop is ALLOWED (default byte-identical) but must never be SILENT:
    # make_proxy_server emits a structured start-time WARNING so the operator always sees the exposure.
    monkeypatch.delenv("VIGIL_POSTURE", raising=False)
    monkeypatch.delenv("VIGIL_HOP_TLS", raising=False)
    httpd = uiproxy.make_proxy_server("127.0.0.1", 0, tmp_path, backends=_REMOTE)
    try:
        err = capsys.readouterr().err
        assert "event=hop_plaintext_remote" in err and "vigil-sovereign:8733" in err
    finally:
        httpd.server_close()

    # NEGATIVE CONTROL: a LOOPBACK-only build (the single-host default) does NOT warn — its bytes never
    # traverse a network, so there is nothing to warn about.
    httpd2 = uiproxy.make_proxy_server("127.0.0.1", 0, tmp_path)   # backends=None ⇒ loopback trio
    try:
        assert "hop_plaintext_remote" not in capsys.readouterr().err
    finally:
        httpd2.server_close()


# ==================================================================================================
# OBJ-3 (test gap) — the SSE re-auth streaming loop, exercised OVER THE TLS HOP through a re-auth interval.
# ==================================================================================================
class _SSEHandler(http.server.BaseHTTPRequestHandler):
    # HTTP/1.0 + connection-close ⇒ a length-less body that ends at EOF (what read1 streams frame by frame).
    def log_message(self, *_a):
        pass

    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        self.wfile.write(b"data: one\n\n")
        self.wfile.flush()
        time.sleep(0.45)                 # a QUIET interval LONGER than the re-auth interval → timeout path
        self.wfile.write(b"data: two\n\n")
        self.wfile.flush()
        # returning closes the connection ⇒ the client's read1 returns b"" and the loop ends.


class _ReauthStub:
    """Minimal stand-in for a ProxyHandler exercising _stream_with_reauth: a wfile sink, a re-auth hook that
    counts calls (and stays authorized so the stream is NOT torn down), and a server with the tiny interval."""

    def __init__(self, interval: float):
        self.server = type("S", (), {"sse_reauth_interval": interval})()
        self.written = bytearray()
        self.reauth_calls = 0
        self.first_write_at = None          # monotonic time of the first non-empty write (prompt-delivery probe)
        stub = self

        def _write(_s, b):
            if b and stub.first_write_at is None:
                stub.first_write_at = time.monotonic()
            stub.written.extend(b)

        self.wfile = type("W", (), {"write": _write, "flush": lambda _s: None})()

    def _authenticate(self, bearer: str, *, fresh: bool = False):
        self.reauth_calls += 1
        return {"username": "op"}          # stays authorized ⇒ the stream continues


def test_sse_over_tls_streams_through_a_reauth_interval(tmp_path):
    cert, key = _selfsigned(tmp_path)
    with _TLSBackend(cert, key, handler=_SSEHandler) as srv:
        ctx = uiproxy.build_hop_tls_context({"VIGIL_HOP_TLS": "require", "VIGIL_HOP_CA": cert})
        conn = uiproxy._hop_connection("localhost", srv.port, timeout=10, tls_ctx=ctx)
        conn.request("GET", "/sovereign/api/events")
        # Mirror production (_proxy): CAPTURE the socket BEFORE getresponse — a `Connection: close` upstream
        # (every SSE backend sets it) makes will_close true and getresponse() then NULLS conn.sock.
        upstream_sock = conn.sock
        resp = conn.getresponse()
        stub = _ReauthStub(interval=0.2)               # < the 0.45s inter-frame gap ⇒ the loop re-auths live
        done = threading.Event()

        def run():
            try:
                uiproxy.ProxyHandler._stream_with_reauth(
                    stub, resp, is_sse=True, reauth_bearer="a-bearer", upstream_sock=upstream_sock)
            finally:
                done.set()

        t = threading.Thread(target=run, daemon=True)
        t.start()
        finished = done.wait(timeout=10)               # if the loop HANGS this stays False
        conn.close()

    assert finished, "the SSE-over-TLS re-auth stream HUNG (did not complete within the timeout)"
    body = bytes(stub.written)
    assert b"data: one\n\n" in body and b"data: two\n\n" in body   # both frames streamed over the TLS hop
    assert stub.reauth_calls >= 1                                   # the re-auth interval was actually crossed


# --------------------------------------------------------------------------------------------------
# OBJ-3 (regression un-mask) — a first SSE event CO-DELIVERED with the response headers must be forwarded
# PROMPTLY, and the stream must still survive a quiet interval. This one test fails on BOTH broken relays.
# --------------------------------------------------------------------------------------------------
class _CoBufferedSSEHandler(http.server.BaseHTTPRequestHandler):
    """Emit the status line, the headers AND the first SSE event in ONE write+flush, so they co-arrive in a
    single TLS record: the http.client reader pulls the event into its OWN BufferedReader while parsing the
    headers, where ``select`` on the raw fd cannot see it. Then IDLE longer than the re-auth interval before
    the second event, so the SAME stream also exercises the quiet-interval re-auth path."""

    idle_s = 3.0

    def log_message(self, *_a):
        pass

    def do_GET(self):  # noqa: N802
        self.wfile.write(b"HTTP/1.0 200 OK\r\n"
                         b"Content-Type: text/event-stream\r\n"
                         b"Connection: close\r\n\r\n"
                         b"data: one\n\n")            # first event CO-BUFFERED with the headers
        self.wfile.flush()
        time.sleep(self.idle_s)                       # a quiet interval LONGER than the re-auth interval
        self.wfile.write(b"data: two\n\n")
        self.wfile.flush()
        # returning closes the connection ⇒ the client's read1 returns b"" and the loop ends.


def test_sse_over_tls_delivers_the_cobuffered_first_event_promptly(tmp_path):
    """UN-MASK the streaming regression the earlier rework introduced. A first SSE event co-delivered with
    the response headers sits in the http.client reader's OWN buffer, invisible to ``select`` on the raw fd.
    The fixed (drain-then-select) relay forwards it IMMEDIATELY; the two broken relays do not, so this test
    FAILS on both and passes only on the fix:

      * the SELECT-STALL rework waits on ``select`` — blind to the buffered bytes — and delivers the first
        event only when the NEXT upstream byte arrives (~``idle_s`` ≈ 3.0 s later): the tight latency bound
        below FAILS.
      * the SETTIMEOUT-original delivers the first event promptly, but its read-timeout POISONS the
        makefile-wrapped socket on the quiet interval (``_timeout_occurred`` → the next read raises
        ``OSError('cannot read from timed out object')``), so the SECOND event is lost: the ``data: two``
        assertion FAILS.

    Asserting BOTH a tight first-event bound AND survival of the idle interval therefore pins the exact
    behaviour only drain-then-select provides."""
    cert, key = _selfsigned(tmp_path)
    with _TLSBackend(cert, key, handler=_CoBufferedSSEHandler) as srv:
        ctx = uiproxy.build_hop_tls_context({"VIGIL_HOP_TLS": "require", "VIGIL_HOP_CA": cert})
        conn = uiproxy._hop_connection("localhost", srv.port, timeout=10, tls_ctx=ctx)
        conn.request("GET", "/sovereign/api/events")
        upstream_sock = conn.sock                     # capture BEFORE getresponse (Connection: close nulls conn.sock)
        resp = conn.getresponse()
        stub = _ReauthStub(interval=1.0)              # < idle_s ⇒ the quiet gap crosses the re-auth boundary
        done = threading.Event()
        started = time.monotonic()

        def run():
            try:
                uiproxy.ProxyHandler._stream_with_reauth(
                    stub, resp, is_sse=True, reauth_bearer="a-bearer", upstream_sock=upstream_sock)
            finally:
                done.set()

        threading.Thread(target=run, daemon=True).start()
        finished = done.wait(timeout=10)              # if the loop HANGS this stays False
        conn.close()

    assert finished, "the SSE-over-TLS stream HUNG (did not complete within the timeout)"
    assert stub.first_write_at is not None, "the first co-buffered event was never delivered"
    first_latency = stub.first_write_at - started
    # PROMPT: the co-buffered first event must land well before the next upstream byte (~idle_s away). The
    # select-stall rework delivers it at ~idle_s (≈3.0 s) and FAILS this bound.
    assert first_latency < 0.5, (
        f"the co-buffered first SSE event stalled {first_latency:.3f}s — select() on the raw fd is blind to "
        f"bytes already buffered by the http.client reader; drain-then-select must forward them at once")
    body = bytes(stub.written)
    assert b"data: one\n\n" in body                 # the co-buffered first event
    # SURVIVES THE IDLE: the settimeout-original poisons the socket on the quiet interval and loses this.
    assert b"data: two\n\n" in body, (
        "the second event was lost — the stream did not survive the quiet interval (settimeout poisons the "
        "makefile-wrapped socket; select/drain-then-select does not)")
    assert stub.reauth_calls >= 1                     # the quiet interval actually crossed the re-auth boundary
