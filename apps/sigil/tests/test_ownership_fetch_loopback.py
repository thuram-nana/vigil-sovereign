"""Audit E5 — the ownership fetcher against REAL loopback HTTPS servers (no fake connection objects).

http.client hands the socket to the response object and sets ``conn.sock = None`` once a response says
``Connection: close`` (or is HTTP/1.0). The fetcher used to re-arm its body-read timeout through
``conn.sock`` after the response, so verification failed against essentially every real server (they all
honour the ``Connection: close`` the fetcher itself sends). The fix bounds I/O on the TLS socket the request
actually went out on, and adds a peer check (``getpeername`` before any byte is sent) that the connected
socket is the vetted address.

Loopback is on the fetcher's SSRF deny list, so these tests use test-only seams (monkeypatch): the module's
``_addr_is_internal`` is narrowed to allow exactly 127.0.0.1, ``_HTTPS_PORT`` is pointed at the ephemeral
test port, and a self-signed cert is trusted through the fetcher's own ``ssl_context`` injection. Nothing in
production can reach these seams.
"""
from __future__ import annotations

import datetime
import http.server
import json
import socket
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from sigil.governor.asset_ownership import METHOD_DNS_TXT, METHOD_META_TAG, METHOD_WELL_KNOWN
from sigil.ui import ownership_fetch as of
from sigil.ui.ownership_fetch import OwnershipFetchError, WellKnownFetcher, _require_peer

HOST = "apme.cm"
DOH = "cloudflare-dns.com"
TOKEN = b"vigil-site-verification=TOK"
DOH_BODY = json.dumps({"Answer": [{"type": 16, "data": '"vigil-site-verification=TOK"'}]}).encode()


@pytest.fixture(scope="module")
def cert_files(tmp_path_factory):
    d = tmp_path_factory.mktemp("e5cert")
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "e5-test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST), x509.DNSName(DOH)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    c, k = d / "cert.pem", d / "key.pem"
    c.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    k.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()))
    return str(c), str(k)


class _Server:
    """A real threaded HTTP(S) server on loopback. ``mode``: ``close`` (HTTP/1.1 + ``Connection: close``),
    ``keepalive`` (HTTP/1.1, Content-Length, no close header), ``http10`` (HTTP/1.0)."""

    def __init__(self, cert_files, mode, *, bind="127.0.0.1", tls=True, status=200, body=None):
        self.requests: list[str] = []
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0" if mode == "http10" else "HTTP/1.1"

            def do_GET(self):
                outer.requests.append(self.path)
                if body is not None:
                    b = body
                elif self.path.startswith("/dns-query"):
                    b = DOH_BODY
                else:
                    b = TOKEN
                self.send_response(status)
                if status in (301, 302):
                    self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
                self.send_header("Content-Length", str(len(b)))
                if mode == "close":
                    self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(b)

            def log_message(self, *a):
                pass

        class Srv(http.server.ThreadingHTTPServer):
            daemon_threads = True

            def handle_error(self, request, client_address):
                pass                                    # a client the fetcher refused mid-exchange is expected

        self.srv = Srv((bind, 0), H)
        if tls:
            sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            sctx.load_cert_chain(*cert_files)
            self.srv.socket = sctx.wrap_socket(self.srv.socket, server_side=True)
        self.port = self.srv.server_address[1]
        self._t = threading.Thread(target=self.srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self._t.start()

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()


def _loopback_resolver(host, port, **kw):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]


@pytest.fixture
def serve(cert_files, monkeypatch):
    """Start a real server and aim the fetcher's (test-only) seams at it."""
    started: list[_Server] = []
    monkeypatch.setattr(of, "_addr_is_internal", lambda ip: str(ip) != "127.0.0.1")

    def _start(mode, **kw):
        s = _Server(cert_files, mode, **kw)
        started.append(s)
        monkeypatch.setattr(of, "_HTTPS_PORT", s.port)
        return s
    yield _start
    for s in started:
        s.stop()


def _fetcher(cert_files, **kw):
    ctx = ssl.create_default_context(cafile=cert_files[0])   # the module's own trust injection seam
    return WellKnownFetcher(resolver=_loopback_resolver, ssl_context=ctx, **kw)


_EXPECTED = {METHOD_WELL_KNOWN: TOKEN.decode(), METHOD_META_TAG: TOKEN.decode(),
             METHOD_DNS_TXT: ["vigil-site-verification=TOK"]}


@pytest.mark.parametrize("mode", ["close", "keepalive", "http10"])
@pytest.mark.parametrize("method", [METHOD_WELL_KNOWN, METHOD_META_TAG, METHOD_DNS_TXT])
def test_real_server_fetch_succeeds_for_every_connection_mode(serve, cert_files, mode, method):
    """The E5 regression: a ``Connection: close`` / HTTP/1.0 response used to fail every method with
    ``'NoneType' object has no attribute 'settimeout'``; keep-alive must keep working."""
    s = serve(mode)
    out = _fetcher(cert_files).fetch(method, HOST)
    assert out == _EXPECTED[method]
    assert len(s.requests) == 1
    if method == METHOD_DNS_TXT:
        assert s.requests[0].startswith("/dns-query?name=_vigil-challenge.apme.cm&type=TXT")


@pytest.mark.parametrize("mode", ["close", "keepalive"])
def test_real_server_redirect_is_not_followed(serve, cert_files, mode):
    s = serve(mode, status=302, body=b"")
    with pytest.raises(OwnershipFetchError, match="HTTP 302"):
        _fetcher(cert_files).fetch(METHOD_WELL_KNOWN, HOST)
    assert len(s.requests) == 1                        # the Location (metadata URL) was never chased


@pytest.mark.parametrize("mode", ["close", "keepalive"])
def test_real_server_oversized_body_is_refused(serve, cert_files, mode):
    serve(mode, body=b"x" * 5000)
    with pytest.raises(OwnershipFetchError, match="too large"):
        _fetcher(cert_files, max_bytes=4096).fetch(METHOD_WELL_KNOWN, HOST)


def test_real_server_tls_hostname_mismatch_is_refused(serve, cert_files):
    """The cert names apme.cm / cloudflare-dns.com only — SNI/cert validation against the HOSTNAME holds."""
    s = serve("close")
    with pytest.raises(OwnershipFetchError, match="TLS"):
        _fetcher(cert_files).fetch(METHOD_WELL_KNOWN, "vigil-other.cm")
    assert s.requests == []


def test_plain_http_server_is_refused(serve, cert_files):
    """https only: a plain-HTTP listener fails the TLS handshake — no plaintext fallback."""
    s = serve("close", tls=False)
    with pytest.raises(OwnershipFetchError, match="TLS"):
        _fetcher(cert_files).fetch(METHOD_WELL_KNOWN, HOST)
    assert s.requests == []


def test_untrusted_cert_is_refused(serve, cert_files):
    """Without the injected trust anchor the self-signed cert is rejected (cert validation is on)."""
    s = serve("close")
    with pytest.raises(OwnershipFetchError, match="TLS"):
        WellKnownFetcher(resolver=_loopback_resolver).fetch(METHOD_WELL_KNOWN, HOST)
    assert s.requests == []


@pytest.mark.parametrize("method", [METHOD_WELL_KNOWN, METHOD_META_TAG, METHOD_DNS_TXT])
def test_peer_mismatch_is_refused_before_any_byte_is_sent(serve, cert_files, monkeypatch, method):
    """The vetted address is 127.0.0.1 but the connection actually lands on 127.0.0.2 (a real listener):
    the peer check refuses before the TLS handshake or the request — the server sees nothing."""
    s = serve("close", bind="127.0.0.2")
    real = socket.create_connection
    monkeypatch.setattr(of, "_connect", lambda addr, timeout=None: real(("127.0.0.2", addr[1]), timeout))
    with pytest.raises(OwnershipFetchError, match="not the vetted address"):
        _fetcher(cert_files).fetch(method, HOST)
    assert s.requests == []


def test_undeterminable_peer_is_refused():
    """Fail-closed: a socket whose peer cannot be read (unconnected) is refused, never passed."""
    with socket.socket() as sock:
        with pytest.raises(OwnershipFetchError, match="could not determine"):
            _require_peer(sock, "127.0.0.1")


def test_undeterminable_peer_aborts_the_fetch(serve, cert_files, monkeypatch):
    s = serve("close")
    real = socket.create_connection

    class _NoPeer:
        def __init__(self, sock):
            self._s = sock

        def getpeername(self):
            raise OSError("peer unknown")

        def __getattr__(self, name):
            return getattr(self._s, name)

    monkeypatch.setattr(of, "_connect", lambda addr, timeout=None: _NoPeer(real(addr, timeout)))
    with pytest.raises(OwnershipFetchError, match="could not determine"):
        _fetcher(cert_files).fetch(METHOD_WELL_KNOWN, HOST)
    assert s.requests == []


def _clock_spent_after(n_calls):
    """A monotonic clock that reads 0 for the first ``n_calls`` reads, then far past any budget."""
    calls = [0]

    def mono():
        calls[0] += 1
        return 0.0 if calls[0] <= n_calls else 1e6
    return mono


@pytest.mark.parametrize("mode", ["close", "keepalive"])
def test_budget_is_rechecked_before_the_body_read(serve, cert_files, mode):
    """Clock reads: fetch start, connect, handshake, request, body. Spent at the body read → refused, on
    the captured TLS socket, even after a ``Connection: close`` response nulled ``conn.sock``."""
    s = serve(mode)
    with pytest.raises(OwnershipFetchError, match="total time budget"):
        _fetcher(cert_files, monotonic=_clock_spent_after(4)).fetch(METHOD_WELL_KNOWN, HOST)
    assert len(s.requests) == 1


def test_budget_is_rechecked_before_the_request(serve, cert_files):
    s = serve("close")
    with pytest.raises(OwnershipFetchError, match="total time budget"):
        _fetcher(cert_files, monotonic=_clock_spent_after(3)).fetch(METHOD_WELL_KNOWN, HOST)
    assert s.requests == []


def test_resolver_is_asked_for_the_https_port_and_internal_still_refused(cert_files):
    """Without the loopback seam the real SSRF gate refuses 127.0.0.1 before any connect."""
    seen = []

    def res(host, port, **kw):
        seen.append(port)
        return _loopback_resolver(host, port)
    with pytest.raises(OwnershipFetchError, match="non-global"):
        WellKnownFetcher(resolver=res).fetch(METHOD_WELL_KNOWN, HOST)
    assert seen == [443]
