"""Audit E5 — the ownership fetcher against REAL loopback HTTPS servers (no fake connection objects).

http.client hands the socket to the response object and sets ``conn.sock = None`` once a response says
``Connection: close`` (or is HTTP/1.0). The fetcher used to re-arm its body-read timeout through
``conn.sock`` after the response, so verification failed against essentially every real server (they all
honour the ``Connection: close`` the fetcher itself sends). The fix keeps the TLS socket the request
actually went out on, re-arms the remaining budget before EVERY send and recv on it (a server dripping one
byte per recv can no longer outlast the absolute deadline; the name resolution is bounded by the same
budget), checks the connected peer (``getpeername`` before any byte is sent) is the vetted address, and
closes that socket itself. A failure (resolve, connect, TLS, transport) shows the customer only the
fetcher's own fixed wording; the resolver / TLS / socket error text goes to the operator audit.

Loopback is on the fetcher's SSRF deny list, so these tests use test-only seams (monkeypatch): the module's
``_addr_is_internal`` is narrowed to allow exactly 127.0.0.1, ``_HTTPS_PORT`` is pointed at the ephemeral
test port, and a self-signed cert is trusted through the fetcher's own ``ssl_context`` injection. Nothing in
production can reach these seams (``config.ownership_fetcher`` builds ``WellKnownFetcher()`` with the
defaults).
"""
from __future__ import annotations

import datetime
import gc
import http.client
import http.server
import itertools
import json
import socket
import ssl
import tempfile
import threading
import time
import warnings

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from sigil.governor.asset_ownership import METHOD_DNS_TXT, METHOD_META_TAG, METHOD_WELL_KNOWN
from sigil.ui import ownership_fetch as of
from sigil.ui.ownership_fetch import OwnershipFetchError, WellKnownFetcher

HOST = "apme.cm"
DOH = "cloudflare-dns.com"
TOKEN = b"vigil-site-verification=TOK"
DOH_BODY = json.dumps({"Answer": [{"type": 16, "data": '"vigil-site-verification=TOK"'}]}).encode()
DRIP_S = 0.1                                            # one byte every 100 ms ...
DRIP_N = 60                                             # ... for 6 s — far past the budgets used below
STALL_DRIP_S = 0.05                                     # drip-then-stall: one byte every 50 ms ...
STALL_DRIP_N = 18                                       # ... for ~0.9 s of a 1 s budget, then silence
SLACK_S = 0.5                                           # scheduling slack allowed past a budget


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
    ``keepalive`` (HTTP/1.1, Content-Length, no close header), ``http10`` (HTTP/1.0), ``eof`` (no
    Content-Length: the body ends when the server closes), ``drip-head`` / ``drip-body`` (the header block /
    the body trickles out one byte per ``DRIP_S``), ``stall-head`` / ``stall-body`` (the header block / the
    body trickles for most of the budget, then the server goes silent until ``stop()``), ``badstatus`` (a
    malformed status line). ``stop()`` joins every handler thread, so ``requests`` is final once it returns."""

    def __init__(self, cert_files, mode, *, bind="127.0.0.1", tls=True, status=200, body=None):
        self.requests: list[str] = []
        self._quit = threading.Event()
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0" if mode == "http10" else "HTTP/1.1"
            timeout = 10                                # a handler can never hang the teardown join

            def do_GET(self):
                outer.requests.append(self.path)
                if body is not None:
                    b = body
                elif self.path.startswith("/dns-query"):
                    b = DOH_BODY
                else:
                    b = TOKEN
                if mode == "badstatus":
                    self.wfile.write(b"HTTP/1.1 two-hundred OK\r\n\r\n")
                    return
                if mode == "stall-head":
                    self.wfile.write(b"HTTP/1.1 200 OK\r\nX-Drip: ")
                    for _ in range(STALL_DRIP_N):
                        self.wfile.write(b"y")
                        time.sleep(STALL_DRIP_S)
                    outer._quit.wait(10)                # silent: neither more bytes nor a close
                    return
                if mode == "stall-body":
                    self.send_response(200)
                    self.send_header("Content-Length", "4000")
                    self.end_headers()
                    for _ in range(STALL_DRIP_N):
                        self.wfile.write(b"x")
                        time.sleep(STALL_DRIP_S)
                    outer._quit.wait(10)
                    return
                if mode == "drip-head":
                    self.wfile.write(b"HTTP/1.1 200 OK\r\nX-Drip: ")
                    for _ in range(DRIP_N):
                        self.wfile.write(b"y")
                        time.sleep(DRIP_S)
                    self.wfile.write(b"\r\nContent-Length: %d\r\n\r\n" % len(b) + b)
                    return
                self.send_response(status)
                if status in (301, 302):
                    self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
                if mode == "drip-body":
                    self.send_header("Content-Length", str(DRIP_N))
                    self.end_headers()
                    for _ in range(DRIP_N):
                        self.wfile.write(b"x")
                        time.sleep(DRIP_S)
                    return
                if mode != "eof":
                    self.send_header("Content-Length", str(len(b)))
                if mode in ("close", "eof"):
                    self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(b)

            def log_message(self, *a):
                pass

        class Srv(http.server.ThreadingHTTPServer):
            daemon_threads = False                      # server_close() joins the handler threads

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
        self._stopped = False

    def stop(self):
        if not self._stopped:
            self._stopped = True
            self._quit.set()
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


class _RawPeer:
    """A bare TCP (optionally TLS) listener for ONE connection. With ``reply`` it reads the request head and
    answers ``reply`` WITHOUT closing; then it waits for the client to close its end. ``saw_eof`` is set
    when the client's FIN arrives — the client really closed the socket, it was not left for the garbage
    collector."""

    def __init__(self, cert_files=None, *, bind="127.0.0.1", reply=None):
        self.saw_eof = threading.Event()
        self._lsock = socket.create_server((bind, 0))
        self._lsock.settimeout(5)
        self.port = self._lsock.getsockname()[1]
        self._ctx = None
        if cert_files is not None:
            self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self._ctx.load_cert_chain(*cert_files)
        self._reply = reply
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()

    def _run(self):
        try:
            c, _ = self._lsock.accept()
        except OSError:
            return
        c.settimeout(5)
        try:
            if self._ctx is not None:
                c = self._ctx.wrap_socket(c, server_side=True)
            if self._reply is not None:
                head = b""
                while b"\r\n\r\n" not in head:
                    chunk = c.recv(4096)
                    if not chunk:
                        return
                    head += chunk
                c.sendall(self._reply)
            while c.recv(4096):
                pass
            self.saw_eof.set()
        except OSError:
            pass                                        # a timeout here means: no EOF from the client
        finally:
            c.close()

    def stop(self):
        self._lsock.close()
        self._t.join(10)


@pytest.fixture
def raw_peer(monkeypatch):
    started: list[_RawPeer] = []
    monkeypatch.setattr(of, "_addr_is_internal", lambda ip: str(ip) != "127.0.0.1")

    def _start(*a, **kw):
        p = _RawPeer(*a, **kw)
        started.append(p)
        monkeypatch.setattr(of, "_HTTPS_PORT", p.port)
        return p
    yield _start
    for p in started:
        p.stop()


@pytest.fixture
def closed_port(monkeypatch):
    """A loopback port that is bound but NOT listening: a connect there is refused at once (no race with
    another process grabbing a just-freed port)."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    monkeypatch.setattr(of, "_addr_is_internal", lambda ip: str(ip) != "127.0.0.1")
    monkeypatch.setattr(of, "_HTTPS_PORT", sock.getsockname()[1])
    yield
    sock.close()


_EXPECTED = {METHOD_WELL_KNOWN: TOKEN.decode(), METHOD_META_TAG: TOKEN.decode(),
             METHOD_DNS_TXT: ["vigil-site-verification=TOK"]}


@pytest.mark.parametrize("mode", ["close", "keepalive", "http10", "eof"])
@pytest.mark.parametrize("method", [METHOD_WELL_KNOWN, METHOD_META_TAG, METHOD_DNS_TXT])
def test_real_server_fetch_succeeds_for_every_connection_mode(serve, cert_files, mode, method):
    """The E5 regression: a ``Connection: close`` / HTTP/1.0 / close-delimited response used to fail every
    method with ``'NoneType' object has no attribute 'settimeout'``; keep-alive must keep working."""
    s = serve(mode)
    out = _fetcher(cert_files).fetch(method, HOST)
    assert out == _EXPECTED[method]
    s.stop()
    assert len(s.requests) == 1
    if method == METHOD_DNS_TXT:
        assert s.requests[0].startswith("/dns-query?name=_vigil-challenge.apme.cm&type=TXT")


@pytest.mark.parametrize("mode", ["close", "keepalive"])
def test_real_server_redirect_is_not_followed(serve, cert_files, mode):
    s = serve(mode, status=302, body=b"")
    with pytest.raises(OwnershipFetchError, match="HTTP 302"):
        _fetcher(cert_files).fetch(METHOD_WELL_KNOWN, HOST)
    s.stop()
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
    s.stop()
    assert s.requests == []


def test_plain_http_server_is_refused(serve, cert_files):
    """https only: a plain-HTTP listener fails the TLS handshake — no plaintext fallback."""
    s = serve("close", tls=False)
    with pytest.raises(OwnershipFetchError, match="TLS"):
        _fetcher(cert_files).fetch(METHOD_WELL_KNOWN, HOST)
    s.stop()
    assert s.requests == []


def test_untrusted_cert_is_refused(serve, cert_files):
    """Without the injected trust anchor the self-signed cert is rejected (cert validation is on)."""
    s = serve("close")
    with pytest.raises(OwnershipFetchError, match="TLS"):
        WellKnownFetcher(resolver=_loopback_resolver).fetch(METHOD_WELL_KNOWN, HOST)
    s.stop()
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
    s.stop()
    assert s.requests == []


def test_refused_peer_socket_is_closed_at_once(raw_peer, cert_files, monkeypatch):
    """The connection the peer check refuses is closed by the fetcher itself: the listener sees the FIN
    while the caller still holds the exception (whose traceback keeps the fetcher's frames alive)."""
    peer = raw_peer(bind="127.0.0.2")
    real = socket.create_connection
    monkeypatch.setattr(of, "_connect", lambda addr, timeout=None: real(("127.0.0.2", addr[1]), timeout))
    with pytest.raises(OwnershipFetchError, match="not the vetted address") as ei:
        _fetcher(cert_files).fetch(METHOD_WELL_KNOWN, HOST)
    assert ei.value.__traceback__ is not None
    assert peer.saw_eof.wait(2.0)


def test_undeterminable_peer_is_refused():
    """Fail-closed: a socket whose peer cannot be read (unconnected) is refused, never passed."""
    with socket.socket() as sock:
        with pytest.raises(OwnershipFetchError, match="could not determine"):
            of._require_peer(sock, "127.0.0.1")


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
    s.stop()
    assert s.requests == []


def test_pinned_connection_never_dials_on_its_own(serve, cert_files):
    """The request can only go out on the vetted socket: were ``conn.sock`` ever None at request time,
    http.client would otherwise auto-connect by HOSTNAME (a fresh, unpinned DNS resolve)."""
    serve("keepalive")
    f = _fetcher(cert_files)
    conn, tls = f._open_pinned_https(HOST, time.monotonic())
    dialed = []
    conn._create_connection = lambda *a, **kw: dialed.append(a)   # http.client's own dial hook
    try:
        conn.sock = None
        with pytest.raises(http.client.NotConnected):
            conn.request("GET", "/")
    finally:
        tls.close()
    assert dialed == []


# --- the absolute budget ----------------------------------------------------------------------------

def _clock_spent_after(n_calls):
    """A monotonic clock that reads 0 for the first ``n_calls`` reads, then far past any budget."""
    calls = [0]

    def mono():
        calls[0] += 1
        return 0.0 if calls[0] <= n_calls else 1e6
    return mono


def test_budget_is_checked_before_resolving(serve, cert_files):
    """Clock reads: fetch start, then the resolve. Spent there → refused before the resolver is asked."""
    s = serve("close")
    asked = []

    def res(host, port, **kw):
        asked.append(host)
        return _loopback_resolver(host, port)
    with pytest.raises(OwnershipFetchError, match="total time budget"):
        WellKnownFetcher(resolver=res, monotonic=_clock_spent_after(1)).fetch(METHOD_WELL_KNOWN, HOST)
    s.stop()
    assert asked == [] and s.requests == []


def test_budget_is_rechecked_before_the_request_is_sent(serve, cert_files):
    """Clock reads: fetch start, resolve, connect, handshake, then the request send. Spent at the send →
    refused, and the server never receives a request."""
    s = serve("close")
    with pytest.raises(OwnershipFetchError, match="total time budget"):
        _fetcher(cert_files, monotonic=_clock_spent_after(4)).fetch(METHOD_WELL_KNOWN, HOST)
    s.stop()
    assert s.requests == []


@pytest.mark.parametrize("mode", ["close", "keepalive"])
def test_budget_is_rechecked_before_the_first_response_read(serve, cert_files, mode):
    """The 6th clock read is the first recv of the response: spent there → refused although the server
    answered at once."""
    s = serve(mode)
    with pytest.raises(OwnershipFetchError, match="total time budget"):
        _fetcher(cert_files, monotonic=_clock_spent_after(5)).fetch(METHOD_WELL_KNOWN, HOST)
    s.stop()
    assert len(s.requests) == 1


@pytest.mark.parametrize("mode", ["drip-head", "drip-body"])
@pytest.mark.parametrize("method", [METHOD_WELL_KNOWN, METHOD_DNS_TXT])
def test_drip_fed_response_is_cut_at_the_total_budget(serve, cert_files, mode, method):
    """A server that trickles its headers or its body one byte per 100 ms (each recv well inside the 0.5 s
    per-op timeout) for 6 s is refused once the 1 s TOTAL budget is spent — not after the whole drip."""
    serve(mode)
    t0 = time.monotonic()
    with pytest.raises(OwnershipFetchError):
        _fetcher(cert_files, timeout=0.5, total_timeout=1.0).fetch(method, HOST)
    assert time.monotonic() - t0 < 1.0 + SLACK_S


@pytest.mark.parametrize("mode", ["stall-head", "stall-body"])
def test_drip_then_stall_is_cut_at_the_total_budget_not_a_per_op_timeout_later(serve, cert_files, mode):
    """The deadline is ABSOLUTE: each recv's own timeout is capped at what is LEFT of the budget. The server
    drips for ~0.9 s of the 1 s budget and then goes silent, with a per-op timeout (3 s) LONGER than the
    whole budget — the silent recv must end at the 1 s deadline, not a full timeout after the last byte."""
    serve(mode)
    t0 = time.monotonic()
    with pytest.raises(OwnershipFetchError):
        _fetcher(cert_files, timeout=3.0, total_timeout=1.0).fetch(METHOD_WELL_KNOWN, HOST)
    assert time.monotonic() - t0 < 1.0 + SLACK_S


@pytest.mark.parametrize("method", [METHOD_WELL_KNOWN, METHOD_DNS_TXT])
def test_slow_name_resolution_is_cut_at_the_total_budget(serve, cert_files, method):
    """A customer's nameserver that drops queries leaves the system resolver retrying for tens of seconds:
    the fetch gives up at the deadline (per-op timeout 3 s, total budget 1 s) and never connects."""
    s = serve("keepalive")
    release = threading.Event()

    def stuck(host, port, **kw):
        release.wait(5)
        return _loopback_resolver(host, port)
    f = WellKnownFetcher(resolver=stuck, ssl_context=ssl.create_default_context(cafile=cert_files[0]),
                         timeout=3.0, total_timeout=1.0)
    t0 = time.monotonic()
    try:
        with pytest.raises(OwnershipFetchError) as ei:
            f.fetch(method, HOST)
        elapsed = time.monotonic() - t0
    finally:
        release.set()                                   # let the abandoned resolver worker finish
    assert elapsed < 1.0 + SLACK_S
    assert str(ei.value) == f"could not resolve {(DOH if method == METHOD_DNS_TXT else HOST)!r}"
    assert ei.value.detail.startswith("TimeoutError: ")
    s.stop()
    assert s.requests == []


# --- customer-facing errors vs the operator audit ---------------------------------------------------

_INTERNALS = ("SSL", "_ssl.c", "certificate verify", "self-signed", "Error", "Errno")


def test_tls_failure_shows_a_fixed_reason_and_keeps_the_detail_for_the_operator(serve, cert_files):
    serve("close")
    with pytest.raises(OwnershipFetchError) as ei:
        WellKnownFetcher(resolver=_loopback_resolver).fetch(METHOD_WELL_KNOWN, HOST)   # untrusted cert
    assert str(ei.value) == "TLS to 'apme.cm' failed"
    assert "CERTIFICATE_VERIFY_FAILED" in ei.value.detail


def test_transport_failure_shows_a_fixed_reason_and_keeps_the_detail_for_the_operator(serve, cert_files):
    serve("badstatus")
    with pytest.raises(OwnershipFetchError) as ei:
        _fetcher(cert_files).fetch(METHOD_META_TAG, HOST)
    assert str(ei.value) == "meta-tag fetch failed"
    assert "BadStatusLine" in ei.value.detail


@pytest.mark.parametrize("method", [METHOD_WELL_KNOWN, METHOD_META_TAG, METHOD_DNS_TXT])
def test_connect_failure_shows_a_fixed_reason_and_keeps_the_detail_for_the_operator(closed_port, cert_files,
                                                                                    method):
    """Host down / firewalled / connect timeout: an ``OwnershipFetchError`` naming the host actually dialled
    (the DoH resolver for dns-txt), never a bare socket exception."""
    with pytest.raises(OwnershipFetchError) as ei:
        _fetcher(cert_files).fetch(method, HOST)
    assert str(ei.value) == f"could not connect to {(DOH if method == METHOD_DNS_TXT else HOST)!r}"
    assert ei.value.detail.startswith("ConnectionRefusedError: ")


def test_failed_exchange_closes_its_tls_socket_while_the_error_is_held(raw_peer, cert_files):
    """The server answers on a kept-alive connection with a malformed status line; the fetch fails inside
    the exchange. The fetcher closes the TLS socket itself: the server sees the FIN while the caller still
    holds the exception (whose traceback keeps the exchange's frame, and its locals, alive)."""
    peer = raw_peer(cert_files, reply=b"HTTP/1.1 two-hundred OK\r\n\r\n")
    with pytest.raises(OwnershipFetchError, match="well-known fetch failed") as ei:
        _fetcher(cert_files).fetch(METHOD_WELL_KNOWN, HOST)
    assert ei.value.__traceback__ is not None
    assert peer.saw_eof.wait(2.0)


@pytest.mark.parametrize("status", [200, 404])
def test_finished_exchange_leaves_no_socket_for_the_garbage_collector(serve, cert_files, status):
    """On the normal paths too the TLS socket is closed explicitly — no 'unclosed socket' ResourceWarning."""
    s = serve("keepalive", status=status, body=None if status == 200 else b"")
    with warnings.catch_warnings(record=True) as seen:
        warnings.simplefilter("always", ResourceWarning)
        try:
            _fetcher(cert_files).fetch(METHOD_WELL_KNOWN, HOST)
        except OwnershipFetchError:
            assert status == 404
        gc.collect()
    ours = [w for w in seen if issubclass(w.category, ResourceWarning)
            and f"raddr=('127.0.0.1', {s.port})" in str(w.message)]
    assert ours == []


_iss = itertools.count(1)


@pytest.fixture
def prov(monkeypatch):
    """A vault-backed Provisioner (as ``test_provision_target``) whose fetcher is the REAL one."""
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    from sigil.governor.customers import CustomerRegistry
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.governor.orgs import OrgRegistry
    from sigil.governor.wallet import WalletRegistry
    from sigil.spine.store import SpineStore
    from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
    from sigil.ui.login_ratelimit import LoginRateLimiter
    from sigil.ui.provision import Provisioner

    def _make(fetcher):
        ensure_owner_keypair()
        s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
        orgs = OrgRegistry(s)
        p = Provisioner(s, customers=CustomerRegistry(s), orgs=orgs, wallet=WalletRegistry(s),
                        email_tokens=EmailTokenLedger(tempfile.mkdtemp(), ttl_s=1e4),
                        rate_limiter=LoginRateLimiter(tempfile.mkdtemp(), max_fails=1000, window_s=1e4,
                                                      base_lock_s=1.0),
                        email_sender=NullEmailSender(), target_fetcher=fetcher,
                        now_fn=lambda: float(next(_iss)))
        orgs.create_org("org_a", "org_a", owner="u_op", issued_at=float(next(_iss)))
        orgs.grant_membership("org_a", "u_op", "operator", issued_at=float(next(_iss)))
        return p, s
    return _make


def _verify_audits(store):
    return [r.payload for r in store.iter_records()
            if isinstance(r.payload, dict) and r.payload.get("signal") == "provision.audit"
            and r.payload.get("action") == "target_verify"]


def test_self_serve_verify_mints_the_authority_against_a_connection_close_server(serve, cert_files, prov):
    """End to end: challenge → the customer publishes the marker on a real server that answers
    ``Connection: close`` → target_verify records the proof and mints the owner-signed authority."""
    p, s = prov(_fetcher(cert_files))
    ch = p.target_challenge("u_op", "org_a", HOST)
    serve("close", body=ch["well_known_body"].encode())
    r = p.target_verify("u_op", "org_a", HOST, METHOD_WELL_KNOWN, authorized=True)
    assert r["scope"] == [HOST] and r["environment"] == "live"
    assert [a["outcome"] for a in _verify_audits(s)] == ["authorized"]


def test_customer_never_sees_tls_internals_the_operator_audit_does(serve, cert_files, prov):
    from sigil.ui.provision import ProvisionDenied
    serve("close")
    p, s = prov(WellKnownFetcher(resolver=_loopback_resolver))           # production trust: self-signed fails
    with pytest.raises(ProvisionDenied) as ei:
        p.target_verify("u_op", "org_a", HOST, METHOD_WELL_KNOWN, authorized=True)
    msg = str(ei.value)
    assert msg == "could not read the published token: TLS to 'apme.cm' failed"
    assert not any(x in msg for x in _INTERNALS)
    (audit,) = _verify_audits(s)
    assert audit["outcome"] == "fetch_failed" and "CERTIFICATE_VERIFY_FAILED" in audit["reason"]


def test_fixed_refusal_reason_reaches_customer_and_audit(serve, cert_files, prov):
    """A refusal in the fetcher's own words (here: the marker is not published, HTTP 404) is what the
    customer needs to act on, and the operator audit records the same reason."""
    from sigil.ui.provision import ProvisionDenied
    serve("close", status=404, body=b"")
    p, s = prov(_fetcher(cert_files))
    with pytest.raises(ProvisionDenied) as ei:
        p.target_verify("u_op", "org_a", HOST, METHOD_WELL_KNOWN, authorized=True)
    assert str(ei.value) == "could not read the published token: well-known returned HTTP 404"
    (audit,) = _verify_audits(s)
    assert audit["outcome"] == "fetch_failed" and audit["reason"] == "well-known returned HTTP 404"


def test_resolver_is_asked_for_the_https_port_and_internal_still_refused(cert_files):
    """Without the loopback seam the real SSRF gate refuses 127.0.0.1 before any connect."""
    seen = []

    def res(host, port, **kw):
        seen.append(port)
        return _loopback_resolver(host, port)
    with pytest.raises(OwnershipFetchError, match="non-global"):
        WellKnownFetcher(resolver=res).fetch(METHOD_WELL_KNOWN, HOST)
    assert seen == [443]


def test_connect_failure_reaches_customer_as_a_fixed_reason_and_the_audit_with_detail(closed_port, cert_files,
                                                                                       prov):
    """End to end (dns-txt, whose dialled peer is the DoH resolver): the customer is told what failed in the
    fetcher's own words — not a well-known message for a dns-txt verify — and the audit keeps the socket
    error."""
    from sigil.ui.provision import ProvisionDenied
    p, s = prov(_fetcher(cert_files))
    with pytest.raises(ProvisionDenied) as ei:
        p.target_verify("u_op", "org_a", HOST, METHOD_DNS_TXT, authorized=True)
    assert str(ei.value) == "could not read the published token: could not connect to 'cloudflare-dns.com'"
    (audit,) = _verify_audits(s)
    assert audit["outcome"] == "fetch_failed" and audit["reason"].startswith("ConnectionRefusedError: ")
