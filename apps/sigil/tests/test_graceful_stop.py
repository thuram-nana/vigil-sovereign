"""The cockpit, the customer edge and the public site stop GRACEFULLY on SIGTERM (what `systemctl stop|restart`
sends): a request already accepted finishes and gets its answer, a connection still waiting in the listen queue is
served (never reset), the cockpit's SSE feeds end, new connections are refused, and the process exits 0 — all
within a drain deadline shorter than the units' TimeoutStopSec. A second signal ends the drain at once.

The subprocess tests run the real `python -m sigil serve*` entry points and send real signals.

Run: SIGIL_HOME=$(mktemp -d) PYTHONPATH=apps/sigil:packages/core/vigil_core \
     .venv-sovereign/bin/python -m pytest -q apps/sigil/tests/test_graceful_stop.py
"""
from __future__ import annotations

import http.client
import json
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

from sigil.ui import custui, graceful, pubui
from sigil.ui.custui import CustomerServer
from sigil.ui.pubui import PublicServer
from sigil.ui.server import UIServer

_SIGIL = Path(__file__).resolve().parents[1]
_REPO = _SIGIL.parents[1]
_PYPATH = os.pathsep.join([str(_SIGIL), str(_REPO / "packages" / "core" / "vigil_core")])


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _spawn(tmp_path, args, extra_env=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("VIGIL_", "SIGIL_"))}
    env.update({"SIGIL_HOME": str(tmp_path / "home"), "PYTHONPATH": _PYPATH, "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONUNBUFFERED": "1"})
    env.update(extra_env or {})
    (tmp_path / "home").mkdir(exist_ok=True)
    log = open(tmp_path / "server.log", "w")  # noqa: SIM115 — closed by the caller via proc.wait
    return subprocess.Popen([sys.executable, "-m", "sigil", *args], env=env, stdout=log, stderr=subprocess.STDOUT)


def _wait_listening(port: int, proc, timeout=30.0) -> None:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        assert proc.poll() is None, "server exited during start-up"
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return
        except OSError:
            time.sleep(0.1)
    raise AssertionError(f"nothing listening on {port}")


def _refused(port: int, within: float = 1.5) -> bool:
    """True once a connection to ``port`` is REFUSED (nothing listens), polling for up to ``within`` seconds. A
    connection that is accepted, or that times out in a full listen backlog, is not a refusal."""
    end = time.monotonic() + within
    while True:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
        except ConnectionRefusedError:
            return True
        except OSError:
            pass
        if time.monotonic() >= end:
            return False
        time.sleep(0.2)


# ── the customer edge: an accepted request (a slow provisioner hop) completes across SIGTERM ─────────────────
class _SlowProvisioner(BaseHTTPRequestHandler):
    received = threading.Event()
    delay = 3.0

    def log_message(self, *a):
        pass

    def do_POST(self):  # noqa: N802
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        type(self).received.set()
        time.sleep(type(self).delay)
        body = json.dumps({"ok": True, "marker": "the-slow-answer"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.mark.parametrize("delay", [3.0, graceful.DRAIN_DEADLINE_S + 2.0],
                         ids=["quick", "slower-than-the-public-sites-deadline"])
def test_customer_edge_finishes_an_in_flight_request_on_sigterm(tmp_path, monkeypatch, delay):
    # a reset email sent inline may take up to 60 s; the edge (and the cockpit) wait for it across a stop
    monkeypatch.setattr(_SlowProvisioner, "delay", delay)
    _SlowProvisioner.received.clear()
    prov = ThreadingHTTPServer(("127.0.0.1", 0), _SlowProvisioner)
    threading.Thread(target=prov.serve_forever, daemon=True).start()
    port = _free_port()
    proc = _spawn(tmp_path, ["serve-customer", "--host", "127.0.0.1", "--port", str(port)],
                  {"VIGIL_PROVISION_HOP_KEY": "graceful-hop-key",
                   "VIGIL_PROVISION_BASE": f"http://127.0.0.1:{prov.server_address[1]}"})
    try:
        _wait_listening(port, proc)
        result: dict = {}

        def _client():
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=delay + 15)
            try:
                c.request("POST", "/api/customer/recover/request", body=json.dumps({"email": "a@example.test"}),
                          headers={"Content-Type": "application/json", "Host": f"127.0.0.1:{port}",
                                   "Origin": f"http://127.0.0.1:{port}"})
                r = c.getresponse()
                result["status"], result["body"] = r.status, r.read().decode()
            except Exception as exc:  # noqa: BLE001 — the pre-fix failure mode is a dropped connection
                result["error"] = repr(exc)

        t = threading.Thread(target=_client)
        t.start()
        assert _SlowProvisioner.received.wait(10), "the hop never reached the provisioner"
        proc.send_signal(signal.SIGTERM)
        time.sleep(0.3)
        assert _refused(port), "a stopping edge must refuse new connections"
        t.join(delay + 15)
        assert result.get("status") == 200, result
        assert json.loads(result["body"])["marker"] == "the-slow-answer"
        assert proc.wait(15) == 0
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        prov.shutdown()


class _SlowerThanTheGenericDeadline(_SlowProvisioner):
    received = threading.Event()

    def do_POST(self):  # noqa: N802
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        type(self).received.set()
        time.sleep(3.0)                                  # the generic deadline in the child below is 1 s
        body = json.dumps({"ok": True, "marker": "sent-after-the-generic-deadline"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_customer_edge_outwaits_a_cockpit_action_slower_than_the_generic_deadline(tmp_path):
    # In production the generic deadline (10 s) is shorter than what custui allows some cockpit calls (45-60 s): a
    # sign-up email taking 14 s, cut at 10 s by an edge swap, left the customer with nginx's "unavailable" page
    # while the cockpit sent the email anyway. Here the child's generic deadline is 1 s and the action takes 3 s:
    # the real `serve-customer` entry point must still wait for it, answer it, and only then exit 0.
    _SlowerThanTheGenericDeadline.received.clear()
    prov = ThreadingHTTPServer(("127.0.0.1", 0), _SlowerThanTheGenericDeadline)
    threading.Thread(target=prov.serve_forever, daemon=True).start()
    port = _free_port()
    env = {k: v for k, v in os.environ.items() if not k.startswith(("VIGIL_", "SIGIL_"))}
    env.update({"SIGIL_HOME": str(tmp_path / "home"), "PYTHONPATH": _PYPATH, "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONUNBUFFERED": "1", "VIGIL_PROVISION_HOP_KEY": "graceful-hop-key",
                "VIGIL_PROVISION_BASE": f"http://127.0.0.1:{prov.server_address[1]}"})
    (tmp_path / "home").mkdir()
    code = ("import sys\nfrom sigil.ui import graceful\ngraceful.DRAIN_DEADLINE_S = 1.0\n"
            "from sigil.cli import main\n"
            f"main(['serve-customer', '--host', '127.0.0.1', '--port', '{port}'])\n")
    log = open(tmp_path / "server.log", "w")  # noqa: SIM115 — closed below
    proc = subprocess.Popen([sys.executable, "-c", code], env=env, stdout=log, stderr=subprocess.STDOUT)
    try:
        _wait_listening(port, proc)
        result: dict = {}

        def _client():
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
            try:
                c.request("POST", "/api/customer/signup/request", body=json.dumps({"email": "a@example.test"}),
                          headers={"Content-Type": "application/json", "Host": f"127.0.0.1:{port}",
                                   "Origin": f"http://127.0.0.1:{port}"})
                r = c.getresponse()
                result["status"], result["body"] = r.status, r.read().decode()
            except Exception as exc:  # noqa: BLE001 — the pre-fix failure mode: the edge exits mid-action
                result["error"] = repr(exc)

        t = threading.Thread(target=_client)
        t.start()
        assert _SlowerThanTheGenericDeadline.received.wait(10), "the hop never reached the provisioner"
        t0 = time.monotonic()
        proc.send_signal(signal.SIGTERM)
        t.join(20)
        assert result.get("status") == 200, result
        assert json.loads(result["body"])["marker"] == "sent-after-the-generic-deadline"
        assert proc.wait(20) == 0
        assert time.monotonic() - t0 > 2.0               # it waited past the generic deadline, for the action
        log.close()
        # ... with the customer edge's own deadline (the one the units' TimeoutStopSec is sized for)
        assert f"waiting up to {custui.drain_deadline_s():g} s for 1 request(s)" in \
            (tmp_path / "server.log").read_text(encoding="utf-8")
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        log.close()
        prov.shutdown()


# ── the public site: a request still being read when SIGTERM lands is answered, then it exits 0 ──────────────
def test_public_site_drains_a_request_being_read_then_exits_cleanly(tmp_path):
    port = _free_port()
    proc = _spawn(tmp_path, ["serve-public", "--host", "127.0.0.1", "--port", str(port)])
    try:
        _wait_listening(port, proc)
        s = socket.create_connection(("127.0.0.1", port), timeout=10)
        s.sendall(b"GET / HTTP/1.0\r\n")              # the request is accepted and in flight, headers pending
        time.sleep(0.3)
        proc.send_signal(signal.SIGTERM)
        time.sleep(0.5)
        assert proc.poll() is None, "the public site exited with a request still in flight"
        assert _refused(port)
        s.sendall(b"Host: 127.0.0.1\r\n\r\n")
        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
        s.close()
        assert data.startswith(b"HTTP/1.0 200"), data[:80]
        assert proc.wait(15) == 0
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


def test_a_second_signal_ends_the_drain_at_once(tmp_path):
    port = _free_port()
    proc = _spawn(tmp_path, ["serve-public", "--host", "127.0.0.1", "--port", str(port)])
    try:
        _wait_listening(port, proc)
        s = socket.create_connection(("127.0.0.1", port), timeout=10)
        s.sendall(b"GET / HTTP/1.0\r\n")              # never completed: it would hold the drain to its deadline
        time.sleep(0.3)
        proc.send_signal(signal.SIGTERM)
        time.sleep(0.5)
        assert proc.poll() is None
        t0 = time.monotonic()
        proc.send_signal(signal.SIGINT)
        assert proc.wait(5) == 0
        assert time.monotonic() - t0 < graceful.DRAIN_DEADLINE_S / 2
        s.close()
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


# ── the cockpit: its SSE feeds end on SIGTERM and the process exits 0 well inside the deadline ──────────────
@pytest.mark.parametrize("feed", ["/api/stream", "/api/sigil/hud"], ids=["spine", "hud"])
def test_cockpit_ends_its_sse_feed_and_exits_cleanly_on_sigterm(tmp_path, feed):
    port = _free_port()
    proc = _spawn(tmp_path, ["serve", "--host", "127.0.0.1", "--port", str(port), "--token", "graceful-token"])
    try:
        _wait_listening(port, proc)
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
        c.request("GET", f"{feed}?token=graceful-token", headers={"Host": f"127.0.0.1:{port}"})
        r = c.getresponse()
        assert r.status == 200 and r.getheader("Content-Type") == "text/event-stream"
        assert r.fp.readline()                           # the feed is live (heartbeats)
        t0 = time.monotonic()
        proc.send_signal(signal.SIGTERM)
        ended = threading.Event()

        def _drain():
            try:
                while r.fp.readline():
                    pass
            except OSError:
                pass
            ended.set()

        threading.Thread(target=_drain, daemon=True).start()
        assert ended.wait(5), "the SSE feed did not end on SIGTERM"
        assert proc.wait(10) == 0
        assert time.monotonic() - t0 < graceful.DRAIN_DEADLINE_S
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


# ── the drain itself (in process) ────────────────────────────────────────────────────────────────────────────
class _Hold(BaseHTTPRequestHandler):
    release = threading.Event()
    started = threading.Event()

    def log_message(self, *a):
        pass

    def do_GET(self):  # noqa: N802
        type(self).started.set()
        type(self).release.wait(10)
        self.send_response(204)
        self.end_headers()


class _Srv(graceful.GracefulMixin, ThreadingHTTPServer):
    daemon_threads = True


def _held_request(srv):
    _Hold.release.clear()
    _Hold.started.clear()
    out: dict = {}

    def _go():
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{srv.server_address[1]}/", timeout=15) as r:
                out["status"] = r.status
        except (urllib.error.URLError, OSError) as exc:
            out["error"] = repr(exc)

    t = threading.Thread(target=_go)
    t.start()
    assert _Hold.started.wait(5)
    return t, out


def test_drain_waits_for_the_request_in_flight():
    srv = _Srv(("127.0.0.1", 0), _Hold)
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    t, out = _held_request(srv)
    assert srv.inflight() == 1
    threading.Timer(0.5, _Hold.release.set).start()
    t0 = time.monotonic()
    assert graceful.graceful_stop(srv, drain_deadline_s=5, log=lambda _m: None) is True
    assert 0.3 < time.monotonic() - t0 < 5
    t.join(5)
    assert out == {"status": 204} and srv.stopping.is_set() and srv.inflight() == 0
    srv.server_close()


def test_drain_gives_up_at_the_deadline():
    srv = _Srv(("127.0.0.1", 0), _Hold)
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    t, _out = _held_request(srv)
    t0 = time.monotonic()
    assert graceful.graceful_stop(srv, drain_deadline_s=0.4, log=lambda _m: None) is False
    assert time.monotonic() - t0 < 2
    t1 = time.monotonic()
    srv.server_close()                                   # never waits for the held request thread
    assert time.monotonic() - t1 < 1
    _Hold.release.set()
    t.join(5)


class _LongDrainSrv(_Srv):
    def drain_deadline(self) -> float:
        return 5.0


class _ShortDrainSrv(_Srv):
    def drain_deadline(self) -> float:
        return 0.4


def test_a_stop_without_an_explicit_deadline_uses_the_servers_own():
    # the deadline is the server's (the customer edge's is longer than the generic one), not one global figure
    for cls, drained in ((_LongDrainSrv, True), (_ShortDrainSrv, False)):
        srv = cls(("127.0.0.1", 0), _Hold)
        threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        t, _out = _held_request(srv)
        threading.Timer(1.0, _Hold.release.set).start()
        assert graceful.graceful_stop(srv, log=lambda _m: None) is drained, cls.__name__
        srv.server_close()
        _Hold.release.set()
        t.join(5)


def test_a_server_without_its_own_deadline_gets_the_generic_one():
    assert graceful.drain_deadline_of(object()) == graceful.DRAIN_DEADLINE_S
    assert graceful.drain_deadline_of(_LongDrainSrv.__new__(_LongDrainSrv)) == 5.0
    assert graceful.drain_deadline_of(object.__new__(CustomerServer)) == custui.drain_deadline_s()


def test_the_customer_edge_waits_past_its_slowest_cockpit_hop():
    # A stopping edge must outwait every hop it may be in: otherwise it exits while the cockpit still completes
    # the action (an email sent, a checkout created, a single-use sign-in code spent) and the customer is told
    # it failed. The public site and the cockpit keep the generic deadline.
    longest = max([custui._HOP_TIMEOUT_S, *custui._SLOW_HOP_TIMEOUTS_S.values()])
    customer = object.__new__(CustomerServer).drain_deadline()
    assert customer >= longest + 15, (customer, longest)
    assert customer == custui.drain_deadline_s()
    assert object.__new__(PublicServer).drain_deadline() == graceful.DRAIN_DEADLINE_S
    assert object.__new__(UIServer).drain_deadline() == graceful.PROVISIONER_DRAIN_DEADLINE_S
    assert graceful.DRAIN_DEADLINE_S < longest           # why the customer edge needs its own


def test_serve_until_signal_stops_on_its_event_and_closes_the_server():
    srv = _Srv(("127.0.0.1", 0), _Hold)
    stop = threading.Event()
    port = srv.server_address[1]
    done = threading.Event()
    threading.Thread(target=lambda: (graceful.serve_until_signal(srv, stop=stop, log=lambda _m: None),
                                     done.set()), daemon=True).start()
    time.sleep(0.2)
    stop.set()
    assert done.wait(5)
    assert _refused(port)


@pytest.mark.parametrize("cls", [UIServer, CustomerServer, PublicServer])
def test_the_three_servers_are_graceful(cls):
    assert issubclass(cls, graceful.GracefulMixin)
    assert cls.block_on_close is False


@pytest.mark.parametrize("unit,cls", [("sigil-cockpit.service", UIServer), ("sigil-customer.service", CustomerServer),
                                      ("sigil-public.service", PublicServer), ("sigil-customer@.service", CustomerServer),
                                      ("sigil-public@.service", PublicServer)])
def test_the_drain_deadline_is_inside_every_units_stop_timeout(unit, cls):
    # systemd SIGKILLs at TimeoutStopSec: the server's own drain must end well before that
    text = (_SIGIL / "deploy" / "systemd" / unit).read_text(encoding="utf-8")
    m = re.search(r"^TimeoutStopSec=(\d+)\s*$", text, re.M)
    assert m, f"{unit} sets no TimeoutStopSec"
    deadline = object.__new__(cls).drain_deadline()
    assert deadline + graceful.HANDSHAKE_GRACE_S + 5 <= int(m.group(1)), (unit, deadline, m.group(1))
    assert re.search(r"^KillSignal=SIGTERM\s*$", text, re.M)


class _Quick(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("Content-Length", "0"))
        body = json.dumps({"got": self.rfile.read(n).decode()}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _read_all(s: socket.socket) -> bytes:
    data = b""
    try:
        while chunk := s.recv(65536):
            data += chunk
    except OSError as exc:                               # the pre-fix outcome: the queued connection is reset
        return data + f"<{type(exc).__name__}>".encode()
    return data


def test_connections_waiting_in_the_listen_queue_are_served_not_reset():
    # The kernel completes a handshake before the server accepts it, so a client (nginx) may already have sent its
    # POST into the listen queue when the stop begins; closing the listener then would reset it, and nginx never
    # re-sends a POST. Here no accept loop runs at all: every request below is in the queue when the stop starts.
    srv = _Srv(("127.0.0.1", 0), _Quick)
    port = srv.server_address[1]
    clients = []
    for i in range(4):
        c = socket.create_connection(("127.0.0.1", port), timeout=10)
        body = f'{{"n": {i}}}'.encode()
        c.sendall(b"POST /api/customer/launch/reserve HTTP/1.0\r\nHost: x\r\nContent-Type: application/json\r\n"
                  + f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
        clients.append((c, body))
    assert graceful.graceful_stop(srv, drain_deadline_s=5, log=lambda _m: None, serving=False) is True
    for c, body in clients:
        data = _read_all(c)
        c.close()
        assert data.startswith(b"HTTP/1.0 200 "), data[:80]
        assert json.loads(data.split(b"\r\n\r\n", 1)[1]) == {"got": body.decode()}
    assert _refused(port)
    srv.server_close()


def test_a_client_that_gave_up_in_the_queue_does_not_strand_the_ones_behind_it():
    # accept() can report a connection its client aborted while queued (ECONNABORTED); the connections queued
    # behind it are still served
    srv = _Srv(("127.0.0.1", 0), _Quick)
    c = socket.create_connection(("127.0.0.1", srv.server_address[1]), timeout=10)
    c.sendall(b"POST / HTTP/1.0\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}")
    real, calls = srv.get_request, []

    def _aborted_first():
        calls.append(1)
        if len(calls) == 1:
            raise ConnectionAbortedError("the client gave up while queued")
        return real()

    srv.get_request = _aborted_first
    assert graceful.graceful_stop(srv, drain_deadline_s=5, log=lambda _m: None, serving=False) is True
    data = _read_all(c)
    c.close()
    assert data.startswith(b"HTTP/1.0 200 "), data[:80]
    srv.server_close()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the SYN filter is Linux-only")
def test_a_stopping_listener_takes_no_new_connection_but_keeps_the_ones_queued():
    srv = _Srv(("127.0.0.1", 0), _Quick)
    port = srv.server_address[1]
    queued = socket.create_connection(("127.0.0.1", port), timeout=5)       # handshake done before the hold
    if not graceful._hold_new_connections(srv):
        # A kernel that refuses the socket filter (GitHub's runners answer EPERM): the hold is an extra safeguard
        # there — the edge swap points nginx at the new edge before the old one stops, which is what loses
        # nothing (test_nginx_edge_down). The refusal is recorded, and the queued connection is still served.
        assert graceful.HOLD_UNAVAILABLE.startswith(("PermissionError", "OSError")), graceful.HOLD_UNAVAILABLE
        assert graceful._serve_waiting_connections(srv) == 1
        graceful._close_listener(srv)
        queued.close()
        srv.server_close()
        return
    t0 = time.monotonic()
    with pytest.raises(socket.timeout):                                     # a new attempt is not taken ...
        socket.create_connection(("127.0.0.1", port), timeout=0.5)
    assert time.monotonic() - t0 >= 0.45
    late: dict = {}

    def _late():
        t = time.monotonic()
        try:
            socket.create_connection(("127.0.0.1", port), timeout=5).close()
            late["r"] = "connected"
        except OSError as exc:
            late["r"], late["s"] = type(exc).__name__, time.monotonic() - t

    th = threading.Thread(target=_late)
    th.start()
    time.sleep(0.2)
    assert graceful._serve_waiting_connections(srv) == 1                     # ... the queued one still is
    graceful._close_listener(srv)
    th.join(5)
    assert late.get("r") == "ConnectionRefusedError", late                  # ... and the held one is refused
    queued.close()
    srv.server_close()


def test_the_stop_holds_new_connections_then_serves_the_queue_then_closes(monkeypatch):
    # the order is what makes the stop lose nothing: once new attempts are held, nothing can join the queue between
    # the last accept and the close
    srv = _Srv(("127.0.0.1", 0), _Quick)
    order: list = []
    for name in ("_hold_new_connections", "_serve_waiting_connections", "_close_listener"):
        def _spy(s, _real=getattr(graceful, name), _name=name):
            order.append(_name)
            return _real(s)
        monkeypatch.setattr(graceful, name, _spy)
    assert graceful.graceful_stop(srv, drain_deadline_s=1, log=lambda _m: None, serving=False) is True
    assert order == ["_hold_new_connections", "_serve_waiting_connections", "_close_listener"]
    srv.server_close()


# ── a new edge listens only once it can serve ────────────────────────────────────────────────────────────────
def _build(edge: str, port: int, tmp_path):
    if edge == "customer":
        return CustomerServer(("127.0.0.1", port), custui.CustomerHandler, hop_key="k",
                              provision_base="http://127.0.0.1:1", sessions_dir=str(tmp_path / "s"))
    return PublicServer(("127.0.0.1", port), pubui.PublicHandler)


@pytest.mark.parametrize("edge,module,name", [("customer", "custui", "build_app_snapshot"),
                                              ("public", "pubui", "SiteSnapshot")])
def test_a_new_edge_refuses_connections_until_it_can_serve(tmp_path, monkeypatch, edge, module, name):
    # During an edge swap nginx sends requests to the new edge's port as soon as it accepts connections; a request
    # handed to an edge whose startup then fails is reset (a POST is never re-sent). So the port refuses until the
    # app is read, and a startup that fails leaves the port refusing and free.
    mod = {"custui": custui, "pubui": pubui}[module]
    real = getattr(mod, name)
    port = _free_port()
    seen: dict = {}

    def _spy(*a, **k):
        seen["refused"] = _refused(port)
        return real(*a, **k)

    monkeypatch.setattr(mod, name, _spy)
    srv = _build(edge, port, tmp_path / "ok")
    try:
        assert seen == {"refused": True}, "the edge accepted connections before it could serve"
        assert not _refused(port)                                    # and it listens once it can
    finally:
        srv.server_close()

    def _fails(*_a, **_k):
        raise ValueError("customer_app/sw.js must carry exactly one BUILD and one SHELL placeholder line")

    monkeypatch.setattr(mod, name, _fails)
    with pytest.raises(ValueError, match="placeholder"):
        _build(edge, port, tmp_path / "bad")
    assert _refused(port)
    s = socket.socket()
    s.bind(("127.0.0.1", port))                                      # the failed edge released its port
    s.close()


def test_the_provisioner_drain_outwaits_every_action_the_customer_edge_waits_for():
    from sigil.ui import custui
    waits = [custui._HOP_TIMEOUT_S, *custui._SLOW_HOP_TIMEOUTS_S.values()]
    assert graceful.PROVISIONER_DRAIN_DEADLINE_S > max(waits)
    assert graceful.DRAIN_DEADLINE_S < graceful.PROVISIONER_DRAIN_DEADLINE_S


def _captured_serve(monkeypatch, module) -> dict:
    seen: dict = {}

    def _capture(srv, **kw):
        seen.update(kw, srv=srv)
        srv.server_close()
        return True
    monkeypatch.setattr(module, "serve_until_signal", _capture)
    return seen


def test_the_customer_edge_stops_with_its_own_deadline_past_the_cockpits(tmp_path, monkeypatch):
    # the edge waits for its own deadline (custui.drain_deadline_s), which outlasts the cockpit's drain: an action
    # the cockpit is still finishing at a joint stop is answered before the edge gives up on it
    from sigil.ui import custui
    seen = _captured_serve(monkeypatch, custui)
    (tmp_path / "s").mkdir()
    custui.serve_customer(host="127.0.0.1", port=0, hop_key="k", provision_base="http://127.0.0.1:9",
                          sessions_dir=str(tmp_path / "s"))
    assert seen.get("drain_deadline_s") is None
    assert graceful.drain_deadline_of(seen["srv"]) == custui.drain_deadline_s()
    assert custui.drain_deadline_s() > graceful.PROVISIONER_DRAIN_DEADLINE_S


@pytest.mark.parametrize("gateway_on", [True, False], ids=["gateway", "no-gateway"])
def test_the_cockpit_stops_with_the_provisioner_deadline_and_stops_its_gateway(tmp_path, monkeypatch, gateway_on):
    from sigil import model_gateway
    from sigil.spine.store import SpineStore
    from sigil.ui import server
    seen = _captured_serve(monkeypatch, server)
    fake_gw = SimpleNamespace(server_address=("127.0.0.1", 0))
    stopped: list = []
    sources: list = []

    def fake_start(allowance=None):
        sources.append(allowance)
        return fake_gw if gateway_on else None

    monkeypatch.setattr(model_gateway, "start_from_env", fake_start)
    monkeypatch.setattr(model_gateway, "stop", lambda gw, *, drain_s=None: stopped.append((gw, drain_s)))
    spine = tmp_path / "spine.jsonl"
    SpineStore(spine).append(kind="message", source="x", actor="user", payload={"text": "hi"})
    server.serve(token="graceful-token", host="127.0.0.1", port=0, spine_path=spine)
    assert seen["drain_deadline_s"] == graceful.PROVISIONER_DRAIN_DEADLINE_S
    # W2b-2: the cockpit hands its gateway the in-process allowance source over its own spine
    from sigil.ui.launch_gate import LaunchAllowance
    assert len(sources) == 1 and isinstance(sources[0], LaunchAllowance)
    assert isinstance(sources[0].gate.store, SpineStore)
    assert sources[0].gate.store.path == spine
    assert sources[0].available_credits(SimpleNamespace(org_id="org_gateway_probe")) == 0
    if not gateway_on:
        assert seen["on_stop"] is None
        return
    seen["on_stop"](seen["drain_deadline_s"])
    assert stopped == [(fake_gw, graceful.PROVISIONER_DRAIN_DEADLINE_S)]


class _Crashing(_Srv):
    def service_actions(self):            # runs inside socketserver's serve loop: the loop itself fails
        raise OSError("the listening socket failed")


def test_a_serve_loop_that_fails_still_fails_the_process():
    # serve_forever raising must not turn into a clean exit: the caller (and so `Restart=on-failure`) sees it
    srv = _Crashing(("127.0.0.1", 0), _Hold)
    with pytest.raises(OSError, match="listening socket failed"):
        graceful.serve_until_signal(srv, stop=threading.Event(), log=lambda _m: None)
    assert _refused(srv.server_address[1])


def test_a_log_line_that_cannot_be_written_never_breaks_the_stop():
    srv = _Srv(("127.0.0.1", 0), _Hold)
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    t, out = _held_request(srv)
    threading.Timer(0.3, _Hold.release.set).start()

    def _closed_stdout(_msg):
        raise BrokenPipeError("stdout is gone")

    assert graceful.graceful_stop(srv, drain_deadline_s=5, log=_closed_stdout) is True
    t.join(5)
    assert out == {"status": 204}
    srv.server_close()


class _Interrupted(_Srv):
    def service_actions(self):            # an interrupt raised inside the serve loop
        raise KeyboardInterrupt


def test_an_interrupt_inside_the_serve_loop_is_a_clean_stop():
    srv = _Interrupted(("127.0.0.1", 0), _Hold)
    assert graceful.serve_until_signal(srv, stop=threading.Event(), log=lambda _m: None) is True
    assert _refused(srv.server_address[1])


def test_an_idle_server_stops_promptly(tmp_path):
    port = _free_port()
    proc = _spawn(tmp_path, ["serve-public", "--host", "127.0.0.1", "--port", str(port)])
    try:
        _wait_listening(port, proc)
        time.sleep(0.5)                                  # idle: no connection wakes the serve loop
        t0 = time.monotonic()
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(10) == 0
        assert time.monotonic() - t0 < 2.5, "an idle server must notice a stop within its poll interval"
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


# ── a companion server stops with the server, from the same moment and within the same deadline ─────────────────
def test_the_model_gateway_refuses_new_requests_from_the_moment_the_cockpit_stops(tmp_path):
    from vigil_core import generate_keypair

    from sigil import model_gateway
    cfg = model_gateway.GatewayConfig(api_key="sk-test-not-used", owner_pubkey=generate_keypair().public_key_b64,
                                      meter_dir=tmp_path / "meter")
    gw_srv, _t = model_gateway.start(cfg)
    gw_port = gw_srv.server_address[1]
    srv = _Srv(("127.0.0.1", 0), _Hold)
    stop = threading.Event()
    done = threading.Event()
    threading.Thread(target=lambda: (graceful.serve_until_signal(
        srv, stop=stop, log=lambda _m: None, drain_deadline_s=10,
        on_stop=lambda d: model_gateway.stop(gw_srv, drain_s=d)), done.set()), daemon=True).start()
    t, out = _held_request(srv)                          # the cockpit is draining a request ...
    stop.set()
    assert _refused(gw_port, within=3), "the gateway must stop accepting when the cockpit's stop begins"
    assert not done.is_set() and out == {}               # ... while that request is still in flight
    _Hold.release.set()
    assert done.wait(10) and out == {"status": 204}
    t.join(5)
    assert model_gateway.GrantMeter(tmp_path / "meter")._live_boot() is None   # its meter directory let go


def test_a_companion_that_fails_never_stops_the_servers_own_stop():
    srv = _Srv(("127.0.0.1", 0), _Hold)
    stop = threading.Event()
    stop.set()

    def _boom(_d):
        raise RuntimeError("companion failed")
    logs: list = []
    assert graceful.serve_until_signal(srv, stop=stop, log=logs.append, on_stop=_boom) is True
    assert _refused(srv.server_address[1])
    assert any("companion stop failed: RuntimeError: companion failed" in m for m in logs), logs


def test_a_companion_still_running_at_the_deadline_is_not_waited_for_past_it():
    srv = _Srv(("127.0.0.1", 0), _Hold)
    stop = threading.Event()
    stop.set()
    hold = threading.Event()
    t0 = time.monotonic()
    assert graceful.serve_until_signal(srv, stop=stop, log=lambda _m: None, drain_deadline_s=0.5,
                                       on_stop=lambda _d: hold.wait(30)) is False
    assert time.monotonic() - t0 < 3
    hold.set()
