"""The cockpit, the customer edge and the public site stop GRACEFULLY on SIGTERM (what `systemctl stop|restart`
sends): a request already accepted finishes and gets its answer, the cockpit's SSE feeds end, new connections
are refused at once, and the process exits 0 — all within a drain deadline shorter than the units'
TimeoutStopSec. A second signal ends the drain at once.

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

import pytest

from sigil.ui import graceful
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


def _refused(port: int) -> bool:
    try:
        socket.create_connection(("127.0.0.1", port), timeout=1).close()
        return False
    except OSError:
        return True


# ── the customer edge: an accepted request (a slow provisioner hop) completes across SIGTERM ─────────────────
class _SlowProvisioner(BaseHTTPRequestHandler):
    received = threading.Event()

    def log_message(self, *a):
        pass

    def do_POST(self):  # noqa: N802
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        type(self).received.set()
        time.sleep(2.0)
        body = json.dumps({"ok": True, "marker": "the-slow-answer"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_customer_edge_finishes_an_in_flight_request_on_sigterm(tmp_path):
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
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
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
        t.join(15)
        assert result.get("status") == 200, result
        assert json.loads(result["body"])["marker"] == "the-slow-answer"
        assert proc.wait(15) == 0
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
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


# ── the cockpit: its SSE feed ends on SIGTERM and the process exits 0 well inside the deadline ───────────────
def test_cockpit_ends_its_sse_feed_and_exits_cleanly_on_sigterm(tmp_path):
    port = _free_port()
    proc = _spawn(tmp_path, ["serve", "--host", "127.0.0.1", "--port", str(port), "--token", "graceful-token"])
    try:
        _wait_listening(port, proc)
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
        c.request("GET", "/api/stream?token=graceful-token", headers={"Host": f"127.0.0.1:{port}"})
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


@pytest.mark.parametrize("unit", ["sigil-cockpit.service", "sigil-customer.service", "sigil-public.service"])
def test_the_drain_deadline_is_inside_every_units_stop_timeout(unit):
    text = (_SIGIL / "deploy" / "systemd" / unit).read_text(encoding="utf-8")
    m = re.search(r"^TimeoutStopSec=(\d+)\s*$", text, re.M)
    assert m, f"{unit} sets no TimeoutStopSec"
    assert graceful.DRAIN_DEADLINE_S + 5 <= int(m.group(1)), (unit, m.group(1))
    assert re.search(r"^KillSignal=SIGTERM\s*$", text, re.M)
