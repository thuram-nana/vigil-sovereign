"""While the cockpit restarts, nothing listens on the provisioner port, so a customer request cannot reach it. The
customer edge then answers 503 with `Retry-After` and `{"error": "updating"}` — a guarantee that the request did
NOT reach the provisioner and changed nothing. A request that may have reached it (the connection broke after it
was sent) is never reported that way: it stays a 502. The edge never re-sends a request to the provisioner.

Run: SIGIL_HOME=$(mktemp -d) PYTHONPATH=apps/sigil:packages/core/vigil_core \
     .venv-sovereign/bin/python -m pytest -q apps/sigil/tests/test_custui_updating.py
"""
from __future__ import annotations

import json
import socket
import struct
import threading
import urllib.error
import urllib.request

import pytest

from sigil.ui import custui
from sigil.ui.custui import CUSTOMER_COOKIE, build_customer_server

_HOP = "hop-key-for-the-updating-tests"


def _dead_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class _Breaker:
    """A provisioner that reads each request in full, counts it, then breaks the connection (RST or a bare close)
    without answering — the request DID reach it."""

    def __init__(self, *, reset: bool):
        self.hits = 0
        self.reset = reset
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = c.recv(65536)
                if not chunk:
                    break
                buf += chunk
            head, _, rest = buf.partition(b"\r\n\r\n")
            n = 0
            for line in head.split(b"\r\n"):
                if line.lower().startswith(b"content-length:"):
                    n = int(line.split(b":", 1)[1])
            while len(rest) < n:
                rest += c.recv(65536)
            self.hits += 1
            if self.reset:
                c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            c.close()

    def close(self):
        self.sock.close()


def _edge(tmp_path, port):
    custui._readyz_cache.clear()
    sessions = tmp_path / "sessions"
    sessions.mkdir(exist_ok=True)
    srv = build_customer_server(host="127.0.0.1", port=0, hop_key=_HOP,
                                provision_base=f"http://127.0.0.1:{port}", sessions_dir=str(sessions))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _call(srv, path, *, body=None, cookie=None):
    port = srv.server_address[1]
    h = {"Host": f"127.0.0.1:{port}"}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        h.update({"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{port}"})
    if cookie:
        h["Cookie"] = f"{CUSTOMER_COOKIE}={cookie}"
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, headers=h,
                                 method="POST" if body is not None else "GET")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.headers, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, e.headers, json.loads(e.read() or b"{}")


@pytest.mark.parametrize("path,body", [
    ("/api/customer/login", {"email": "a@example.test", "password": "pw"}),
    ("/api/customer/launch/reserve", {"host": "example.test", "product_id": "x"}),
    ("/api/customer/billing", None),
])
def test_a_provisioner_that_is_not_listening_is_reported_as_updating(tmp_path, path, body):
    srv = _edge(tmp_path, _dead_port())
    try:
        sid = srv.sessions.create("alice", "customer", org_id="org_a")
        status, headers, payload = _call(srv, path, body=body, cookie=sid)
        assert status == 503, (path, status, payload)
        assert payload == {"error": "updating"}
        assert headers.get("Retry-After") == "5"
        assert headers.get("Cache-Control") == "no-store"
    finally:
        srv.shutdown()


@pytest.mark.parametrize("reset", [True, False], ids=["reset", "closed"])
def test_a_request_that_reached_the_provisioner_is_never_reported_as_updating(tmp_path, reset):
    prov = _Breaker(reset=reset)
    srv = _edge(tmp_path, prov.port)
    try:
        sid = srv.sessions.create("alice", "customer", org_id="org_a")
        status, headers, payload = _call(srv, "/api/customer/launch/reserve",
                                         body={"host": "example.test", "product_id": "x"}, cookie=sid)
        assert status == 502, (status, payload)
        assert payload.get("error") != "updating"
        assert headers.get("Retry-After") is None
        assert prov.hits == 1, "the edge must send a request to the provisioner exactly once"
    finally:
        srv.shutdown()
        prov.close()


def test_readyz_still_reports_the_provisioner_down(tmp_path):
    srv = _edge(tmp_path, _dead_port())
    try:
        status, _headers, payload = _call(srv, "/readyz")
        assert status == 503 and payload["ok"] is False
    finally:
        srv.shutdown()
