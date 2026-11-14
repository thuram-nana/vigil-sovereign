"""When a customer or public edge is down (restarting), the shipped nginx vhosts answer 503 + Retry-After with a
small no-store page instead of a bare 502 — and ONLY then: a response the edge sends (its own 503
`{"error":"updating"}`, a 502, anything) passes through untouched, and nginx sends each request to the edge once.

The edge runs on one of TWO loopback ports (the edge swap, tools/deploy/edge-swap.sh): nginx sends every request
to the primary while it accepts connections and to the backup port when it does not; a request moves to the
other port only when it could not be delivered (or, for a GET, when the connection broke before an answer) — a
POST that reached an edge is never sent again — and a swap done the way the script does it loses no request.

The static checks always run; the behavioural ones run the shipped `upstream` and `location` blocks, verbatim
except for the two upstream ports, under a real nginx on loopback.
"""
from __future__ import annotations

import http.client
import json
import os
import shutil
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

_RP = Path(__file__).resolve().parents[1] / "deploy" / "reverse-proxy"
# edge -> (vhost, primary port, backup port, upstream name), as shipped
_CONFS = {"customer": (_RP / "vigil-customer.nginx.conf", 8734, 8744, "vigil_customer"),
          "public": (_RP / "vigil-public.nginx.conf", 8735, 8745, "vigil_public")}
_NGINX = shutil.which("nginx") or ("/usr/sbin/nginx" if Path("/usr/sbin/nginx").exists() else None)


def _block(text: str, opener: str) -> str:
    """The `opener { ... }` block, brace-matched."""
    i = text.index(opener)
    depth = 0
    for j in range(text.index("{", i), len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[i: j + 1]
    raise AssertionError(f"unterminated block {opener!r}")


def _directives(block: str) -> list[str]:
    return [ln.strip() for ln in block.splitlines() if ln.strip() and not ln.strip().startswith("#")]


@pytest.mark.parametrize("edge", sorted(_CONFS))
def test_the_vhost_answers_edge_down_errors_and_nothing_else(edge):
    text = _CONFS[edge][0].read_text(encoding="utf-8")
    loc = _directives(_block(text, "location / {"))
    assert "error_page 502 504 = @vigil_unavailable;" in loc
    assert not any(d.startswith("proxy_intercept_errors") for d in _directives(text)), \
        "the edge's own error responses must pass through untouched"
    named = _directives(_block(text, "location @vigil_unavailable {"))
    _conf, a, b, up = _CONFS[edge]
    assert f"proxy_pass http://{up};" in loc
    assert "proxy_next_upstream error timeout;" in loc                      # never http_5xx, never non_idempotent
    assert not any("non_idempotent" in d or "http_50" in d for d in _directives(text))
    assert _directives(_block(text, f"upstream {up} {{"))[1:3] == [
        f"server 127.0.0.1:{a} max_fails=1 fail_timeout=2s;", f"server 127.0.0.1:{b} backup;"]
    assert "add_header Retry-After 5 always;" in named
    assert 'add_header Cache-Control "no-store" always;' in named
    assert 'add_header Strict-Transport-Security "max-age=31536000" always;' in named
    assert any(d.startswith("return 503 '") for d in named)


# ── behaviour under a real nginx ─────────────────────────────────────────────────────────────────────────────
class _Upstream:
    """A stand-in edge. mode: 'ok' answers 200 {"edge": name}; 'updating' answers 503 {"error":"updating"} +
    Retry-After; 'bad' answers its own 502; 'break' reads the request then closes without answering. Counts the
    requests it received. close() stops it the way a graceful stop does: the listener is closed (refused)."""

    def __init__(self, mode: str, name: str = "edge", port: int = 0):
        self.hits = 0
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _any(self):
                self.rfile.read(int(self.headers.get("Content-Length", "0") or 0))
                outer.hits += 1
                if mode == "break":
                    self.close_connection = True
                    self.connection.close()
                    return
                code, body = ((503, {"error": "updating"}) if mode == "updating"
                              else (200, {"edge": name}) if mode == "ok"
                              else (502, {"error": "provisioner unreachable"}))
                raw = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                if mode == "updating":
                    self.send_header("Retry-After", "5")
                self.end_headers()
                self.wfile.write(raw)

            do_GET = do_POST = _any  # noqa: N815

        self.srv = ThreadingHTTPServer(("127.0.0.1", port), H)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture()
def nginx(tmp_path):
    if _NGINX is None:
        pytest.skip("nginx not installed")
    procs = []

    def start(edge: str, upstream_port: int, backup_port: "int | None" = None) -> int:
        conf_path, primary, backup, up = _CONFS[edge]
        text = conf_path.read_text(encoding="utf-8")
        backup_port = backup_port or _free_port()                # by default nothing listens on the backup port
        ups = (_block(text, f"upstream {up} {{")
               .replace(f"server 127.0.0.1:{primary} ", f"server 127.0.0.1:{upstream_port} ")
               .replace(f"server 127.0.0.1:{backup} backup;", f"server 127.0.0.1:{backup_port} backup;"))
        assert f"127.0.0.1:{upstream_port} " in ups and f"127.0.0.1:{backup_port} backup" in ups
        loc = _block(text, "location / {")
        named = _block(text, "location @vigil_unavailable {")
        port = _free_port()
        d = tmp_path / f"nginx-{edge}-{port}"
        d.mkdir()
        user = "user root;\n" if os.geteuid() == 0 else ""
        (d / "nginx.conf").write_text(
            f"{user}daemon off;\npid {d}/nginx.pid;\nerror_log {d}/error.log;\nevents {{}}\nhttp {{\n"
            f"  access_log off;\n  client_body_temp_path {d}/cb;\n  proxy_temp_path {d}/px;\n"
            f"  fastcgi_temp_path {d}/fc;\n  uwsgi_temp_path {d}/uw;\n  scgi_temp_path {d}/sc;\n"
            f"  proxy_connect_timeout 2s;\n  proxy_read_timeout 5s;\n  {ups}\n"
            f"  server {{\n    listen 127.0.0.1:{port};\n    {loc}\n    {named}\n  }}\n}}\n", encoding="utf-8")
        p = subprocess.Popen([_NGINX, "-p", str(d), "-c", str(d / "nginx.conf"), "-e", str(d / "error.log")],
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        procs.append(p)
        end = time.monotonic() + 10
        while time.monotonic() < end:
            assert p.poll() is None, p.stderr.read().decode() if p.stderr else "nginx exited"
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.3).close()
                return port
            except OSError:
                time.sleep(0.05)
        raise AssertionError("nginx did not start")

    yield start
    for p in procs:
        p.terminate()
        try:
            p.wait(5)
        except subprocess.TimeoutExpired:
            p.kill()


def _req(port, method, path, body=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request(method, path, body=json.dumps(body).encode() if body is not None else None,
              headers={"Content-Type": "application/json"} if body is not None else {})
    r = c.getresponse()
    return r.status, {k.lower(): v for k, v in r.getheaders()}, r.read().decode()


@pytest.mark.parametrize("edge", sorted(_CONFS))
@pytest.mark.parametrize("method,path,body", [("GET", "/", None),
                                              ("POST", "/api/customer/login", {"email": "a@example.test"})])
def test_an_edge_that_is_down_gets_the_unavailable_page(nginx, edge, method, path, body):
    port = nginx(edge, _free_port())                     # nothing listens upstream
    status, h, text = _req(port, method, path, body)
    assert status == 503
    assert h.get("retry-after") == "5" and h.get("cache-control") == "no-store"
    assert h.get("content-type", "").startswith("text/html") and "VIGIL is briefly unavailable" in text


@pytest.mark.parametrize("edge", sorted(_CONFS))
def test_a_connection_the_edge_breaks_is_answered_once_and_never_resent(nginx, edge):
    up = _Upstream("break")
    try:
        port = nginx(edge, up.port)
        status, h, text = _req(port, "POST", "/api/customer/launch/reserve", {"host": "h"})
        assert status == 503 and "VIGIL is briefly unavailable" in text
        time.sleep(0.2)
        assert up.hits == 1, "nginx must send a request to the edge exactly once"
    finally:
        up.close()


@pytest.mark.parametrize("edge", sorted(_CONFS))
@pytest.mark.parametrize("mode,code", [("updating", 503), ("bad", 502)])
def test_the_edges_own_error_answers_pass_through_untouched(nginx, edge, mode, code):
    up = _Upstream(mode)
    try:
        port = nginx(edge, up.port)
        status, h, text = _req(port, "POST", "/api/customer/login", {"email": "a@example.test"})
        assert status == code
        assert h.get("content-type", "").startswith("application/json")
        assert "briefly unavailable" not in text
        if mode == "updating":
            assert json.loads(text) == {"error": "updating"} and h.get("retry-after") == "5"
        assert up.hits == 1
    finally:
        up.close()


# ── the two ports: the edge swap ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("edge", sorted(_CONFS))
def test_the_primary_takes_every_request_while_it_is_up(nginx, edge):
    a, b = _Upstream("ok", "A"), _Upstream("ok", "B")
    try:
        port = nginx(edge, a.port, b.port)
        for method, body in (("GET", None), ("POST", {"x": 1}), ("GET", None)):
            status, _h, text = _req(port, method, "/api/customer/whoami", body)
            assert status == 200 and json.loads(text) == {"edge": "A"}
        assert (a.hits, b.hits) == (3, 0)
    finally:
        a.close()
        b.close()


@pytest.mark.parametrize("edge", sorted(_CONFS))
@pytest.mark.parametrize("method,body", [("GET", None), ("POST", {"email": "a@example.test"})])
def test_the_backup_port_answers_when_the_primary_is_down(nginx, edge, method, body):
    b = _Upstream("ok", "B")
    try:
        port = nginx(edge, _free_port(), b.port)                 # nothing listens on the primary
        status, _h, text = _req(port, method, "/api/customer/login", body)
        assert status == 200 and json.loads(text) == {"edge": "B"}
        assert b.hits == 1                                       # delivered once: the primary refused it
    finally:
        b.close()


@pytest.mark.parametrize("edge", sorted(_CONFS))
def test_a_post_that_reached_an_edge_is_never_sent_to_the_other_port(nginx, edge):
    a, b = _Upstream("break", "A"), _Upstream("ok", "B")
    try:
        port = nginx(edge, a.port, b.port)
        status, _h, text = _req(port, "POST", "/api/customer/launch/reserve", {"host": "h"})
        time.sleep(0.2)
        assert status == 503 and "VIGIL is briefly unavailable" in text
        assert (a.hits, b.hits) == (1, 0), "a POST the primary received must never be sent to the backup"
    finally:
        a.close()
        b.close()


@pytest.mark.parametrize("edge", sorted(_CONFS))
def test_a_get_whose_connection_broke_is_answered_by_the_other_port(nginx, edge):
    a, b = _Upstream("break", "A"), _Upstream("ok", "B")
    try:
        port = nginx(edge, a.port, b.port)
        status, _h, text = _req(port, "GET", "/api/customer/billing")
        assert status == 200 and json.loads(text) == {"edge": "B"} and (a.hits, b.hits) == (1, 1)
    finally:
        a.close()
        b.close()


def _hammer(port, stop, results):
    while not stop.is_set():
        try:
            status, _h, text = _req(port, "GET", "/api/customer/whoami")
            results.append((status, text))
        except OSError as e:                                     # nginx itself never refuses here
            results.append((0, repr(e)))
        time.sleep(0.02)


@pytest.mark.parametrize("edge", sorted(_CONFS))
def test_a_swap_done_like_the_script_loses_no_request(nginx, edge):
    # Both directions of tools/deploy/edge-swap.sh: start the new edge on the free port, wait until it answers,
    # wait VIGIL_EDGE_SWAP_SETTLE_S (3 s, longer than fail_timeout=2s), then stop the old edge (listener closed).
    pa, pb = _free_port(), _free_port()
    b = _Upstream("ok", "B", pb)                                 # the edge currently runs on the BACKUP port
    port = nginx(edge, pa, pb)
    stop, results = threading.Event(), []
    t = threading.Thread(target=_hammer, args=(port, stop, results), daemon=True)
    t.start()
    try:
        time.sleep(1.0)                                          # nginx has learnt the primary is down
        a = _Upstream("ok", "A", pa)                             # swap back to the primary port ...
        time.sleep(3.0)
        b.close()                                                # ... and stop the old edge
        time.sleep(1.0)
        b = _Upstream("ok", "B", pb)                             # and forward again: new edge on the backup port
        time.sleep(3.0)
        a.close()
        time.sleep(1.0)
    finally:
        stop.set()
        t.join(5)
        b.close()
    statuses = [s for s, _t in results]
    assert len(statuses) > 100 and set(statuses) == {200}, [r for r in results if r[0] != 200][:3]
    served = {json.loads(t)["edge"] for _s, t in results}
    assert served == {"A", "B"}
