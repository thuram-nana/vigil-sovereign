"""When a customer or public edge is down (restarting), the shipped nginx vhosts answer 503 + Retry-After with a
small no-store page instead of a bare 502 — and ONLY then: a response the edge sends (its own 503
`{"error":"updating"}`, a 502, anything) passes through untouched, and nginx sends each request to the edge once.

The edge runs on one of TWO loopback ports (the edge swap, tools/deploy/edge-swap.sh): nginx tries the primary for
every request and the backup port when the primary does not take the connection; a request moves to the other
port only when it could not be delivered (or, for a GET, when the connection broke before an answer) — a POST that
reached an edge is never sent again. Neither port is ever marked unavailable, so a request an edge drops costs that
request only. A swap done the way the script does it, with the edges' own graceful stop, loses no request: no
GET, and no POST (each POST reaches exactly one edge, exactly once).

The static checks always run; the behavioural ones run the shipped `upstream` and `location` blocks, verbatim
except for the two upstream ports, under a real nginx on loopback.
"""
from __future__ import annotations

import http.client
import json
import os
import re
import shutil
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from sigil.ui.graceful import GracefulMixin, graceful_stop

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
    # max_fails=0 on both: nginx never marks a port unavailable (one dropped request must not take the edge out)
    assert _directives(_block(text, f"upstream {up} {{"))[1:] == [
        f"server 127.0.0.1:{a} max_fails=0;", f"server 127.0.0.1:{b} backup max_fails=0;", "}"]
    assert not any("fail_timeout" in d for d in _directives(text))
    assert "add_header Retry-After 5 always;" in named
    assert 'add_header Cache-Control "no-store" always;' in named
    assert 'add_header Strict-Transport-Security "max-age=31536000" always;' in named
    assert any(d.startswith("return 503 '") for d in named)


def test_the_customer_vhost_outwaits_the_edges_longest_cockpit_hop():
    # nginx's default 60 s read timeout was not longer than the edge's 60 s budget for a sign-up / recovery email:
    # nginx gave up first and answered "unavailable" for an action that could still complete
    from sigil.ui import custui
    loc = _directives(_block(_CONFS["customer"][0].read_text(encoding="utf-8"), "location / {"))
    found = [d for d in loc if d.startswith("proxy_read_timeout ")]
    assert len(found) == 1, found
    m = re.fullmatch(r"proxy_read_timeout (\d+)s;", found[0])
    assert m, found[0]
    longest = max([custui._HOP_TIMEOUT_S, *custui._SLOW_HOP_TIMEOUTS_S.values()])
    assert int(m.group(1)) >= longest + 15, (found[0], longest)


# ── behaviour under a real nginx ─────────────────────────────────────────────────────────────────────────────
class _EdgeServer(GracefulMixin, ThreadingHTTPServer):
    daemon_threads = True


class _Upstream:
    """A stand-in edge. mode: 'ok' answers 200 {"edge": name}; 'updating' answers 503 {"error":"updating"} +
    Retry-After; 'bad' answers its own 502; 'break' (or a request for `break_path`) reads the request then closes
    without answering. Counts the requests it received and records the "id" of every POST body. close() is the
    edges' own graceful stop (ui/graceful.py, what SIGTERM runs in custui and pubui)."""

    def __init__(self, mode: str, name: str = "edge", port: int = 0, *, break_path: "str | None" = None):
        self.hits = 0
        self.post_ids: list = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _any(self):
                raw_body = self.rfile.read(int(self.headers.get("Content-Length", "0") or 0))
                outer.hits += 1
                if self.command == "POST":
                    try:
                        outer.post_ids.append(json.loads(raw_body or b"{}").get("id"))
                    except ValueError:
                        pass
                if mode == "break" or self.path == break_path:
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

        self.srv = _EdgeServer(("127.0.0.1", port), H)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        graceful_stop(self.srv, drain_deadline_s=5, log=lambda _m: None)
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
               .replace(f"server 127.0.0.1:{backup} backup ", f"server 127.0.0.1:{backup_port} backup "))
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


# ── one failed request never takes the edge out ─────────────────────────────────────────────────────────────
@pytest.mark.parametrize("edge", sorted(_CONFS))
@pytest.mark.parametrize("on", ["primary", "backup"])
def test_one_broken_connection_never_takes_the_only_edge_out(nginx, edge, on):
    # Normally ONE edge runs, on the primary (during a swap, on the backup port alone for seconds). A request it drops
    # (a handler fault, a slow answer) must cost that request only: nginx never marks a server unavailable, so the
    # next requests reach the same edge at once instead of nginx's "no live upstreams" for seconds.
    up = _Upstream("ok", "A", break_path="/api/customer/broken")
    try:
        port = nginx(edge, up.port) if on == "primary" else nginx(edge, _free_port(), up.port)
        status, _h, text = _req(port, "POST", "/api/customer/broken", {"x": 1})
        assert status == 503 and "VIGIL is briefly unavailable" in text
        for method, body in (("GET", None), ("POST", {"x": 2}), ("GET", None), ("GET", None)):
            status, _h, text = _req(port, method, "/api/customer/whoami", body)
            assert status == 200 and json.loads(text) == {"edge": "A"}, (status, text[:80])
        status, _h, text = _req(port, "GET", "/api/customer/broken")      # a broken GET: the other port refuses
        assert status == 503
        status, _h, text = _req(port, "GET", "/api/customer/whoami")
        assert status == 200 and json.loads(text) == {"edge": "A"}
    finally:
        up.close()


# ── the two ports: the edge swap ─────────────────────────────────────────────────────────────────────────────
def _errors(port: int, edge: str, tmp_path) -> str:
    return (tmp_path / f"nginx-{edge}-{port}" / "error.log").read_text(encoding="utf-8")


@pytest.mark.parametrize("edge", sorted(_CONFS))
def test_on_the_primary_nginx_logs_no_error_per_request(nginx, edge, tmp_path):
    # Why the swap always ends on the primary port: there nginx's first try succeeds and its error log stays quiet.
    # On the backup port alone every request first meets the refused primary, which nginx logs as an [error] line
    # (burying real upstream faults, firing log-based alerts) and counts as one of its two tries.
    up = _Upstream("ok", "A")
    try:
        port = nginx(edge, up.port)
        assert all(_req(port, "GET", "/")[0] == 200 for _ in range(10))
        assert "connect() failed" not in _errors(port, edge, tmp_path)
    finally:
        up.close()
    up = _Upstream("ok", "B")
    try:
        port = nginx(edge, _free_port(), up.port)
        assert all(_req(port, "GET", "/")[0] == 200 for _ in range(10))
        assert _errors(port, edge, tmp_path).count("connect() failed (111") == 10
    finally:
        up.close()
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


def _client(port, method, tag, stop, results):
    i = 0
    while not stop.is_set():
        i += 1
        rid = f"{tag}-{i}"
        try:
            if method == "POST":
                status, _h, text = _req(port, "POST", "/api/customer/launch/reserve", {"id": rid})
            else:
                status, _h, text = _req(port, "GET", "/api/customer/whoami")
            results.append((method, rid, status, text))
        except OSError as e:                                     # nginx itself never refuses here
            results.append((method, rid, 0, repr(e)))
        if method == "GET":
            time.sleep(0.01)


@pytest.mark.parametrize("edge", sorted(_CONFS))
def test_a_swap_done_like_the_script_loses_no_request(nginx, edge):
    # tools/deploy/edge-swap.sh in both directions, three times over: start the new edge on the free port, let it
    # answer, then stop the old one with the edges' graceful stop — under four clients sending POSTs back to back
    # and one sending GETs. Every request is answered by an edge (never nginx's unavailable page), and every POST
    # reaches exactly one edge exactly once (nginx never re-sends one, so none may be lost on the way).
    pa, pb = _free_port(), _free_port()
    edges = {"B": _Upstream("ok", "B", pb)}                     # the edge currently runs on the BACKUP port
    port = nginx(edge, pa, pb)
    stop, results, received = threading.Event(), [], []
    clients = [threading.Thread(target=_client, args=(port, m, f"{m}{n}", stop, results), daemon=True)
               for n, m in enumerate(("POST", "POST", "POST", "POST", "GET"))]
    for t in clients:
        t.start()
    try:
        time.sleep(0.3)
        for _ in range(3):
            edges["A"] = _Upstream("ok", "A", pa)                # new edge on the primary port ...
            time.sleep(0.4)
            old = edges.pop("B")
            old.close()                                          # ... and the old one (backup port) stops
            received += old.post_ids
            time.sleep(0.2)
            edges["B"] = _Upstream("ok", "B", pb)                # new edge on the backup port ...
            time.sleep(0.4)
            old = edges.pop("A")
            old.close()                                          # ... and the old one (primary port) stops
            received += old.post_ids
            time.sleep(0.2)
    finally:
        stop.set()
        for t in clients:
            t.join(15)
        for e in edges.values():
            e.close()
            received += e.post_ids
    bad = [r for r in results if r[2] != 200]
    assert not bad, (len(bad), bad[:3])
    posts = [rid for m, rid, _s, _t in results if m == "POST"]
    assert len(posts) > 100 and len(results) - len(posts) > 20
    assert sorted(received) == sorted(posts), "a POST was lost on the way or reached an edge twice"
    assert {json.loads(t)["edge"] for _m, _r, _s, t in results} == {"A", "B"}
