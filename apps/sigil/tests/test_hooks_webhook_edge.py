"""The payment webhooks reach the `vigil up` proxy through a DEDICATED host (hooks.vigilguard.net), never the console.

Stripe delivers to ``https://hooks.vigilguard.net/webhooks/stripe``. The hooks vhost templates (nginx and Caddy, in
deploy/reverse-proxy and infra/edge/Caddyfile.example) forward EXACTLY ``POST /webhooks/stripe`` and
``POST /webhooks/billing`` to the proxy at 127.0.0.1:8770, byte-exact on the raw request line, with a 1 MB body cap and
Host / ``Stripe-Signature`` forwarded unchanged. Everything else is 404 (421 for a foreign Host): other paths, other
methods, and raw request lines that only NORMALISE onto a webhook path. The console and cockpit vhosts expose no
webhook path and carry no exception to their IP allow-list.

The static checks always run. The behavioural ones run the shipped hooks server block, verbatim except for its
TLS/listen lines and the upstream port, under a real nginx on loopback, against a recording upstream. (The end-to-end
run through the REAL proxy, with Host hooks.vigilguard.net, is integration/tests/test_hooks_vhost_uiproxy_e2e.py.)
The Caddy templates are checked statically here (no Caddy binary in CI).
"""
from __future__ import annotations

import http.client
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

REPO = Path(__file__).resolve().parents[3]
RP = REPO / "apps" / "sigil" / "deploy" / "reverse-proxy"
HOOKS_NGINX = RP / "vigil-hooks.nginx.conf"
HOOKS_CADDY = {"vigil-hooks.Caddyfile": (RP / "vigil-hooks.Caddyfile", "hooks.vigilguard.net"),
               "Caddyfile.example": (REPO / "infra" / "edge" / "Caddyfile.example", "hooks.vigil.example.com")}
UIPROXY = REPO / "integration" / "vigil_integration" / "uiproxy.py"
WEBHOOKS = ("/webhooks/stripe", "/webhooks/billing")
HOST = "hooks.vigilguard.net"
_NGINX = shutil.which("nginx") or ("/usr/sbin/nginx" if Path("/usr/sbin/nginx").exists() else None)


def _brace_block(text: str, start: int) -> str:
    """The text from ``start`` to the brace that closes the first ``{`` at or after it (comments ignored)."""
    i = text.index("{", start)
    depth = 0
    j = i
    while j < len(text):
        c = text[j]
        if c == "#":
            j = text.index("\n", j)
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[start:j + 1]
        j += 1
    raise AssertionError("unbalanced braces")


def _live(text: str) -> str:
    """The text with every comment removed (Caddy and nginx both use '#')."""
    return "\n".join(line.split("#", 1)[0].rstrip() for line in text.splitlines())


def _real_ip(text: str) -> "tuple[list[str], bool]":
    ranges = [ln.split()[1].rstrip(";") for ln in text.splitlines() if ln.strip().startswith("set_real_ip_from")]
    return ranges, any(ln.strip().startswith("real_ip_header CF-Connecting-IP;") for ln in text.splitlines())


# --- the proxy really serves exactly these paths, ahead of its Host gate -------------------------------------------

def test_the_forwarded_paths_are_the_proxy_webhook_routes_and_sit_before_its_host_gate():
    src = UIPROXY.read_text(encoding="utf-8")
    served = re.findall(r'split\.path == "(/webhooks/[a-z-]+)" and getattr\(self\.server, "webhook_(?:billing|stripe)',
                        src)
    assert set(served) == set(WEBHOOKS), served
    handle = src[src.index("    def _handle(self):"):]
    handle = handle[: handle.index("\n    def ", 10)]
    # both routes are dispatched before plane control and routing (where the Host/Origin gates live)
    for p in WEBHOOKS:
        assert handle.index(f'split.path == "{p}"') < handle.index("is_plane_path(split.path)")
        assert handle.index(f'split.path == "{p}"') < handle.index("route(split.path")


# --- nginx hooks vhost, statically ----------------------------------------------------------------------------------

def _nginx_tls_server() -> str:
    text = HOOKS_NGINX.read_text(encoding="utf-8")
    blocks = [_brace_block(text, m.start()) for m in re.finditer(r"^server \{", text, re.M)]
    tls = [b for b in blocks if "listen 443 ssl;" in b]
    assert len(tls) == 1 and f"server_name {HOST};" in tls[0]
    return tls[0]


def _locations(server: str) -> "dict[str, str]":
    live = _live(server)
    return {m.group(1).strip(): _brace_block(live, m.start())
            for m in re.finditer(r"^\s*location ([^{]+?) \{", live, re.M)}


def test_nginx_hooks_vhost_forwards_exactly_the_two_webhooks_and_nothing_else():
    server = _nginx_tls_server()
    locs = _locations(server)
    assert set(locs) == {f"= {p}" for p in WEBHOOKS} | {"/"}, set(locs)
    assert re.search(r"^\s*return 404;", locs["/"], re.M) and "proxy_pass" not in locs["/"]
    for p in WEBHOOKS:
        loc = locs[f"= {p}"]
        assert f'if ($request_uri != "{p}") {{ return 404; }}' in loc          # raw request line, byte-exact
        assert "if ($request_method != POST) { return 404; }" in loc           # POST only
        assert re.search(r"^\s*client_max_body_size 1m;", loc, re.M)
        assert re.findall(r"proxy_pass (\S+);", loc) == [f"http://127.0.0.1:8770{p}"]
        assert re.search(r"^\s*proxy_set_header Host \$host;", loc, re.M)
        assert "Stripe-Signature" not in loc and "proxy_pass_request_headers" not in loc
    # the only proxy_pass lines in the whole file are those two
    assert len(re.findall(r"proxy_pass ", _live(HOOKS_NGINX.read_text(encoding="utf-8")))) == 2
    assert 'if ($host != "hooks.vigilguard.net") { return 421; }' in server
    assert "allow " not in _live(server) and "deny " not in _live(server)


def test_nginx_hooks_vhost_restores_the_cloudflare_client_ip_like_the_public_vhost():
    public = _real_ip((RP / "vigil-public.nginx.conf").read_text(encoding="utf-8"))
    hooks = _real_ip(HOOKS_NGINX.read_text(encoding="utf-8"))
    assert public[0] and hooks == public and hooks[1] is True


# --- Caddy hooks sites, statically ----------------------------------------------------------------------------------

def _caddy_site(name: str) -> str:
    path, host = HOOKS_CADDY[name]
    live = _live(path.read_text(encoding="utf-8"))
    m = re.search(rf"^{re.escape(host)} \{{", live, re.M)
    assert m, f"{name}: no {host} site"
    return _brace_block(live, m.start())


@pytest.mark.parametrize("name", sorted(HOOKS_CADDY))
def test_caddy_hooks_site_forwards_exactly_post_to_the_two_webhooks(name):
    site = _caddy_site(name)
    host = HOOKS_CADDY[name][1]
    m = re.search(r"^\s*@provider_webhook \{", site, re.M)
    assert m and len(re.findall(r"^\s*@provider_webhook \{", site, re.M)) == 1
    lines = [ln.strip() for ln in _brace_block(site, m.start()).splitlines()
             if ln.strip() and not ln.strip().endswith(("{", "}"))]
    assert sorted(lines) == sorted([
        "method POST", f"host {host}", f"path {' '.join(WEBHOOKS)}",
        'expression `{http.request.uri} in ["/webhooks/stripe", "/webhooks/billing"]`']), lines
    handles = re.findall(r"^\s*handle( @[A-Za-z_]+)? \{", site, re.M)
    assert handles == [" @provider_webhook", ""], handles
    wh = _brace_block(site, re.search(r"^\s*handle @provider_webhook \{", site, re.M).start())
    assert re.search(r"request_body \{\s*max_size 1MB\s*\}", wh)
    assert re.findall(r"reverse_proxy (\S+)", wh) == ["127.0.0.1:8770"]
    # the edge buffers the whole (capped) body before dialling the proxy: a stalled client never pins a proxy thread
    assert re.search(r"reverse_proxy 127\.0\.0\.1:8770 \{\s*request_buffers 1MB\s*\}", wh), wh
    assert "header_up" not in wh and "rewrite" not in wh and "uri " not in wh
    rest = _brace_block(site, re.search(r"^\s*handle \{", site, re.M).start())
    assert f"@badhost not host {host}" in rest and "respond @badhost 421" in rest
    assert re.search(r"^\s*respond 404\s*$", rest, re.M) and "reverse_proxy" not in rest
    assert site.count("reverse_proxy") == 1                                  # nothing else is proxied


# --- the console / cockpit vhosts expose no webhook -----------------------------------------------------------------

CONSOLE_AND_COCKPIT = {
    "vigil.nginx.conf": RP / "vigil.nginx.conf", "vigil.Caddyfile": RP / "vigil.Caddyfile",
    "Caddyfile": RP / "Caddyfile", "cockpit.nginx.conf": RP / "cockpit.nginx.conf",
}


@pytest.mark.parametrize("name", sorted(CONSOLE_AND_COCKPIT))
def test_the_console_and_cockpit_vhosts_carry_no_webhook_exception(name):
    live = _live(CONSOLE_AND_COCKPIT[name].read_text(encoding="utf-8"))
    assert "webhooks" not in live and "allow all" not in live and "@provider_webhook" not in live, name


def test_the_edge_example_console_site_is_fully_ip_restricted():
    live = _live(HOOKS_CADDY["Caddyfile.example"][0].read_text(encoding="utf-8"))
    m = re.search(r"^console\.[a-z0-9.-]+ \{", live, re.M)
    console = _brace_block(live, m.start())
    assert "webhooks" not in console and "handle" not in console
    assert re.search(r"@blocked not remote_ip \S+", console) and 'respond @blocked "forbidden" 403' in console


# --- nginx hooks vhost, behaviourally -------------------------------------------------------------------------------

def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class _Upstream:
    """Records every request that reaches the console proxy's port."""

    def __init__(self) -> None:
        seen = self.seen = []

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _any(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else b""
                seen.append({"method": self.command, "path": self.path, "host": self.headers.get("Host"),
                             "sig": self.headers.get("Stripe-Signature"), "body": body})
                self.send_response(202)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            do_GET = do_POST = do_PUT = do_DELETE = _any

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()


@pytest.fixture()
def hooks(tmp_path):
    if _NGINX is None:
        pytest.skip("nginx not installed")
    up = _Upstream()
    port = _free_port()
    server = _nginx_tls_server()
    inner = server[server.index("{") + 1: server.rindex("}")]
    kept = [ln.replace("127.0.0.1:8770", f"127.0.0.1:{up.port}") for ln in inner.splitlines()
            if not ln.strip().startswith(("listen ", "http2 ", "ssl_"))]
    d = tmp_path / "nginx"
    d.mkdir()
    user = "user root;\n" if os.geteuid() == 0 else ""
    (d / "nginx.conf").write_text(
        f"{user}daemon off;\npid {d}/nginx.pid;\nerror_log {d}/error.log;\nevents {{}}\nhttp {{\n"
        f"  access_log off;\n  client_body_temp_path {d}/cb;\n  proxy_temp_path {d}/px;\n"
        f"  fastcgi_temp_path {d}/fc;\n  uwsgi_temp_path {d}/uw;\n  scgi_temp_path {d}/sc;\n"
        f"  server {{\n    listen 127.0.0.1:{port};\n" + "\n".join(kept) + "\n  }\n}\n", encoding="utf-8")
    p = subprocess.Popen([_NGINX, "-p", str(d), "-c", str(d / "nginx.conf"), "-e", str(d / "error.log")],
                         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        end = time.monotonic() + 10
        while True:
            assert p.poll() is None, p.stderr.read().decode() if p.stderr else "nginx exited"
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.3).close()
                break
            except OSError:
                assert time.monotonic() < end, "nginx did not start"
                time.sleep(0.05)
        yield port, up
    finally:
        p.terminate()
        try:
            p.wait(5)
        except subprocess.TimeoutExpired:
            p.kill()
        up.close()


def _send(port, method, path, body=b"", headers=None, host=HOST):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
    for k, v in {"Host": host, **(headers or {})}.items():
        c.putheader(k, v)
    c.putheader("Content-Length", str(len(body)))
    c.endheaders(body)
    r = c.getresponse()
    r.read()
    c.close()
    return r.status


@pytest.mark.parametrize("path", WEBHOOKS)
def test_a_webhook_post_reaches_the_proxy_unchanged(hooks, path):
    port, up = hooks
    sig = "t=1700000000,v1=" + "ab" * 32
    body = b'{"id":"evt_test","object":"event"}'
    assert _send(port, "POST", path, body, {"Stripe-Signature": sig, "Content-Type": "application/json"}) == 202
    assert up.seen == [{"method": "POST", "path": path, "host": HOST, "sig": sig, "body": body}]


@pytest.mark.parametrize("method", ["GET", "HEAD", "PUT", "DELETE", "OPTIONS"])
def test_another_method_on_the_webhook_path_is_404(hooks, method):
    port, up = hooks
    assert _send(port, method, "/webhooks/stripe") == 404
    assert up.seen == []


@pytest.mark.parametrize("path", ["/webhooks/stripex", "/webhooks/stripe/", "/webhooks/Stripe", "/webhooks/",
                                  "/webhooks/github", "/sovereign/api/stream", "/", "/offense/api/v1/engage",
                                  "/healthz", "/webhooks/x/../stripe", "/webhooks//stripe", "/webhooks/%73tripe",
                                  "/webhooks/stripe?x=1", "/sovereign/../webhooks/stripe",
                                  "/sovereign/api/x/../../../webhooks/stripe", "/webhooks/./stripe"])
def test_every_other_path_or_raw_line_is_404_and_never_forwarded(hooks, path):
    port, up = hooks
    assert _send(port, "POST", path, b"{}") == 404
    assert up.seen == []


def test_a_foreign_host_is_421(hooks):
    port, up = hooks
    assert _send(port, "POST", "/webhooks/stripe", b"{}", host="console.vigilguard.net") == 421
    assert up.seen == []


def test_a_body_over_the_cap_is_413(hooks):
    port, up = hooks
    assert _send(port, "POST", "/webhooks/stripe", b"x" * (1024 * 1024 + 1)) == 413
    assert up.seen == []


# --- the runbooks name the host and the URL -------------------------------------------------------------------------

def test_the_runbooks_state_the_hooks_host_and_the_webhook_url():
    go_live = (REPO / "docs" / "runbooks" / "GO-LIVE-quickstart.md").read_text(encoding="utf-8")
    s9b = go_live[go_live.index("## 9b."): go_live.index("## 10.")]
    assert "`https://hooks.vigilguard.net/webhooks/stripe`" in s9b and "<operator ingress>" not in s9b
    assert "vigil-hooks.nginx.conf" in go_live
    aws = (REPO / "docs" / "runbooks" / "AWS-DEPLOY.md").read_text(encoding="utf-8")
    assert "| A | `hooks` | your Elastic IP | Proxied |" in aws
    assert "| A | `console` | — | **OMIT — no public record** |" in aws
    assert "`https://hooks.vigilguard.net/webhooks/stripe`" in aws
    remote = (REPO / "apps" / "sigil" / "deploy" / "REMOTE-HOSTING.md").read_text(encoding="utf-8")
    assert "vigil-hooks.nginx.conf" in remote and "hooks." in remote
