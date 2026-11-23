"""The console vhost's ONE exception to its admin IP allow-list: the payment-provider webhooks.

Stripe delivers to ``https://console.<domain>/webhooks/stripe`` (live: ``https://console.vigilguard.net/webhooks/stripe``)
from its own servers, which are never on the admin list. So every console vhost template forwards EXACTLY
``POST /webhooks/stripe`` (and Flutterwave's ``POST /webhooks/billing``, which the proxy also serves) from any source
IP, ahead of the IP block, with a 1 MB body cap and Host / ``Stripe-Signature`` forwarded unchanged. Nothing else is
exempted: not another path, not a prefix, not a raw request line that only NORMALISES onto the webhook path, and not
another method.

The static checks always run. The behavioural ones run the shipped nginx console server block, verbatim except for
its TLS/listen lines, the upstream port and the IP block (uncommented, with a range that excludes the test client),
under a real nginx on loopback. The Caddy templates are checked statically (no Caddy binary in CI).
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
NGINX_CONSOLE = RP / "vigil.nginx.conf"
CADDY_CONSOLES = {"vigil.Caddyfile": RP / "vigil.Caddyfile", "Caddyfile.example": REPO / "infra" / "edge" /
                  "Caddyfile.example"}
UIPROXY = REPO / "integration" / "vigil_integration" / "uiproxy.py"
WEBHOOKS = ("/webhooks/stripe", "/webhooks/billing")
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


# --- the proxy really serves exactly these paths -------------------------------------------------------------------

def test_the_exempted_paths_are_the_ones_the_console_proxy_serves():
    src = UIPROXY.read_text(encoding="utf-8")
    served = set(re.findall(r'split\.path == "(/webhooks/[a-z-]+)" and getattr\(self\.server, "webhook_(?:billing|stripe)',
                            src))
    assert served == set(WEBHOOKS), served


# --- Caddy ----------------------------------------------------------------------------------------------------------

def _caddy_console(name: str) -> str:
    text = CADDY_CONSOLES[name].read_text(encoding="utf-8")
    live = _live(text)
    m = re.search(r"^console\.[a-z0-9.-]+ \{", live, re.M)
    assert m, f"{name}: no console site block"
    return _brace_block(live, m.start())


@pytest.mark.parametrize("name", sorted(CADDY_CONSOLES))
def test_caddy_console_exempts_exactly_post_to_the_two_webhook_paths(name):
    site = _caddy_console(name)
    matchers = re.findall(r"^\s*(@[A-Za-z_]+) \{", site, re.M)
    assert matchers.count("@provider_webhook") == 1
    m = re.search(r"^\s*@provider_webhook \{", site, re.M)
    body = _brace_block(site, m.start())
    lines = [ln.strip() for ln in body.splitlines() if ln.strip() and not ln.strip().endswith(("{", "}"))]
    assert "method POST" in lines                                           # POST only
    assert f"path {' '.join(WEBHOOKS)}" in lines                            # exact paths, no wildcard
    assert "*" not in body
    expr = [ln for ln in lines if ln.startswith("expression ")]
    assert expr == ['expression `{http.request.uri} in ["/webhooks/stripe", "/webhooks/billing"]`'], expr
    assert all(ln.split()[0] in ("method", "path", "expression", "host") for ln in lines), lines
    # the handle: body cap, straight to the console proxy, no header rewriting
    h = re.search(r"^\s*handle @provider_webhook \{", site, re.M)
    assert h
    handle = _brace_block(site, h.start())
    assert re.search(r"request_body \{\s*max_size 1MB\s*\}", handle)
    assert re.search(r"^\s*reverse_proxy 127\.0\.0\.1:8770\s*$", handle, re.M)
    assert "header_up" not in handle and "rewrite" not in handle and "uri " not in handle


@pytest.mark.parametrize("name", sorted(CADDY_CONSOLES))
def test_caddy_webhook_handle_comes_first_and_everything_else_is_the_allow_listed_handle(name):
    site = _caddy_console(name)
    handles = re.findall(r"^\s*handle( @[A-Za-z_]+)? \{", site, re.M)
    assert handles == [" @provider_webhook", ""], handles              # one exception, then one catch-all
    webhook_at = re.search(r"^\s*handle @provider_webhook \{", site, re.M).start()
    rest_at = re.search(r"^\s*handle \{", site, re.M).start()
    assert webhook_at < rest_at
    rest = _brace_block(site, rest_at)
    # nothing proxies outside the two handles (a site-level reverse_proxy would bypass the catch-all's allow-list)
    outside = site.replace(_brace_block(site, webhook_at), "").replace(rest, "")
    assert "reverse_proxy" not in outside and "respond" not in outside
    # the IP block lives in the catch-all, after the exception (shipped live in the example, inert in vigil.Caddyfile)
    raw = CADDY_CONSOLES[name].read_text(encoding="utf-8")
    ip_at = raw.index("not remote_ip")
    assert raw.index("handle @provider_webhook") < ip_at < len(raw)
    if name == "Caddyfile.example":
        assert re.search(r'@blocked not remote_ip \S+', rest) and 'respond @blocked "forbidden" 403' in rest
    else:
        assert re.search(r"^\s*# @blocked not remote_ip \S+", raw, re.M)
        assert re.search(r'^\s*# respond @blocked "forbidden" 403', raw, re.M)
        assert raw.index("# @blocked not remote_ip") > raw.index("handle {")


# --- nginx ----------------------------------------------------------------------------------------------------------

def _nginx_tls_server() -> str:
    text = NGINX_CONSOLE.read_text(encoding="utf-8")
    starts = [m.start() for m in re.finditer(r"^server \{", text, re.M)]
    blocks = [_brace_block(text, s) for s in starts]
    tls = [b for b in blocks if "listen 443 ssl;" in b]
    assert len(tls) == 1
    return tls[0]


def _locations(server: str) -> "dict[str, str]":
    live = _live(server)
    out = {}
    for m in re.finditer(r"^\s*location ([^{]+?) \{", live, re.M):
        out[m.group(1).strip()] = _brace_block(live, m.start())
    return out


def test_nginx_exempts_exactly_the_two_webhook_locations_post_only_exact_path():
    locs = _locations(_nginx_tls_server())
    exempt = {k for k, v in locs.items() if re.search(r"^\s*allow all;", v, re.M)}
    assert exempt == {f"= {p}" for p in WEBHOOKS}, exempt
    assert not any("webhooks" in k for k in locs if not k.startswith("= ")), "no prefix/regex webhook location"
    for p in WEBHOOKS:
        loc = locs[f"= {p}"]
        assert re.search(r"limit_except POST \{\s*deny all;\s*\}", loc)
        assert f'if ($request_uri != "{p}") {{ return 404; }}' in loc
        assert re.search(r"^\s*client_max_body_size 1m;", loc, re.M)
        assert re.search(rf"^\s*proxy_pass http://127\.0\.0\.1:8770{re.escape(p)};", loc, re.M)
        assert re.search(r"^\s*proxy_set_header Host \$host;", loc, re.M)
        assert "Stripe-Signature" not in loc and "proxy_pass_request_headers off" not in loc
        assert "verif-hash" not in loc


def test_nginx_webhook_locations_come_before_the_ip_block():
    server = _nginx_tls_server()
    ip_at = server.index("# allow 203.0.113.0/24;")
    assert server.index("# deny all;") > ip_at
    for p in WEBHOOKS:
        assert server.index(f"location = {p} {{") < ip_at


def test_the_cockpit_only_vhosts_carry_no_webhook_exception():
    # these front `sigil serve` (127.0.0.1:8733), which serves no webhook: an exemption there would expose nothing
    # useful and only widen the surface
    for f in (RP / "Caddyfile", RP / "cockpit.nginx.conf"):
        live = _live(f.read_text(encoding="utf-8"))
        assert "webhooks" not in live and "allow all" not in live, f.name


# --- nginx, behaviourally -------------------------------------------------------------------------------------------

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
def console(tmp_path):
    if _NGINX is None:
        pytest.skip("nginx not installed")
    up = _Upstream()
    port = _free_port()
    server = _nginx_tls_server()
    inner = server[server.index("{") + 1: server.rindex("}")]
    kept = []
    for line in inner.splitlines():
        s = line.strip()
        if s.startswith(("listen ", "http2 ", "ssl_", "server_name ")):
            continue
        if s.startswith("# allow 203.0.113.0/24;"):
            line = "    allow 203.0.113.0/24;"                 # the IP block switched ON; it excludes 127.0.0.1
        elif s == "# deny all;":
            line = "    deny all;"
        kept.append(line.replace("127.0.0.1:8770", f"127.0.0.1:{up.port}"))
    body = "\n".join(kept)
    assert "allow 203.0.113.0/24;" in body and "\n    deny all;" in body
    d = tmp_path / "nginx"
    d.mkdir()
    user = "user root;\n" if os.geteuid() == 0 else ""
    (d / "nginx.conf").write_text(
        f"{user}daemon off;\npid {d}/nginx.pid;\nerror_log {d}/error.log;\nevents {{}}\nhttp {{\n"
        f"  access_log off;\n  client_body_temp_path {d}/cb;\n  proxy_temp_path {d}/px;\n"
        f"  fastcgi_temp_path {d}/fc;\n  uwsgi_temp_path {d}/uw;\n  scgi_temp_path {d}/sc;\n"
        f"  server {{\n    listen 127.0.0.1:{port};\n    server_name console.vigilguard.net;\n{body}\n  }}\n}}\n",
        encoding="utf-8")
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


def _send(port, method, path, body=b"", headers=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    h = {"Host": "console.vigilguard.net", **(headers or {})}
    c.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
    for k, v in h.items():
        c.putheader(k, v)
    c.putheader("Content-Length", str(len(body)))
    c.endheaders(body)
    r = c.getresponse()
    r.read()
    c.close()
    return r.status


@pytest.mark.parametrize("path", WEBHOOKS)
def test_a_webhook_post_from_outside_the_allow_list_reaches_the_proxy_unchanged(console, path):
    port, up = console
    sig = "t=1700000000,v1=" + "ab" * 32
    body = b'{"id":"evt_test","object":"event"}'
    assert _send(port, "POST", path, body, {"Stripe-Signature": sig, "Content-Type": "application/json"}) == 202
    assert up.seen == [{"method": "POST", "path": path, "host": "console.vigilguard.net", "sig": sig, "body": body}]


@pytest.mark.parametrize("method", ["GET", "PUT", "DELETE"])
def test_another_method_on_the_webhook_path_is_refused(console, method):
    port, up = console
    assert _send(port, method, "/webhooks/stripe") == 403
    assert up.seen == []


@pytest.mark.parametrize("path", ["/webhooks/stripex", "/webhooks/stripe/", "/webhooks/Stripe", "/webhooks/",
                                  "/webhooks/github", "/sovereign/api/stream", "/", "/offense/api/v1/engage"])
def test_every_other_path_still_meets_the_ip_block(console, path):
    port, up = console
    assert _send(port, "POST", path, b"{}") == 403
    assert up.seen == []


@pytest.mark.parametrize("path", ["/webhooks/x/../stripe", "/webhooks//stripe", "/webhooks/%73tripe",
                                  "/webhooks/stripe?x=1", "/sovereign/../webhooks/stripe",
                                  "/sovereign/api/x/../../../webhooks/stripe", "/webhooks/./stripe"])
def test_a_raw_line_that_only_normalises_onto_the_webhook_is_not_forwarded(console, path):
    port, up = console
    assert _send(port, "POST", path, b"{}") == 404
    assert up.seen == []


def test_a_body_over_the_cap_is_refused_at_the_edge(console):
    port, up = console
    assert _send(port, "POST", "/webhooks/stripe", b"x" * (1024 * 1024 + 1)) == 413
    assert up.seen == []


# --- the docs name the exact URL and the exception ----------------------------------------------------------------

def test_the_runbooks_state_the_webhook_url_and_the_single_exception():
    go_live = (REPO / "docs" / "runbooks" / "GO-LIVE-quickstart.md").read_text(encoding="utf-8")
    s9b = go_live[go_live.index("## 9b."): go_live.index("## 10.")]
    assert "`https://<console host>/webhooks/stripe`" in s9b
    assert "`https://console.vigilguard.net/webhooks/stripe`" in s9b
    assert "<operator ingress>" not in s9b
    aws = (REPO / "docs" / "runbooks" / "AWS-DEPLOY.md").read_text(encoding="utf-8")
    assert "exactly `https://console.vigilguard.net/webhooks/stripe`" in aws and "**one** exception" in aws
    remote = (REPO / "apps" / "sigil" / "deploy" / "REMOTE-HOSTING.md").read_text(encoding="utf-8")
    assert "one exception" in remote and "`POST /webhooks/stripe`" in remote
