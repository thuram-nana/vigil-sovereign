"""End to end: a Stripe delivery to https://hooks.vigilguard.net/webhooks/stripe is spooled by the REAL `vigil up` proxy.

The shipped hooks vhost (apps/sigil/deploy/reverse-proxy/vigil-hooks.nginx.conf: its TLS server block, verbatim
except for the TLS/listen lines and the upstream port) runs under a real nginx in front of a real proxy built by
``make_proxy_server`` the way a ``--domain console.vigilguard.net`` deployment builds it: its Host allow-list names
the CONSOLE host only, and the Stripe lane is mounted (spool + secret).

What this pins:
  * the proxy's ``/webhooks/stripe`` route answers a delivery whose Host is ``hooks.vigilguard.net`` — the route sits
    in the probe-safe band ahead of the Host/Origin gate — so the vhost forwards Host unchanged and NO proxy code
    change (no extra allowed host, no Host rewrite at the edge) is needed;
  * a correctly signed delivery is spooled byte-for-byte with its signature; a forged one is refused (401) and
    spools nothing; with the Stripe lane unmounted nothing is spooled either;
  * the Host gate itself is untouched: a plane-control path with ``Host: hooks.vigilguard.net`` sent STRAIGHT to the
    proxy (bypassing the vhost) is still refused, and through the vhost it never reaches the proxy at all.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import json
import os
import re
import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path

import pytest

from vigil_integration.uiproxy import make_proxy_server

REPO = Path(__file__).resolve().parents[2]
HOOKS_NGINX = REPO / "apps" / "sigil" / "deploy" / "reverse-proxy" / "vigil-hooks.nginx.conf"
HOOKS = "hooks.vigilguard.net"
CONSOLE = "console.vigilguard.net"
SECRET = "whsec_" + "e2e-dummy-not-a-real-secret"
_NGINX = shutil.which("nginx") or ("/usr/sbin/nginx" if Path("/usr/sbin/nginx").exists() else None)


def _brace_block(text: str, start: int) -> str:
    i = text.index("{", start)
    depth, j = 0, i
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


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _wait_port(port: int, proc: "subprocess.Popen | None" = None) -> None:
    end = time.monotonic() + 10
    while True:
        if proc is not None:
            assert proc.poll() is None, proc.stderr.read().decode() if proc.stderr else "exited"
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.3).close()
            return
        except OSError:
            assert time.monotonic() < end, f"nothing listening on {port}"
            time.sleep(0.05)


@pytest.fixture()
def stack(tmp_path, monkeypatch):
    """(nginx port, proxy port, stripe spool dir) — the hooks vhost in front of the real proxy."""
    if _NGINX is None:
        pytest.skip("nginx not installed")

    def start(*, stripe_mounted: bool = True):
        monkeypatch.setenv("VIGIL_STRIPE_WEBHOOK_SECRET", SECRET)
        ui = tmp_path / "ui"
        ui.mkdir(exist_ok=True)
        spool = tmp_path / "stripe-spool"
        srv = make_proxy_server("127.0.0.1", 0, ui, allowed_hosts=(CONSOLE,),
                                allowed_origins=(f"https://{CONSOLE}",),
                                webhook_stripe_spool_dir=str(spool) if stripe_mounted else None)
        threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        servers.append(srv)
        proxy_port = srv.server_address[1]

        text = HOOKS_NGINX.read_text(encoding="utf-8")
        blocks = [_brace_block(text, m.start()) for m in re.finditer(r"^server \{", text, re.M)]
        (tls,) = [b for b in blocks if "listen 443 ssl;" in b]
        inner = tls[tls.index("{") + 1: tls.rindex("}")]
        kept = [ln.replace("127.0.0.1:8770", f"127.0.0.1:{proxy_port}") for ln in inner.splitlines()
                if not ln.strip().startswith(("listen ", "http2 ", "ssl_"))]
        port = _free_port()
        d = tmp_path / f"nginx-{port}"
        d.mkdir()
        user = "user root;\n" if os.geteuid() == 0 else ""
        (d / "nginx.conf").write_text(
            f"{user}daemon off;\npid {d}/nginx.pid;\nerror_log {d}/error.log;\nevents {{}}\nhttp {{\n"
            f"  access_log off;\n  client_body_temp_path {d}/cb;\n  proxy_temp_path {d}/px;\n"
            f"  fastcgi_temp_path {d}/fc;\n  uwsgi_temp_path {d}/uw;\n  scgi_temp_path {d}/sc;\n"
            f"  server {{\n    listen 127.0.0.1:{port};\n" + "\n".join(kept) + "\n  }\n}\n", encoding="utf-8")
        p = subprocess.Popen([_NGINX, "-p", str(d), "-c", str(d / "nginx.conf"), "-e", str(d / "error.log")],
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        procs.append(p)
        _wait_port(port, p)
        return port, proxy_port, spool

    servers: list = []
    procs: list = []
    yield start
    for p in procs:
        p.terminate()
        try:
            p.wait(5)
        except subprocess.TimeoutExpired:
            p.kill()
    for srv in servers:
        srv.shutdown()
        srv.server_close()


def _sign(body: bytes, t: "int | None" = None) -> str:
    ts = str(int(time.time()) if t is None else t)
    v1 = hmac.new(SECRET.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return f"t={ts},v1={v1}"


def _post(port: int, path: str, body: bytes, headers: dict, host: str = HOOKS, method: str = "POST"):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
    for k, v in {"Host": host, **headers}.items():
        c.putheader(k, v)
    c.putheader("Content-Length", str(len(body)))
    c.endheaders(body)
    r = c.getresponse()
    data = r.read()
    c.close()
    return r.status, data


def _spooled(spool: Path) -> "list[dict]":
    inc = spool / "incoming"
    return [json.loads(f.read_text(encoding="utf-8")) for f in sorted(inc.glob("*.json"))] if inc.is_dir() else []


def test_a_signed_delivery_to_the_hooks_host_is_spooled_by_the_real_proxy(stack):
    port, _proxy, spool = stack()
    body = b'{"id":"evt_e2e_1","object":"event","type":"checkout.session.completed"}'
    sig = _sign(body)
    status, data = _post(port, "/webhooks/stripe", body, {"Stripe-Signature": sig,
                                                          "Content-Type": "application/json"})
    assert status == 202, data
    assert json.loads(data) == {"ok": True, "spooled": True}
    (env,) = _spooled(spool)
    assert env["schema"] == "vigil.webhook.stripe.v1"
    assert base64.b64decode(env["body_b64"]) == body                  # the body, byte-for-byte
    assert env["stripe_signature"] == sig                              # the signature header, unchanged


def test_a_forged_delivery_is_refused_and_spools_nothing(stack):
    port, _proxy, spool = stack()
    body = b'{"id":"evt_forged","object":"event"}'
    status, _ = _post(port, "/webhooks/stripe", body, {"Stripe-Signature": _sign(b"something else")})
    assert status == 401
    status, _ = _post(port, "/webhooks/stripe", body, {})
    assert status == 401
    assert _spooled(spool) == []


def test_with_the_stripe_lane_unmounted_nothing_is_spooled(stack):
    port, _proxy, spool = stack(stripe_mounted=False)
    body = b'{"id":"evt_unmounted","object":"event"}'
    status, _ = _post(port, "/webhooks/stripe", body, {"Stripe-Signature": _sign(body)})
    assert status != 202
    assert _spooled(spool) == []


def test_the_proxy_host_gate_still_refuses_the_hooks_host_on_everything_else(stack):
    port, proxy_port, spool = stack()
    # straight to the proxy, bypassing the vhost: plane control with the hooks Host is refused by the Host gate
    status, data = _post(proxy_port, "/__vigil/plane/status", b"", {}, host=f"127.0.0.1:{proxy_port}", method="GET")
    assert b"Host=" not in data                                      # control: the proxy's own Host passes the gate
    status, data = _post(proxy_port, "/__vigil/plane/status", b"", {}, host=HOOKS, method="GET")
    assert status == 403 and b"Host=" in data, data
    # through the vhost, nothing but the two webhook paths ever reaches the proxy
    for path in ("/__vigil/plane/status", "/sovereign/api/whoami", "/", "/webhooks/x/../stripe"):
        status, _ = _post(port, path, b"{}", {})
        assert status == 404, path
    assert _spooled(spool) == []
