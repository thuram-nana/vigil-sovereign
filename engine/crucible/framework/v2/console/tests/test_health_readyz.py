"""W6-1 — real /healthz (liveness) and /readyz (dependency-checking readiness) on the Ops Console.

The console gates every /api/* route behind an anti-rebinding Host check AND a session token. A k8s/LB
probe can present neither, so /healthz and /readyz sit BEFORE both gates: they are UNAUTHENTICATED,
Host-UNGATED, and carry no secret. /readyz checks the console's REAL dependency — its writable working
directory, where every run/report/blackboard is persisted — and returns 503 when it cannot be written,
proven not-a-constant by pointing that dependency at a path that does not exist.
"""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager

from framework.v2.console import actions, server


@contextmanager
def _running():
    httpd = server.serve(host="127.0.0.1", port=0)
    port = httpd.server_address[1]
    th = threading.Thread(target=httpd.serve_forever, daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()


def _get(url: str, *, host: str | None = None):
    """A probe request: NO session token, and a caller-chosen Host (a k8s/LB probe's Host, not the
    loopback authority the anti-rebinding gate would demand)."""
    h = {}
    if host is not None:
        h["Host"] = host
    req = urllib.request.Request(url, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310 (loopback test)
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def test_api_route_is_still_host_and_token_gated():
    """Control: a real data route with a probe Host + no token is refused (403 rebind / 401 token) — so
    the probes below are proven to bypass a gate that is genuinely active, not a dead one."""
    with _running() as base:
        st, _ = _get(base + "/api/status", host="kube-probe/1.0")
        assert st in (401, 403)


def test_healthz_unauthenticated_and_host_ungated():
    with _running() as base:
        st, body = _get(base + "/healthz", host="kube-probe/1.0")
        assert st == 200, body
        assert json.loads(body) == {"ok": True}


def test_readyz_200_when_store_writable():
    with _running() as base:
        st, body = _get(base + "/readyz", host="kube-probe/1.0")
        assert st == 200, body
        d = json.loads(body)
        assert d["ok"] is True
        assert any(c["name"] == "console_store" and c["ok"] for c in d["checks"])


def test_readyz_503_when_store_down_negative_control(monkeypatch, tmp_path):
    """NEGATIVE CONTROL: point the console's working dir at a path that does not exist so it cannot be
    written — /readyz flips to 503. The endpoint is not a constant."""
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path / "does-not-exist")
    with _running() as base:
        st, body = _get(base + "/readyz", host="kube-probe/1.0")
        assert st == 503, body
        d = json.loads(body)
        assert d["ok"] is False
        assert any(c["name"] == "console_store" and not c["ok"] for c in d["checks"])


def test_probes_expose_no_secret(monkeypatch, tmp_path):
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path / "nope")
    with _running() as base:
        for path in ("/healthz", "/readyz"):
            _, body = _get(base + path, host="kube-probe/1.0")
            low = body.lower()
            assert "token" not in low
            assert str(tmp_path) not in body           # no filesystem path leaks
            assert "traceback" not in low
