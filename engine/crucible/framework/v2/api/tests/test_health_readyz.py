"""W6-1 — real /healthz (liveness) and /readyz (dependency-checking readiness) on the loopback external API.

The API gates every /api/v1/* route behind an optional API key (stacked on the loopback bind + same-origin
guard). A k8s/LB probe presents no key, so /healthz and /readyz sit BEFORE the key gate: they are
UNAUTHENTICATED and carry no secret. /readyz checks the API's REAL dependency — the console working
directory it reads from and the importer persists into — and returns 503 when it cannot be written, proven
not-a-constant by pointing that dependency at a path that does not exist.
"""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager

from framework.v2.api import server
from framework.v2.console import actions as console_actions


@contextmanager
def _running(*, api_key=None):
    httpd = server.serve(host="127.0.0.1", port=0, api_key=api_key)
    port = httpd.server_address[1]
    th = threading.Thread(target=httpd.serve_forever, daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        th.join(timeout=5)


def _get(url: str):
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310 (loopback test)
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def test_api_route_is_still_key_gated():
    """Control: with an API key configured, a real read route WITHOUT the key is refused (401) — so the
    probes below are proven to bypass a gate that is genuinely active, not a dead one."""
    with _running(api_key="k-control-not-a-real-secret") as base:
        st, _ = _get(base + "/api/v1/status")
        assert st == 401


def test_healthz_unauthenticated_even_with_key_configured():
    with _running(api_key="k-control-not-a-real-secret") as base:
        st, body = _get(base + "/healthz")
        assert st == 200, body
        assert json.loads(body) == {"ok": True}


def test_readyz_200_when_store_writable():
    with _running() as base:
        st, body = _get(base + "/readyz")
        assert st == 200, body
        d = json.loads(body)
        assert d["ok"] is True
        assert any(c["name"] == "console_store" and c["ok"] for c in d["checks"])


def test_readyz_503_when_store_down_negative_control(monkeypatch, tmp_path):
    """NEGATIVE CONTROL: point the console working dir at a path that does not exist so os.access fails —
    /readyz flips to 503. The endpoint is not a constant."""
    monkeypatch.setattr(console_actions, "console_dir", lambda: tmp_path / "does-not-exist")
    with _running() as base:
        st, body = _get(base + "/readyz")
        assert st == 503, body
        d = json.loads(body)
        assert d["ok"] is False
        assert any(c["name"] == "console_store" and not c["ok"] for c in d["checks"])


def test_probes_expose_no_secret(monkeypatch, tmp_path):
    monkeypatch.setattr(console_actions, "console_dir", lambda: tmp_path / "nope")
    with _running(api_key="k-control-not-a-real-secret") as base:
        for path in ("/healthz", "/readyz"):
            _, body = _get(base + path)
            low = body.lower()
            assert "token" not in low
            assert "k-control" not in low               # the configured key never leaks
            assert str(tmp_path) not in body            # no filesystem path leaks
            assert "traceback" not in low
