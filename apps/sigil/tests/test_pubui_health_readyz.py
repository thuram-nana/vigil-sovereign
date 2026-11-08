"""HLTH-1 — real /healthz (liveness) and /readyz (dependency-checking readiness) on the keyless, cookieless,
offense-free PUBLIC site (`sigil serve-public`, the `sigil-public.service` long-running edge).

The public site previously exposed no probe surface at all, so an LB/orchestrator could neither liveness-
nor readiness-check it. These add an UNAUTHENTICATED /healthz (the process answers) and a /readyz that
checks the edge's one REAL dependency — its packaged content root must exist and hold the site shell it
serves at `/`. /readyz returns 503 when the root is missing/shell-less, proven not-a-constant by pointing
the root at a directory with no index.html. Both carry no filesystem path or secret.

Run: PYTHONPATH=apps/sigil:packages/core/vigil_core:. SIGIL_HOME=$(mktemp -d) \
     .venv-sovereign/bin/python -m pytest -q apps/sigil/tests/test_pubui_health_readyz.py
"""
from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request

from sigil.ui.pubui import build_public_server


def _serve(root):
    srv = build_public_server(host="127.0.0.1", port=0, root=str(root))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return srv, srv.server_address[1]


def _ready_root(tmp_path):
    root = tmp_path / "site"
    root.mkdir()
    (root / "index.html").write_text("<!doctype html><title>x</title>", encoding="utf-8")
    return root


def _get(port, path):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as r:  # noqa: S310
            return r.status, dict(r.headers), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()


def test_healthz_is_liveness_and_carries_no_secret(tmp_path):
    srv, port = _serve(_ready_root(tmp_path))
    try:
        st, hdrs, body = _get(port, "/healthz")
        assert st == 200, body
        assert json.loads(body) == {"ok": True}
        assert "Set-Cookie" not in hdrs                  # the public plane is cookieless, probes included
        assert hdrs.get("Cache-Control") == "no-store"   # a readiness verdict is never cached
    finally:
        srv.shutdown()


def test_readyz_200_when_content_root_present(tmp_path):
    root = _ready_root(tmp_path)
    srv, port = _serve(root)
    try:
        st, _h, body = _get(port, "/readyz")
        assert st == 200, body
        d = json.loads(body)
        assert d["ok"] is True
        assert any(c["name"] == "content_root" and c["ok"] for c in d["checks"])
        assert str(tmp_path) not in body                 # no filesystem path leaks
    finally:
        srv.shutdown()


def test_readyz_503_when_shell_missing_negative_control(tmp_path):
    """NEGATIVE CONTROL: a content root with no index.html shell — /readyz flips to 503. Not a constant."""
    empty = tmp_path / "broken"
    empty.mkdir()                                        # a dir, but with no index.html site shell
    srv, port = _serve(empty)
    try:
        st, _h, body = _get(port, "/readyz")
        assert st == 503, body
        d = json.loads(body)
        assert d["ok"] is False
        assert any(c["name"] == "content_root" and not c["ok"] for c in d["checks"])
        assert str(tmp_path) not in body                 # even the failure body leaks no path
    finally:
        srv.shutdown()
