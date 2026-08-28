"""Wave 2 (parity) — the sovereign `/api/verify` read: in-process spine self-verify (chain + owner-signed head)."""
from __future__ import annotations

import json
import tempfile
import threading
import time
import urllib.error
import urllib.request

from sigil.governor.identity import ensure_owner_keypair
from sigil.ui.server import build_server

TOKEN = "owner-shared-token-verify"


def _serve(sp):
    ensure_owner_keypair()
    s = build_server(token=TOKEN, port=0, spine_path=sp)
    port = s.server_address[1]
    threading.Thread(target=s.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return s, port


def _get(port, path, token=TOKEN):
    h = {"Origin": f"http://127.0.0.1:{port}", "Host": f"127.0.0.1:{port}"}
    if token:
        h["X-SIGIL-Token"] = token
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=h)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:  # noqa: BLE001
            return e.code, {}


def test_verify_route_returns_spine_status():
    _s, port = _serve(tempfile.mktemp(suffix=".jsonl"))
    code, d = _get(port, "/api/verify")
    assert code == 200
    assert isinstance(d.get("chain_ok"), bool) and "head_present" in d and "ok" in d
    # a fresh spine has a valid chain and no owner-signed head yet → ok == chain_ok
    assert d["ok"] == d["chain_ok"]


def test_verify_route_requires_a_token():
    _s, port = _serve(tempfile.mktemp(suffix=".jsonl"))
    code, _d = _get(port, "/api/verify", token=None)
    assert code == 401
