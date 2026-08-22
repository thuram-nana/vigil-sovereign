"""W6-1 — real /healthz (liveness) and /readyz (dependency-checking readiness) on the witness server.

The witness previously exposed only /health, which returned an in-memory attribute and checked no
dependency. This adds an UNAUTHENTICATED /healthz liveness route and a /readyz that probes the witness's
REAL dependency — its ability to durably persist the co-signed tip (A8), without which a restart could
equivocate. /readyz returns 503 when that tip store is not writable, proven not-a-constant by pointing
the tip path's directory at a regular file.
"""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

from vigil_core import generate_keypair

from vigil_integration.witness_service import WitnessService, serve_witness

_PRODUCER = generate_keypair()


def _serve(svc):
    srv = serve_witness("127.0.0.1", 0, svc, read_timeout=1.0)
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    return srv, srv.server_address[1]


def _get(port: int, path: str):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as r:  # noqa: S310
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def test_healthz_is_liveness_and_carries_no_secret(tmp_path):
    svc = WitnessService("w", generate_keypair(), producer_pubkeys=[_PRODUCER.public_key_b64],
                         clock=lambda: 1, tip_path=str(tmp_path / "tip.json"))
    srv, port = _serve(svc)
    try:
        st, body = _get(port, "/healthz")
        assert st == 200, body
        assert json.loads(body) == {"ok": True}          # no key_id / secret on the liveness probe
    finally:
        srv.shutdown(); srv.server_close()


def test_readyz_200_when_tip_store_writable(tmp_path):
    # /readyz is a READ-ONLY probe (it does not create the dir); the tip dir must already exist.
    (tmp_path / "sub").mkdir()
    svc = WitnessService("w", generate_keypair(), producer_pubkeys=[_PRODUCER.public_key_b64],
                         clock=lambda: 1, tip_path=str(tmp_path / "sub" / "tip.json"))
    srv, port = _serve(svc)
    try:
        st, body = _get(port, "/readyz")
        assert st == 200, body
        d = json.loads(body)
        assert d["ok"] is True
        assert any(c["name"] == "tip_store" and c["ok"] for c in d["checks"])
    finally:
        srv.shutdown(); srv.server_close()


def test_readyz_503_when_tip_store_down_negative_control(tmp_path):
    """NEGATIVE CONTROL: the tip path's directory IS a regular file, so the tip cannot be persisted —
    /readyz flips to 503. The endpoint is not a constant."""
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x", encoding="utf-8")
    svc = WitnessService("w", generate_keypair(), producer_pubkeys=[_PRODUCER.public_key_b64],
                         clock=lambda: 1, tip_path=str(blocker / "tip.json"))
    srv, port = _serve(svc)
    try:
        st, body = _get(port, "/readyz")
        assert st == 503, body
        d = json.loads(body)
        assert d["ok"] is False
        assert any(c["name"] == "tip_store" and not c["ok"] for c in d["checks"])
    finally:
        srv.shutdown(); srv.server_close()


def test_probes_expose_no_secret(tmp_path):
    blocker = tmp_path / "nd"
    blocker.write_text("x", encoding="utf-8")
    svc = WitnessService("w", generate_keypair(), producer_pubkeys=[_PRODUCER.public_key_b64],
                         clock=lambda: 1, tip_path=str(blocker / "tip.json"))
    srv, port = _serve(svc)
    try:
        for path in ("/healthz", "/readyz"):
            _, body = _get(port, path)
            assert str(tmp_path) not in body             # no filesystem path leaks
            assert "traceback" not in body.lower()
    finally:
        srv.shutdown(); srv.server_close()
