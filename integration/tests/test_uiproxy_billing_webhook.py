"""SaaS Slice C — the INBOUND Flutterwave BILLING webhook route on the pure-stdlib reverse proxy, end to end.

Drives the REAL `make_proxy_server` over loopback. The route lives in the probe-safe band (a provider POST
carries no session bearer / Origin); Flutterwave's `verif-hash` PLAINTEXT secret-equality is the SOLE
pre-filter. Pins:
  * a valid verif-hash → 202 AND one inert envelope spooled carrying ONLY the raw body (base64), NEVER the
    verif-hash (which equals the secret);
  * fail-closed: a bad/missing verif-hash → 401, an unset secret → 503, a non-POST → 405, an oversized body →
    413 — and NOTHING is spooled in any of those;
  * content-addressed idempotency (the identical delivery spools exactly one file);
  * the route is ABSENT (404) when no billing spool dir is configured;
  * a 202 is spool-only — never forwarded/spawned (there is no backend, so a forward would 502);
  * END TO END: proxy-spooled envelope → sovereign BillingSpoolWatcher.drain() → the owner-signed wallet is
    credited exactly once (and a replay does not double-credit).
"""
from __future__ import annotations

import json
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from vigil_integration.uiproxy import make_proxy_server

_SECRET = "flw-verif-hash-secret-xyz"
_SECRET_ENV = "VIGIL_BILLING_WEBHOOK_SECRET"


def _serve(tmp_path: Path, *, enabled: bool = True):
    serve_dir = tmp_path / "ui"
    serve_dir.mkdir(parents=True, exist_ok=True)
    spool = tmp_path / "bspool"
    srv = make_proxy_server("127.0.0.1", 0, serve_dir,
                            webhook_billing_spool_dir=str(spool) if enabled else None)
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    time.sleep(0.05)
    return srv, srv.server_address[1], spool


def _post(port: int, body: bytes, headers: dict) -> tuple[int, dict]:
    req = urllib.request.Request(f"http://127.0.0.1:{port}/webhooks/billing", data=body,
                                 method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310 (loopback test)
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode() or "{}")
        except ValueError:
            return e.code, {}


def _charge_body(txid=9911):
    return json.dumps({"event": "charge.completed", "data": {"id": txid}}).encode("utf-8")


def _hdrs(*, verif=_SECRET):
    h = {"Content-Type": "application/json"}
    if verif is not None:
        h["verif-hash"] = verif
    return h


def _spooled(spool: Path) -> list[dict]:
    incoming = spool / "incoming"
    if not incoming.is_dir():
        return []
    return [json.loads(p.read_text()) for p in incoming.glob("*.json")]


def test_valid_verif_hash_spools_body_only_and_202s(monkeypatch, tmp_path):
    monkeypatch.setenv(_SECRET_ENV, _SECRET)
    srv, port, spool = _serve(tmp_path)
    try:
        body = _charge_body()
        status, resp = _post(port, body, _hdrs())
        assert status == 202 and resp.get("spooled") is True, (status, resp)
        envs = _spooled(spool)
        assert len(envs) == 1
        env = envs[0]
        assert env["schema"] == "vigil.webhook.billing.v1" and "body_b64" in env
        # CRITICAL: the verif-hash (== the secret) is NEVER written to the spool.
        assert _SECRET not in json.dumps(env)
        import base64
        assert base64.b64decode(env["body_b64"]) == body
    finally:
        srv.shutdown()


def test_bad_or_missing_verif_hash_401_and_nothing_spooled(monkeypatch, tmp_path):
    monkeypatch.setenv(_SECRET_ENV, _SECRET)
    srv, port, spool = _serve(tmp_path)
    try:
        assert _post(port, _charge_body(), _hdrs(verif="WRONG"))[0] == 401
        assert _post(port, _charge_body(), _hdrs(verif=None))[0] == 401
        assert _spooled(spool) == []
    finally:
        srv.shutdown()


def test_unset_secret_503(monkeypatch, tmp_path):
    monkeypatch.delenv(_SECRET_ENV, raising=False)
    srv, port, spool = _serve(tmp_path)
    try:
        assert _post(port, _charge_body(), _hdrs())[0] == 503
        assert _spooled(spool) == []
    finally:
        srv.shutdown()


def test_non_post_405(monkeypatch, tmp_path):
    monkeypatch.setenv(_SECRET_ENV, _SECRET)
    srv, port, _spool = _serve(tmp_path)
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{port}/webhooks/billing", method="GET")
        try:
            with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310
                code = r.status
        except urllib.error.HTTPError as e:
            code = e.code
        assert code == 405
    finally:
        srv.shutdown()


def test_oversized_body_413(monkeypatch, tmp_path):
    monkeypatch.setenv(_SECRET_ENV, _SECRET)
    srv, port, spool = _serve(tmp_path)
    try:
        huge = b'{"x":"' + b"A" * (128 * 1024 + 10) + b'"}'
        assert _post(port, huge, _hdrs())[0] == 413
        assert _spooled(spool) == []
    finally:
        srv.shutdown()


def test_route_absent_when_unconfigured_404(monkeypatch, tmp_path):
    monkeypatch.setenv(_SECRET_ENV, _SECRET)
    srv, port, _spool = _serve(tmp_path, enabled=False)
    try:
        assert _post(port, _charge_body(), _hdrs())[0] == 404     # falls through to static/route → 404
    finally:
        srv.shutdown()


def test_idempotent_identical_delivery_spools_once(monkeypatch, tmp_path):
    monkeypatch.setenv(_SECRET_ENV, _SECRET)
    srv, port, spool = _serve(tmp_path)
    try:
        body = _charge_body()
        _post(port, body, _hdrs())
        _post(port, body, _hdrs())                                 # identical → content-addressed, one file
        assert len(_spooled(spool)) == 1
    finally:
        srv.shutdown()


def test_end_to_end_proxy_spool_then_sovereign_drain_credits_once(monkeypatch, tmp_path):
    # The whole seam: a verified Flutterwave charge POSTed to the proxy → spooled → the SOVEREIGN drain
    # re-verifies the transaction and mints exactly one owner-signed wallet grant; a replay does not double.
    from sigil.governor.billing import EVENT_TOPUP, BillingSigner, Entitlement, FlutterwaveBillingProvider
    from sigil.governor.metering import PlanCreditLedger
    from sigil.governor.subscription import SubscriptionRegistry
    from sigil.governor.wallet import WalletRegistry
    from sigil.inbound.billing_spool import BillingSpoolWatcher
    from sigil.reuse import generate_keypair
    from sigil.spine.store import SpineStore

    monkeypatch.setenv(_SECRET_ENV, _SECRET)
    srv, port, spool = _serve(tmp_path)
    try:
        _post(port, _charge_body(9911), _hdrs())                   # proxy authenticates + spools (body-only)
        assert len(_spooled(spool)) == 1
        owner = generate_keypair()
        store = SpineStore(tempfile.mktemp(suffix=".jsonl"))
        w = WalletRegistry(store, owner_key=owner, trusted_pubkey=owner.public_key_b64)
        subs = SubscriptionRegistry(store, owner_key=owner, trusted_pubkey=owner.public_key_b64)
        plan = PlanCreditLedger(store, owner_key=owner, trusted_pubkey=owner.public_key_b64)
        verified = {"9911": {"id": 9911, "status": "successful", "tx_ref": "vigil:acme:n1",
                             "created_at": 100.0, "meta": {"price_id": "price_topup_200"}}}
        signer = BillingSigner(FlutterwaveBillingProvider(_SECRET, lambda t: verified.get(str(t))),
                               wallet=w, subscriptions=subs, plan=plan,
                               catalog={"price_topup_200": Entitlement(kind=EVENT_TOPUP, credits=200)})
        watcher = BillingSpoolWatcher(signer, spool_dir=str(spool), verif_hash=_SECRET, now_fn=lambda: 100.0)
        res = watcher.drain()
        assert res["minted"] == 1 and w.available("acme") == 200
        # a redelivery of the same charge → proxy content-addresses it (one file) → drain dedupes → no double
        _post(port, _charge_body(9911), _hdrs())
        watcher.drain()
        assert w.available("acme") == 200
    finally:
        srv.shutdown()
