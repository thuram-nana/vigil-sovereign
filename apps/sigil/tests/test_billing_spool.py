"""Slice C — the SOVEREIGN billing-webhook spool drain (BillingSpoolWatcher).

Load-bearing invariants (a false-green would let an unauthenticated at-rest body mint, double-credit a replay,
or crash/hang the drain on a hostile file):
  * the drain mints ONLY via BillingSigner.ingest -> a verified successful charge credits once; a duplicate
    envelope is deduped (content-addressed) AND ingest is idempotent, so a replay never double-credits;
  * fail-closed: a body whose transaction does NOT re-verify mints nothing (safe no-op, archived not errored);
    a wrong verif-hash makes ingest mint nothing; a malformed envelope / bad base64 / wrong schema is quarantined;
  * hostile-file-hardened: an oversized file is quarantined, never read whole; the drain never raises on one bad
    file;
  * the drain NEVER stores the secret — it is injected (off-spine) and only passed to ingest.
"""
from __future__ import annotations

import base64
import json
import os
import tempfile
from pathlib import Path

import pytest

from sigil.governor.billing import (EVENT_TOPUP, BillingSigner, Entitlement, FlutterwaveBillingProvider)
from sigil.governor.metering import PlanCreditLedger
from sigil.governor.subscription import SubscriptionRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.inbound.billing_spool import BillingSpoolError, BillingSpoolWatcher
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64
_SECRET = "flw-secret-hash-spool"
_SCHEMA = "vigil.webhook.billing.v1"


def _verifier(table):
    def v(txid):
        return table.get(str(txid))
    return v


def _rig(table, *, verif_hash=_SECRET):
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    w = WalletRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    subs = SubscriptionRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    plan = PlanCreditLedger(s, owner_key=OWNER, trusted_pubkey=OP)
    flw = FlutterwaveBillingProvider(_SECRET, _verifier(table))
    signer = BillingSigner(flw, wallet=w, subscriptions=subs, plan=plan, catalog={
        "price_topup_200": Entitlement(kind=EVENT_TOPUP, credits=200)})
    spool = tempfile.mkdtemp()
    watcher = BillingSpoolWatcher(signer, spool_dir=spool, verif_hash=verif_hash, now_fn=lambda: 100.0)
    return s, w, watcher, Path(spool)


def _body(txid):
    return json.dumps({"event": "charge.completed", "data": {"id": txid}}).encode()


def _spool(spool_root: Path, raw: bytes, *, name=None):
    env = json.dumps({"schema": _SCHEMA, "body_b64": base64.b64encode(raw).decode("ascii")}).encode("utf-8")
    inc = spool_root / "incoming"
    inc.mkdir(parents=True, exist_ok=True)
    import hashlib
    fname = name or (hashlib.sha256(env).hexdigest()[:32] + ".json")
    (inc / fname).write_bytes(env)
    return env


def _ok_tx(txid=9911):
    return {str(txid): {"id": txid, "status": "successful", "tx_ref": "vigil:acme:n1", "created_at": 100.0,
                        "meta": {"price_id": "price_topup_200"}}}


def test_verified_charge_mints_once_and_dedupes():
    _s, w, watcher, root = _rig(_ok_tx())
    _spool(root, _body(9911))
    res = watcher.drain()
    assert res["minted"] == 1 and res["noop"] == 0 and res["rejected"] == 0
    assert w.available("acme") == 200
    # re-spool the SAME envelope -> content-addressed dedup, no second mint
    _spool(root, _body(9911))
    res2 = watcher.drain()
    assert res2["deduped"] == 1 and res2["minted"] == 0
    assert w.available("acme") == 200, "a duplicate delivery must not double-credit"


def test_a_fresh_duplicate_delivery_is_idempotent_via_ingest():
    # Even a DIFFERENT envelope wrapper for the same transaction (so spool-dedup does NOT catch it) credits once,
    # because ingest is idempotent by the verified transaction id.
    _s, w, watcher, root = _rig(_ok_tx())
    _spool(root, _body(9911), name="a.json")
    _spool(root, _body(9911), name="b.json")     # same tx id, distinct file name + identical bytes...
    # distinct wrapper: add a harmless whitespace difference so the sha256 (and marker) differ
    inc = root / "incoming"
    (inc / "c.json").write_bytes(json.dumps({"schema": _SCHEMA,
        "body_b64": base64.b64encode(_body(9911)).decode("ascii")}, indent=1).encode())
    watcher.drain()
    assert w.available("acme") == 200, "ingest idempotency credits one real tx once across wrappers"


def test_unverifiable_charge_mints_nothing():
    _s, w, watcher, root = _rig({})              # verifier knows no transaction -> re-verify returns None
    _spool(root, _body(404))
    res = watcher.drain()
    assert res["minted"] == 0 and res["noop"] == 1 and res["rejected"] == 0
    assert w.available("acme") == 0


def test_wrong_verif_hash_mints_nothing():
    # the drain is handed a verif_hash that does NOT match the provider secret -> ingest's constant-time compare
    # fails -> nothing is parsed, nothing minted (the verif-hash gate is enforced inside ingest).
    _s, w, watcher, root = _rig(_ok_tx(), verif_hash="WRONG-SECRET")
    _spool(root, _body(9911))
    res = watcher.drain()
    assert res["minted"] == 0 and res["noop"] == 1
    assert w.available("acme") == 0


def test_unknown_price_is_a_safe_noop():
    table = {"9911": {"id": 9911, "status": "successful", "tx_ref": "vigil:acme:n1", "created_at": 100.0,
                      "meta": {"price_id": "price_NOT_in_catalog"}}}
    _s, w, watcher, root = _rig(table)
    _spool(root, _body(9911))
    res = watcher.drain()
    assert res["minted"] == 0 and res["noop"] == 1 and res["rejected"] == 0
    assert w.available("acme") == 0


def test_malformed_envelopes_are_quarantined():
    _s, w, watcher, root = _rig(_ok_tx())
    inc = root / "incoming"
    inc.mkdir(parents=True, exist_ok=True)
    (inc / "notjson.json").write_bytes(b"not json at all")
    (inc / "wrongschema.json").write_bytes(json.dumps({"schema": "nope", "body_b64": "aGk="}).encode())
    (inc / "badb64.json").write_bytes(json.dumps({"schema": _SCHEMA, "body_b64": "!!!not-base64!!!"}).encode())
    (inc / "nobody.json").write_bytes(json.dumps({"schema": _SCHEMA}).encode())
    res = watcher.drain()
    assert res["rejected"] == 4 and res["minted"] == 0
    assert len(list((root / "rejected").glob("*.json"))) == 4
    assert w.available("acme") == 0


def test_oversized_file_is_quarantined_not_read_whole():
    _s, _w, watcher, root = _rig(_ok_tx())
    inc = root / "incoming"
    inc.mkdir(parents=True, exist_ok=True)
    (inc / "huge.json").write_bytes(b"{" + b"A" * (256 * 1024 + 10))   # over the 256KiB read cap
    res = watcher.drain()
    assert res["rejected"] == 1 and res["minted"] == 0


def test_requires_signer_and_secret():
    with pytest.raises(ValueError):
        BillingSpoolWatcher(object(), spool_dir=tempfile.mkdtemp(), verif_hash=_SECRET)  # type: ignore[arg-type]
    _s, _w, _watcher, _root = _rig(_ok_tx())
    with pytest.raises(ValueError):
        BillingSpoolWatcher(_watcher.signer, spool_dir=tempfile.mkdtemp(), verif_hash="")


def test_drain_never_stores_the_secret_on_disk():
    # the spool envelope carries only the body; the secret is injected + lives in the drain, never written.
    _s, _w, watcher, root = _rig(_ok_tx())
    _spool(root, _body(9911))
    watcher.drain()
    for d in ("incoming", "working", "processed", "rejected"):
        for f in (root / d).glob("*"):
            assert _SECRET not in f.read_text(encoding="utf-8", errors="ignore"), f"secret leaked into {f}"
