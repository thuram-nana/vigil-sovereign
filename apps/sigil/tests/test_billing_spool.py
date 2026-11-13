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
    return {str(txid): {"id": txid, "status": "successful", "currency": "USD", "tx_ref": "vigil:acme:n1", "created_at": 100.0,
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


def test_transient_verify_failure_is_quarantined_not_buried():
    # VERIFIER CONTRACT (red-pen C/A1+B1): a TRANSIENT re-verify failure (the verifier RAISES — network/timeout/
    # 5xx) must be QUARANTINED to rejected/ (recoverable), NOT archived to processed/ as a final no-op — else a
    # genuinely-paid transaction the proxy already 202'd would be silently buried. A definitive None is the only
    # thing that archives as a no-op (covered by the unverifiable/unknown-price tests).
    def boom(_txid):
        raise ConnectionError("flutterwave /verify unreachable (transient)")

    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    w = WalletRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    subs = SubscriptionRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    plan = PlanCreditLedger(s, owner_key=OWNER, trusted_pubkey=OP)
    signer = BillingSigner(FlutterwaveBillingProvider(_SECRET, boom), wallet=w, subscriptions=subs, plan=plan,
                           catalog={"price_topup_200": Entitlement(kind=EVENT_TOPUP, credits=200)})
    spool = Path(tempfile.mkdtemp())
    watcher = BillingSpoolWatcher(signer, spool_dir=str(spool), verif_hash=_SECRET, now_fn=lambda: 100.0)
    _spool(spool, _body(9911))
    res = watcher.drain()
    assert res["minted"] == 0 and res["rejected"] == 1 and res["noop"] == 0
    assert len(list((spool / "rejected").glob("*.json"))) == 1       # recoverable, NOT buried in processed/
    assert list((spool / "processed").glob("*.json")) == []
    assert w.available("acme") == 0


def test_unknown_price_is_a_safe_noop():
    table = {"9911": {"id": 9911, "status": "successful", "currency": "USD", "tx_ref": "vigil:acme:n1", "created_at": 100.0,
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


def _envelope_bytes(raw: bytes) -> bytes:
    return json.dumps({"schema": _SCHEMA, "body_b64": base64.b64encode(raw).decode("ascii")}).encode("utf-8")


def test_reclaim_re_admits_a_crash_stranded_envelope_so_no_paid_webhook_is_lost():
    """Audit HIGH (money nothing-lost): a drain CLAIMS a file into working/ before it ingests; a crash there
    strands a PAID webhook in working/ — out of incoming/, never in processed/. Without reclaim it is lost
    forever (drain only scans incoming/). With it, the next drain re-admits + mints it."""
    _s, w, watcher, root = _rig(_ok_tx())
    (root / "working").mkdir(parents=True, exist_ok=True)
    (root / "working" / "stranded.json").write_bytes(_envelope_bytes(_body(9911)))
    # nothing in incoming/ — the only copy is the crash-stranded one in working/
    res = watcher.drain()
    assert res["minted"] == 1, "the reclaimed paid webhook must be processed, not silently lost"
    assert w.available("acme") == 200
    assert list((root / "working").glob("*.json")) == [], "the reclaimed file is archived, not left stranded"


def test_reclaim_does_not_double_credit_after_a_post_mint_crash():
    """The crash-AFTER-mint-BEFORE-archive case: the tx already credited (no processed/ marker written yet).
    Reclaim re-admits it and re-ingest credits nothing, because BillingSigner.ingest is idempotent by the
    verified transaction's event_id — so money is never DOUBLE-credited by the reclaim."""
    _s, w, watcher, root = _rig(_ok_tx())
    _spool(root, _body(9911))
    watcher.drain()
    assert w.available("acme") == 200
    # a second delivery of the SAME tx got claimed into working/ but was never archived (distinct bytes so the
    # content-addressed marker does NOT catch it — ingest's event_id idempotency is the load-bearing backstop).
    env = json.dumps({"schema": _SCHEMA, "body_b64": base64.b64encode(_body(9911)).decode("ascii"),
                      "nonce": "distinct-wrapper"}).encode("utf-8")
    (root / "working").mkdir(parents=True, exist_ok=True)
    (root / "working" / "stranded.json").write_bytes(env)
    watcher.drain()
    assert w.available("acme") == 200, "a reclaimed post-mint envelope must NOT double-credit"
    assert list((root / "working").glob("*.json")) == []


def test_watch_loop_survives_a_drain_error():
    """Audit MED: watch() must not die on a transient drain fault (IO/spine/dir) and strand every subsequent
    billing webhook. The guarded loop swallows the error and continues; here stop fires after one iteration."""
    import threading
    _s, _w, watcher, _root = _rig(_ok_tx())
    calls = {"n": 0}

    def boom() -> dict:
        calls["n"] += 1
        raise RuntimeError("transient spine/IO fault outside the per-file loop")

    watcher.drain = boom  # type: ignore[method-assign]
    stop = threading.Event()
    stop.set()                                   # wait() returns True right after the first (failing) drain
    watcher.watch(interval=0.0, stop=stop)       # MUST NOT raise despite drain() raising
    assert calls["n"] == 1, "the loop attempted the drain and swallowed its error instead of dying"


def test_drain_failed_recurring_charge_marks_past_due():
    # H4 end-to-end through the drain: a re-verified FAILED recurring (payment_plan) charge drains to a mint (not
    # a noop) and latches the (active) subscription to past_due — the webhook-driven dunning path, fail-closed.
    from sigil.governor.subscription import STATUS_PAST_DUE, SubscriptionRegistry
    table = {"9977": {"id": 9977, "status": "failed", "tx_ref": "vigil:acme:n7", "payment_plan": "flwplan_pro",
                      "created_at": 500.0}}
    s, _w, watcher, root = _rig(table)
    subs = SubscriptionRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    subs.subscribe("acme", "pro", 6000, period_start=100.0, period_end=1100.0, issued_at=100.0)  # active @100
    _spool(root, _body(9977))
    res = watcher.drain()
    assert res["minted"] == 1 and res["rejected"] == 0 and res["noop"] == 0
    assert subs.subscription("acme").status == STATUS_PAST_DUE
