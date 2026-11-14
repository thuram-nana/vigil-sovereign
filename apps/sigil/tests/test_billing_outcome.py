"""What each drained billing webhook did, recorded by the drain and read by the dangling-checkout sweep.

  * ``BillingSigner.ingest_outcome`` returns the seq ``ingest`` returns plus WHY: ``minted`` / ``already_minted`` or
    one no-op reason per place the signer mints nothing; ``apply`` / ``ingest`` are unchanged;
  * the drain records it, report-only, as ``outcomes/<sha256>.outcome`` beside ``processed/<sha256>.json`` — after
    the signer returned and before the envelope is archived; a duplicate leaves the first record; a failed record
    write changes neither the mint nor the counts; a refused envelope gets no record;
  * ``ops-sweep tx-refs`` drops a checkout only when an envelope carrying it MINTED; a no-op is reported ``noop``
    with its reasons, an envelope drained without a record ``processed_unrecorded``
    (precedence minted > noop > processed_unrecorded > quarantined > retrying > no_webhook);
  * a Stripe plan's ``invoice.paid`` names its checkout only through the subscription the drain fetched: its
    record carries that tx_ref, so the subscription-mode session the drain archived as a no-op is then handled.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
from pathlib import Path

import pytest

from sigil import ops_sweeps
from sigil.governor.billing import (EVENT_PAYMENT_FAILED, EVENT_SUBSCRIPTION_ACTIVE, EVENT_SUBSCRIPTION_CANCELED,
                                     EVENT_TOPUP, NOOP_REASONS, BillingEvent, BillingProvider, BillingSigner,
                                     Entitlement, FlutterwaveBillingProvider, IngestOutcome, MockBillingProvider)
from sigil.governor.metering import PlanCreditLedger
from sigil.governor.subscription import SubscriptionRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.inbound.billing_spool import BillingSpoolWatcher
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64
_SECRET = "flw-secret-hash-outcome"
_CATALOG = {"price_topup_200": Entitlement(kind=EVENT_TOPUP, credits=200),
            "price_pro": Entitlement(kind=EVENT_SUBSCRIPTION_ACTIVE, plan_id="pro", allotment=6000, period_s=1000.0)}
_EXPECTED = {"price_topup_200": (4900, "USD"), "price_pro": (9900, "USD")}


class _Fixed(BillingProvider):
    """A provider that 'verifies' every body as the one preset event (or nothing)."""

    def __init__(self, event):
        self.event = event

    def verify_and_parse(self, raw_body, sig_header, *, now):
        return self.event


def _signer(provider, **kw):
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    reg = dict(owner_key=OWNER, trusted_pubkey=OP)
    return BillingSigner(provider, wallet=WalletRegistry(s, **reg), subscriptions=SubscriptionRegistry(s, **reg),
                         plan=PlanCreditLedger(s, **reg), catalog=_CATALOG, expected=_EXPECTED, **kw)


def _ev(kind=EVENT_TOPUP, price="price_topup_200", eid="evt_1", amount=4900, ccy="USD", created=100.0, **data):
    return BillingEvent(event_id=eid, kind=kind, org_id="acme", created=created, price_id=price,
                        amount_minor=amount, currency=ccy, data=data)


def _outcome(event, **kw) -> IngestOutcome:
    return _signer(_Fixed(event), **kw).ingest_outcome(b"{}", "sig", now=100.0)


# =====================================================================================================================
# the signer names why it minted or not
# =====================================================================================================================
@pytest.mark.parametrize("event,kw,reason", [
    (_ev(), {}, "minted"),
    (_ev(price="nope"), {}, "unknown_price"),
    (_ev(amount=4899), {}, "underpaid_or_currency"),
    (_ev(ccy="EUR"), {}, "underpaid_or_currency"),
    (_ev(ccy=""), {"require_verified_amount": True}, "no_verified_amount"),
    (_ev(eid=" "), {}, "bad_event_id"),
    (_ev(kind=EVENT_TOPUP, price="price_pro", amount=9900), {}, "no_entitlement"),
    (None, {}, "not_mintable"),
], ids=["minted", "unknown_price", "underpaid", "currency", "no_verified_amount", "bad_event_id", "no_entitlement",
        "not_mintable"])
def test_each_outcome_names_its_reason(event, kw, reason):
    out = _outcome(event, **kw)
    assert out.reason == reason and out.event is event
    assert (out.seq is not None) == out.minted == (reason == "minted")
    assert reason == "minted" or reason in NOOP_REASONS


def test_a_plan_period_names_minted_then_already_minted_on_a_redelivery():
    signer = _signer(_Fixed(_ev(kind=EVENT_SUBSCRIPTION_ACTIVE, price="price_pro", amount=9900)))
    first = signer.ingest_outcome(b"{}", "s", now=100.0)
    again = signer.ingest_outcome(b"{}", "s", now=100.0)              # the same event, delivered twice
    assert (first.reason, first.minted) == ("minted", True)
    assert (again.seq, again.reason, again.minted) == (None, "already_minted", True)
    older = signer
    older.provider = _Fixed(_ev(kind=EVENT_SUBSCRIPTION_ACTIVE, price="price_pro", amount=9900, eid="evt_0",
                                created=50.0))
    stale = older.ingest_outcome(b"{}", "s", now=100.0)               # an older period the fold does not honour
    assert (stale.seq, stale.reason, stale.minted) == (None, "stale_or_inert", False)


def test_down_events_name_their_line():
    assert _outcome(_ev(kind=EVENT_PAYMENT_FAILED, price="price_pro")).reason in ("minted", "stale_or_inert")
    signer = _signer(_Fixed(_ev(kind=EVENT_SUBSCRIPTION_CANCELED, price="price_pro")))
    signer.subscriptions = None
    assert signer.ingest_outcome(b"{}", "s", now=1.0).reason == "no_line"


def test_apply_and_ingest_return_exactly_what_they_did():
    signer = _signer(_Fixed(_ev()))
    seq = signer.ingest(b"{}", "s", now=100.0)
    assert isinstance(seq, int)
    assert signer.apply(_ev(price="nope"), now=100.0) is None
    assert signer.ingest_outcome(b"{}", "s", now=100.0).seq == seq + 1      # a replayed grant appends (fold dedups)


def test_a_subclass_wrapping_ingest_still_sees_every_call():
    class Spy(BillingSigner):
        calls = 0

        def ingest(self, raw_body, sig_header, *, now):
            Spy.calls += 1
            return super().ingest(raw_body, sig_header, now=now)

    class Liar(BillingSigner):
        def ingest(self, raw_body, sig_header, *, now):
            super().ingest(raw_body, sig_header, now=now)
            return None                                               # hides the seq it got

    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    reg = dict(owner_key=OWNER, trusted_pubkey=OP)
    parts = dict(wallet=WalletRegistry(s, **reg), subscriptions=SubscriptionRegistry(s, **reg),
                 plan=PlanCreditLedger(s, **reg), catalog=_CATALOG, expected=_EXPECTED)
    out = Spy(_Fixed(_ev()), **parts).ingest_outcome(b"{}", "s", now=100.0)
    assert Spy.calls == 1 and out.reason == "minted"
    assert Liar(_Fixed(_ev()), **parts).ingest_outcome(b"{}", "s", now=100.0) == IngestOutcome(None, None,
                                                                                              "unrecorded")


def test_a_stripe_plan_invoice_names_the_checkout_of_its_subscription():
    from sigil.governor import billing as b
    calls = []

    class _Stripe(b.StripeBillingProvider):
        def __init__(self):
            pass

        def _invoice_subscription(self, inv):
            calls.append(inv["id"])
            return {"id": "sub_1", "metadata": {"org_id": "acme", "price_id": "price_pro",
                                                "tx_ref": "vigil:acme:n7"}}

    inv = {"id": "in_1", "status": "paid", "billing_reason": "subscription_create", "amount_paid": 9900,
           "currency": "usd", "status_transitions": {"paid_at": 1_700_000_000}}
    ev = _Stripe()._map_invoice_paid(inv)
    assert ev is not None and ev.data == {"subscription": "sub_1", "tx_ref": "vigil:acme:n7"}
    failed = _Stripe()._map_invoice_failed({"id": "in_2", "status": "open", "created": 1_700_000_000})
    assert failed is not None and failed.data["tx_ref"] == "vigil:acme:n7"


# =====================================================================================================================
# the drain records it
# =====================================================================================================================
def _tx(txid=9911, amount=4900, ref="vigil:acme:n1"):
    return {str(txid): {"id": txid, "status": "successful", "currency": "USD", "amount": amount / 100,
                        "tx_ref": ref, "created_at": 100.0, "meta": {"price_id": "price_topup_200"}}}


def _rig(table):
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    reg = dict(owner_key=OWNER, trusted_pubkey=OP)
    w = WalletRegistry(s, **reg)
    signer = BillingSigner(FlutterwaveBillingProvider(_SECRET, lambda txid: table.get(str(txid))), wallet=w,
                           subscriptions=SubscriptionRegistry(s, **reg), plan=PlanCreditLedger(s, **reg),
                           catalog=_CATALOG, expected=_EXPECTED)
    spool = Path(tempfile.mkdtemp())
    return w, BillingSpoolWatcher(signer, spool_dir=spool, verif_hash=_SECRET, now_fn=lambda: 100.0), spool


def _put(spool: Path, txid) -> str:
    raw = json.dumps({"event": "charge.completed", "data": {"id": txid}}).encode()
    env = json.dumps({"schema": "vigil.webhook.billing.v1", "body_b64": base64.b64encode(raw).decode()}).encode()
    (spool / "incoming").mkdir(parents=True, exist_ok=True)
    (spool / "incoming" / (hashlib.sha256(env).hexdigest()[:32] + ".json")).write_bytes(env)
    return hashlib.sha256(env).hexdigest()


def _record(spool: Path, sha: str):
    p = spool / "outcomes" / f"{sha}.outcome"
    return json.loads(p.read_text()) if p.exists() else None


def test_the_drain_records_a_mint_and_a_noop():
    w, watcher, spool = _rig({**_tx(), **_tx(9912, amount=100, ref="vigil:acme:n2")})
    paid, under = _put(spool, 9911), _put(spool, 9912)
    out = watcher.drain()
    assert (out["minted"], out["noop"]) == (1, 1) and w.available("acme") == 200
    assert _record(spool, paid) == {"v": 1, "outcome": "minted", "reason": "minted", "kind": EVENT_TOPUP,
                                    "tx_ref": "vigil:acme:n1"}
    assert _record(spool, under) == {"v": 1, "outcome": "noop", "reason": "underpaid_or_currency",
                                     "kind": EVENT_TOPUP, "tx_ref": "vigil:acme:n2"}
    assert sorted(p.name for p in (spool / "processed").iterdir()) == sorted([f"{paid}.json", f"{under}.json"])
    assert oct(os.stat(spool / "outcomes").st_mode & 0o777) == "0o700"
    assert oct(os.stat(spool / "outcomes" / f"{paid}.outcome").st_mode & 0o777) == "0o600"


def test_an_unverified_body_is_recorded_not_mintable():
    _w, watcher, spool = _rig({})
    sha = _put(spool, 4040)
    assert watcher.drain()["noop"] == 1
    assert _record(spool, sha) == {"v": 1, "outcome": "noop", "reason": "not_mintable", "kind": "", "tx_ref": ""}


def test_a_duplicate_leaves_the_first_record():
    _w, watcher, spool = _rig(_tx())
    sha = _put(spool, 9911)
    watcher.drain()
    first = (spool / "outcomes" / f"{sha}.outcome").read_bytes()
    os.utime(spool / "outcomes" / f"{sha}.outcome", (1, 1))
    _put(spool, 9911)
    assert watcher.drain()["deduped"] == 1
    assert (spool / "outcomes" / f"{sha}.outcome").read_bytes() == first
    assert os.stat(spool / "outcomes" / f"{sha}.outcome").st_mtime == 1


def test_a_failed_record_never_changes_the_money(capsys):
    w, watcher, spool = _rig(_tx())
    (spool / "outcomes").write_text("not a directory")                   # the record cannot be written
    sha = _put(spool, 9911)
    out = watcher.drain()
    assert (out["minted"], out["rejected"]) == (1, 0) and w.available("acme") == 200
    assert (spool / "processed" / f"{sha}.json").exists()
    assert "could not record the outcome" in capsys.readouterr().err


def test_the_record_is_written_after_the_signer_returns_and_never_for_a_refusal():
    w, watcher, spool = _rig(_tx())
    seen = {}
    real = watcher.signer.ingest_outcome

    def spy(*a, **k):
        seen["before"] = list((spool / "outcomes").glob("*")) if (spool / "outcomes").exists() else []
        return real(*a, **k)
    watcher.signer.ingest_outcome = spy
    sha = _put(spool, 9911)
    watcher.drain()
    assert seen["before"] == [] and _record(spool, sha) is not None

    def boom(*a, **k):
        raise RuntimeError("the processor said no")
    watcher.signer.ingest_outcome = boom
    sha2 = _put(spool, 9913)
    assert watcher.drain()["rejected"] == 1
    assert _record(spool, sha2) is None


# =====================================================================================================================
# the dangling-checkout sweep reads the records
# =====================================================================================================================
def _flw(spool: Path, name: str, ref: str, *, outcome=None, reason="minted", side_ref=None, sub="processed"):
    body = {"event": "charge.completed", "data": {"id": 1, "tx_ref": ref}}
    env = {"schema": "vigil.webhook.billing.v1", "body_b64": base64.b64encode(json.dumps(body).encode()).decode()}
    (spool / sub).mkdir(parents=True, exist_ok=True)
    (spool / sub / f"{name}.json").write_text(json.dumps(env))
    if outcome is not None:
        (spool / "outcomes").mkdir(exist_ok=True)
        (spool / "outcomes" / f"{name}.outcome").write_text(json.dumps(
            {"v": 1, "outcome": outcome, "reason": reason, "kind": "", "tx_ref": side_ref or ref}))


def _sweep(spool, refs, provider="flutterwave"):
    rows = ops_sweeps.sweep_dangling_tx_refs([{"tx_ref": r, "created": 0.0} for r in refs], spool_dir=spool,
                                             now=1000.0, ttl_s=10.0, provider=provider)["items"]
    return {r["tx_ref"].rsplit(":", 1)[1]: (r["status"], tuple(r.get("reasons", ()))) for r in rows}


def test_only_a_minted_outcome_is_handled(tmp_path):
    _flw(tmp_path, "a", "vigil:o:paid", outcome="minted")
    _flw(tmp_path, "b", "vigil:o:under", outcome="noop", reason="underpaid_or_currency")
    _flw(tmp_path, "c", "vigil:o:legacy")                                # drained before outcomes were recorded
    _flw(tmp_path, "d", "vigil:o:broken")
    (tmp_path / "outcomes" / "d.outcome").write_text("{not json")
    _flw(tmp_path, "e", "vigil:o:quar", sub="rejected")
    refs = [f"vigil:o:{n}" for n in ("paid", "under", "legacy", "broken", "quar", "lost")]
    assert _sweep(tmp_path, refs) == {"under": ("noop", ("underpaid_or_currency",)),
                                      "legacy": ("processed_unrecorded", ()), "broken": ("processed_unrecorded", ()),
                                      "quar": ("quarantined", ()), "lost": ("no_webhook", ())}


def test_precedence_minted_over_noop_over_unrecorded_over_quarantined(tmp_path):
    _flw(tmp_path, "a1", "vigil:o:x", outcome="noop", reason="stale_or_inert")
    _flw(tmp_path, "a2", "vigil:o:x", outcome="minted")                  # a later delivery minted it
    _flw(tmp_path, "b1", "vigil:o:y", outcome="noop", reason="not_mintable")
    _flw(tmp_path, "b2", "vigil:o:y")
    _flw(tmp_path, "b3", "vigil:o:y", outcome="noop", reason="unknown_price")
    _flw(tmp_path, "c1", "vigil:o:z")
    _flw(tmp_path, "c2", "vigil:o:z", sub="rejected")
    _flw(tmp_path, "d1", "vigil:o:w", sub="rejected")
    _flw(tmp_path, "d2", "vigil:o:w", sub="retry")
    assert _sweep(tmp_path, [f"vigil:o:{n}" for n in "xyzw"]) == {
        "y": ("noop", ("not_mintable", "unknown_price")), "z": ("processed_unrecorded", ()), "w": ("quarantined", ())}


def _stripe(spool: Path, name: str, obj: dict, etype: str, *, outcome=None, reason="minted", side_ref=""):
    env = {"schema": "vigil.webhook.stripe.v1", "stripe_signature": "t=1,v1=00", "received_at": 1,
           "body_b64": base64.b64encode(json.dumps({"type": etype, "data": {"object": obj}}).encode()).decode()}
    (spool / "processed").mkdir(parents=True, exist_ok=True)
    (spool / "processed" / f"{name}.json").write_text(json.dumps(env))
    if outcome is not None:
        (spool / "outcomes").mkdir(exist_ok=True)
        (spool / "outcomes" / f"{name}.outcome").write_text(json.dumps(
            {"v": 1, "outcome": outcome, "reason": reason, "kind": "", "tx_ref": side_ref}))


def test_a_stripe_plan_is_handled_by_its_invoice_and_reported_without_it(tmp_path):
    session = {"id": "cs_1", "mode": "subscription", "client_reference_id": "vigil:acme:plan"}
    _stripe(tmp_path, "s", session, "checkout.session.completed", outcome="noop", reason="not_mintable")
    assert _sweep(tmp_path, ["vigil:acme:plan"], "stripe") == {"plan": ("noop", ("not_mintable",))}   # control
    _stripe(tmp_path, "i", {"id": "in_1", "subscription": "sub_1"}, "invoice.paid", outcome="minted",
            side_ref="vigil:acme:plan")
    assert _sweep(tmp_path, ["vigil:acme:plan"], "stripe") == {}
    # a record names a reference only for its own provider's envelopes
    assert _sweep(tmp_path, ["vigil:acme:plan"]) == {"plan": ("no_webhook", ())}
