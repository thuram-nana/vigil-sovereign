"""Stripe parity ST-3: the billing spool drain reads (body, signature, time) through an envelope reader.

* A watcher built with only ``verif_hash`` uses the Flutterwave V1 reader, so Flutterwave draining is unchanged.
* The drain checks the envelope schema against the reader's BEFORE reading: an envelope of another provider's
  schema handed to the Flutterwave drain is quarantined and mints nothing (and vice versa).
* A custom reader's signature header and time are exactly what ``BillingSigner.ingest`` receives.
* Exactly one source of the triple: ``verif_hash`` and ``envelope_reader`` together, or a reader without a schema,
  is refused at construction.
"""
from __future__ import annotations

import base64
import hashlib
import json
import tempfile
from pathlib import Path

import pytest

from sigil.governor.billing import EVENT_TOPUP, BillingSigner, Entitlement, FlutterwaveBillingProvider
from sigil.governor.metering import PlanCreditLedger
from sigil.governor.subscription import SubscriptionRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.inbound.billing_spool import (BillingSpoolError, BillingSpoolWatcher, EnvelopeReader,
                                         FlutterwaveEnvelopeV1, decode_envelope_body)
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
_SECRET = "flw-secret-hash-reader"
_V1 = "vigil.webhook.billing.v1"
_OTHER = "vigil.webhook.stripe.v1"
_TABLE = {"9911": {"id": 9911, "status": "successful", "currency": "USD", "tx_ref": "vigil:acme:n1",
                   "created_at": 100.0, "meta": {"price_id": "price_topup_200"}}}


class _SpySigner(BillingSigner):
    """A real signer that records what the drain hands to ``ingest``."""

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.calls: list = []

    def ingest(self, raw_body, sig_header, *, now):
        self.calls.append((raw_body, sig_header, now))
        return super().ingest(raw_body, sig_header, now=now)


def _signer():
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    w = WalletRegistry(s, owner_key=OWNER, trusted_pubkey=OWNER.public_key_b64)
    signer = _SpySigner(FlutterwaveBillingProvider(_SECRET, lambda txid: _TABLE.get(str(txid))), wallet=w,
                        subscriptions=SubscriptionRegistry(s, owner_key=OWNER, trusted_pubkey=OWNER.public_key_b64),
                        plan=PlanCreditLedger(s, owner_key=OWNER, trusted_pubkey=OWNER.public_key_b64),
                        catalog={"price_topup_200": Entitlement(kind=EVENT_TOPUP, credits=200)})
    return signer, w


def _put(root: Path, schema: str, raw: bytes, **extra) -> None:
    env = json.dumps({"schema": schema, "body_b64": base64.b64encode(raw).decode("ascii"), **extra}).encode()
    inc = root / "incoming"
    inc.mkdir(parents=True, exist_ok=True)
    (inc / (hashlib.sha256(env).hexdigest()[:32] + ".json")).write_bytes(env)


_BODY = json.dumps({"event": "charge.completed", "data": {"id": 9911}}).encode()


def _reasons(root: Path) -> str:
    return "\n".join(p.read_text() for p in (root / "rejected").glob("*.reason"))


def test_a_watcher_built_with_only_the_secret_uses_the_v1_reader_unchanged():
    signer, w = _signer()
    root = Path(tempfile.mkdtemp())
    watcher = BillingSpoolWatcher(signer, spool_dir=root, verif_hash=_SECRET, now_fn=lambda: 123.0)
    assert isinstance(watcher._reader, FlutterwaveEnvelopeV1) and watcher._reader.schema == _V1
    _put(root, _V1, _BODY)
    assert watcher.drain()["minted"] == 1 and w.available("acme") == 200
    assert signer.calls == [(_BODY, _SECRET, 123.0)]       # the secret as the header, the drain's own clock


def test_another_providers_envelope_is_quarantined_by_the_flutterwave_drain():
    signer, w = _signer()
    root = Path(tempfile.mkdtemp())
    watcher = BillingSpoolWatcher(signer, spool_dir=root, verif_hash=_SECRET, now_fn=lambda: 100.0)
    _put(root, _OTHER, _BODY, sig="t=1,v1=00")
    res = watcher.drain()
    assert res["rejected"] == 1 and res["minted"] == 0 and w.available("acme") == 0
    assert signer.calls == []                               # never reached ingest
    assert "unexpected envelope schema" in _reasons(root)


class _OtherReader(EnvelopeReader):
    schema = _OTHER

    def read(self, obj, *, drain_now):
        sig = obj.get("sig")
        if not isinstance(sig, str):
            raise BillingSpoolError("envelope missing sig")
        return decode_envelope_body(obj), sig, float(obj["received_at"])


def test_a_custom_reader_supplies_the_signature_and_time_ingest_sees():
    signer, w = _signer()
    root = Path(tempfile.mkdtemp())
    watcher = BillingSpoolWatcher(signer, spool_dir=root, envelope_reader=_OtherReader(), now_fn=lambda: 999.0)
    _put(root, _OTHER, _BODY, sig="t=50,v1=ab", received_at=50.0)
    watcher.drain()
    assert signer.calls == [(_BODY, "t=50,v1=ab", 50.0)]   # the envelope's header + receive time, not the drain's
    assert w.available("acme") == 0                         # wrong header for this provider -> mints nothing


def test_a_custom_reader_drain_quarantines_a_v1_envelope_and_a_reader_refusal():
    signer, w = _signer()
    root = Path(tempfile.mkdtemp())
    watcher = BillingSpoolWatcher(signer, spool_dir=root, envelope_reader=_OtherReader(), now_fn=lambda: 100.0)
    _put(root, _V1, _BODY)                                  # Flutterwave envelope on the other drain
    _put(root, _OTHER, _BODY, received_at=1.0)              # the reader refuses: no sig
    res = watcher.drain()
    assert res["rejected"] == 2 and res["minted"] == 0 and signer.calls == []
    reasons = _reasons(root)
    assert "unexpected envelope schema" in reasons and "envelope missing sig" in reasons


def test_exactly_one_source_of_the_signature_is_required():
    signer, _w = _signer()
    with pytest.raises(ValueError):
        BillingSpoolWatcher(signer, spool_dir=tempfile.mkdtemp())                     # neither
    with pytest.raises(ValueError):
        BillingSpoolWatcher(signer, spool_dir=tempfile.mkdtemp(), verif_hash="")      # empty secret
    with pytest.raises(ValueError):
        BillingSpoolWatcher(signer, spool_dir=tempfile.mkdtemp(), verif_hash=_SECRET,
                            envelope_reader=_OtherReader())                           # both
    with pytest.raises(ValueError):
        BillingSpoolWatcher(signer, spool_dir=tempfile.mkdtemp(), envelope_reader=EnvelopeReader())  # no schema
    with pytest.raises(ValueError):
        BillingSpoolWatcher(signer, spool_dir=tempfile.mkdtemp(), envelope_reader=object())  # type: ignore[arg-type]


def test_the_shared_body_decoder_is_strict():
    with pytest.raises(BillingSpoolError):
        decode_envelope_body({})
    with pytest.raises(BillingSpoolError):
        decode_envelope_body({"body_b64": "not base64!"})
    with pytest.raises(BillingSpoolError):
        decode_envelope_body({"body_b64": base64.b64encode(b"x" * (192 * 1024 + 1)).decode()})
    assert decode_envelope_body({"body_b64": base64.b64encode(b"ok").decode()}) == b"ok"
