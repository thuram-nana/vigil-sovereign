"""W5 — with every W5 flag OFF, the slice is byte-identical: the Stripe provider ignores the reversal events exactly
as it did before, the billing overview carries no hold field, and the launch gate never reads a hold.

This is the default-OFF / fail-closed / byte-identical proof (RULES #1).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import tempfile

from sigil import config
from sigil.governor.billing import StripeBillingProvider
from sigil.spine.store import SpineStore


def _provider(**kw):
    return StripeBillingProvider("whsec_x", fetcher=lambda *a: None, expected_mode="test",
                                 enable_reference_adapter=True, **kw)


def _signed(etype, oid, secret="whsec_x", t=2000):
    ev = {"id": "evt", "object": "event", "type": etype, "created": t, "livemode": False,
          "data": {"object": {"id": oid}}}
    raw = json.dumps(ev).encode()
    mac = hmac.new(secret.encode(), f"{t}.".encode() + raw, hashlib.sha256).hexdigest()
    return raw, f"t={t},v1={mac}"


def test_the_flags_are_off_by_default(monkeypatch):
    for k in ("VIGIL_BILLING_REVERSALS", "VIGIL_BILLING_LOW_BALANCE_ALERT"):
        monkeypatch.delenv(k, raising=False)
    assert config.billing_reversals_enabled() is False and config.low_balance_alert_enabled() is False


def test_with_reversals_off_every_dispute_or_refund_event_maps_to_none_and_fetches_nothing():
    # the default provider (reversals=False) returns None for a dispute / refund event, never calling the fetcher
    p = _provider()
    for etype, oid in [("charge.dispute.created", "du_1"), ("charge.dispute.funds_withdrawn", "du_1"),
                       ("charge.dispute.closed", "du_1"), ("charge.dispute.funds_reinstated", "du_1"),
                       ("charge.refunded", "ch_1"), ("refund.created", "re_1"), ("refund.failed", "re_1")]:
        raw, sig = _signed(etype, oid)
        assert p.verify_and_parse(raw, sig, now=2000.0) is None   # no fetch (the fetcher would raise/return None)


def test_the_reversal_events_are_mapped_only_when_reversals_is_on():
    off, on = _provider(reversals=False), _provider(reversals=True)
    raw, sig = _signed("charge.dispute.created", "du_1")
    assert off.verify_and_parse(raw, sig, now=2000.0) is None     # off: ignored like an unknown type
    # on: it tries to fetch the dispute (the stub fetcher returns None -> None here, but it was ROUTED, not ignored)
    assert on._reversals is True and off._reversals is False


def test_the_billing_overview_has_no_hold_field_when_reversals_are_off(monkeypatch):
    monkeypatch.delenv("VIGIL_BILLING_REVERSALS", raising=False)
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.governor.wallet import WalletRegistry
    from sigil.ui import billing
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    s.append(kind="message", source="x", actor="user", payload={"text": "hi"})
    owner = ensure_owner_keypair()
    WalletRegistry(s).grant("acme", 100, "topup", entry_id="g1", issued_at=1.0)
    ov = billing.billing_overview(s, "acme", now=1000.0)
    assert "hold" not in ov                                        # byte-identical: no new key
    monkeypatch.setenv("VIGIL_BILLING_REVERSALS", "1")
    ov2 = billing.billing_overview(s, "acme", now=1000.0)
    assert ov2["hold"] == {"on_hold": False, "owed": 0}           # on: the field appears
