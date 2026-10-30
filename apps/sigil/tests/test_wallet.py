"""Behavioral tests for the SaaS per-tenant credit wallet (`governor/wallet.py`).

Load-bearing invariants (a false-green here would let a tenant spend credits they didn't buy, let an attacker
drain a competitor, or let a forged/replayed record move a balance):
  * grant/debit are owner-signed + verified BOTH directions — a forged grant can't credit, a forged debit can't
    drain;
  * idempotent per (org_id, entry_id) — a replayed grant/debit never double-moves the balance;
  * credits clamped > 0 at binding and >= 0 in the fold — a negative can't cancel/refund (fail-open bypass);
  * balance = Σgrants − Σdebits, keyed on org_id == tenant_id; tenants are isolated;
  * bad org_id / kind / amount refused fail-closed at binding.
The prune-survival + anti-replay-across-a-prune properties live in test_snapshot_fold_wallet.py.
"""
from __future__ import annotations

import itertools
import tempfile

import pytest

from sigil.governor.authn import signed_payload
from sigil.governor.wallet import (CREDIT_DEBIT_SIGNAL, CREDIT_GRANT_SIGNAL, GRANT_KINDS, _DEBIT_CORE,
                                    _GRANT_CORE, WalletRegistry)
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64
ATTACKER = generate_keypair()

_iss = itertools.count(1)


def _issue() -> float:
    return float(next(_iss))


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _reg(store):
    return WalletRegistry(store, owner_key=OWNER, trusted_pubkey=OP)


# --- grant / debit / balance roundtrip -------------------------------------------
def test_grant_then_balance():
    s = _store()
    w = _reg(s)
    w.grant("acme", 100, "trial", issued_at=_issue(), entry_id="g1")
    w.grant("acme", 50, "topup", source_ref="evt_1", issued_at=_issue(), entry_id="g2")
    b = w.balance("acme")
    assert (b.granted, b.debited, b.available) == (150, 0, 150)


def test_debit_reduces_balance():
    s = _store()
    w = _reg(s)
    w.grant("acme", 100, "subscription_refill", issued_at=_issue(), entry_id="g1")
    w.debit("acme", 30, engagement_id="eng1", issued_at=_issue(), entry_id="d1")
    assert w.available("acme") == 70


def test_available_clamps_when_overdebited():
    # the gate prevents over-debit in production; the fold itself must still never go negative.
    s = _store()
    w = _reg(s)
    w.grant("acme", 100, "trial", issued_at=_issue(), entry_id="g1")
    w.debit("acme", 250, engagement_id="eng1", issued_at=_issue(), entry_id="d1")
    b = w.balance("acme")
    assert b.granted == 100 and b.debited == 250 and b.available == 0


# --- idempotency (replay must not double-move the balance) -----------------------
def test_idempotent_grant_replay():
    s = _store()
    w = _reg(s)
    seq = w.grant("acme", 100, "topup", issued_at=_issue(), entry_id="g1")
    captured = s.get(seq).payload
    s.append(kind="event", source="governor", actor="WARDEN", payload=captured)   # replay verbatim
    assert w.available("acme") == 100, "a replayed grant (same entry_id) must not re-credit"


def test_idempotent_debit_replay():
    s = _store()
    w = _reg(s)
    w.grant("acme", 100, "topup", issued_at=_issue(), entry_id="g1")
    seq = w.debit("acme", 40, engagement_id="eng1", issued_at=_issue(), entry_id="d1")
    captured = s.get(seq).payload
    s.append(kind="event", source="governor", actor="WARDEN", payload=captured)   # replay verbatim
    assert w.available("acme") == 60, "a replayed debit (same entry_id) must not double-charge"


# --- forgery (unsigned/attacker-signed records are inert both directions) --------
def test_forged_grant_ignored():
    s = _store()
    w = _reg(s)
    w.grant("acme", 100, "trial", issued_at=_issue(), entry_id="g1")
    core = {"signal": CREDIT_GRANT_SIGNAL, "org_id": "acme", "entry_id": "evil", "credits": 9999,
            "kind": "topup", "source_ref": "", "issued_at": 10_000.0}
    s.append(kind="event", source="governor", actor="WARDEN", payload={**signed_payload(core, ATTACKER)})
    assert w.available("acme") == 100, "an attacker-signed grant must not credit"


def test_forged_debit_cannot_drain_a_victim():
    s = _store()
    w = _reg(s)
    w.grant("acme", 100, "subscription_refill", issued_at=_issue(), entry_id="g1")
    # an attacker (no owner key) tries to drain acme's balance with a forged debit
    core = {"signal": CREDIT_DEBIT_SIGNAL, "org_id": "acme", "entry_id": "evil", "credits": 100,
            "engagement_id": "x", "issued_at": 10_000.0}
    s.append(kind="event", source="governor", actor="WARDEN", payload={**signed_payload(core, ATTACKER)})
    assert w.available("acme") == 100, "an attacker-signed debit must not drain a victim's balance"


def test_forged_negative_credits_clamped():
    # even an OWNER-signed record with a NEGATIVE amount must not cancel real balance (fail-open refund).
    s = _store()
    w = _reg(s)
    w.grant("acme", 100, "trial", issued_at=_issue(), entry_id="g1")
    core = {"signal": CREDIT_DEBIT_SIGNAL, "org_id": "acme", "entry_id": "neg", "credits": -500,
            "engagement_id": "x", "issued_at": _issue()}
    s.append(kind="event", source="governor", actor="WARDEN", payload={**signed_payload(core, OWNER)})
    assert w.balance("acme").debited == 0, "a negative debit must clamp to 0 (no refund via a negative)"
    assert w.available("acme") == 100


# --- binding-time validation (fail-closed) ---------------------------------------
def test_zero_or_negative_amount_refused():
    s = _store()
    w = _reg(s)
    for bad in (0, -1, -100):
        with pytest.raises(ValueError):
            w.grant("acme", bad, "trial", issued_at=_issue())
    with pytest.raises(ValueError):
        w.debit("acme", 0, issued_at=_issue())


def test_bad_kind_refused():
    s = _store()
    w = _reg(s)
    for bad in ("", "owner", "gift", "refund"):
        with pytest.raises(ValueError):
            w.grant("acme", 10, bad, issued_at=_issue())
    assert "trial" in GRANT_KINDS and "subscription_refill" in GRANT_KINDS and "topup" in GRANT_KINDS


def test_bad_org_id_refused():
    s = _store()
    w = _reg(s)
    for bad in ("", "bad/slug", "../escape", ".", "a" * 65, "-startsdash", "has space"):
        with pytest.raises(ValueError):
            w.grant(bad, 10, "trial", issued_at=_issue())


def test_grant_requires_owner_key():
    s = _store()
    nokey = WalletRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    nokey.owner_key = None
    with pytest.raises(ValueError):
        nokey.grant("acme", 10, "trial", issued_at=_issue())
    with pytest.raises(ValueError):
        nokey.debit("acme", 10, issued_at=_issue())


# --- tenant isolation ------------------------------------------------------------
def test_tenants_are_isolated():
    s = _store()
    w = _reg(s)
    w.grant("orga", 100, "trial", issued_at=_issue(), entry_id="a1")
    w.grant("orgb", 40, "topup", issued_at=_issue(), entry_id="b1")
    w.debit("orga", 10, issued_at=_issue(), entry_id="ad1")
    assert w.available("orga") == 90
    assert w.available("orgb") == 40
    assert w.available("ghost") == 0                       # unknown tenant reads zero, fail-closed
    assert {b.org_id for b in w.balances()} == {"orga", "orgb"}


def test_grant_and_debit_may_share_an_entry_id():
    # the idempotency key is namespaced by direction: a grant and a debit carrying the SAME entry_id are
    # distinct events and BOTH count. A shared dedup namespace would silently drop one (free credits, or lost
    # paid credits) — the collision the red-pen flagged.
    s = _store()
    w = _reg(s)
    w.grant("acme", 100, "topup", issued_at=_issue(), entry_id="shared")
    w.debit("acme", 40, engagement_id="e", issued_at=_issue(), entry_id="shared")
    b = w.balance("acme")
    assert (b.granted, b.debited, b.available) == (100, 40, 60)


def test_entry_id_autogenerated_unique():
    # two grants with no explicit entry_id must BOTH count (unique auto ids, not collapsed as a replay).
    s = _store()
    w = _reg(s)
    w.grant("acme", 10, "topup", issued_at=_issue())
    w.grant("acme", 10, "topup", issued_at=_issue())
    assert w.available("acme") == 20
