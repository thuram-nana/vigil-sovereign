"""Behavioral tests for enterprise POSTPAID (`governor/postpaid.py`): the account-mode registry + arrears ledger.

Load-bearing invariants (a false-green would let a forged/stale record open or inflate a credit line, or let a
tenant draw past it):
  * set_account is owner-signed + FRESH (strictly > per-org high-water); a forged/stale/replayed enable is inert;
  * disable is the SAFE direction — honored on sight even unsigned (never fail-open), lowering only `enabled` and
    retaining the last-open limit/terms; a fresh owner-signed set_account re-opens; a stale webhook-close is ignored;
  * the arrears ledger is ADDITIVE + idempotent per entry_id; accrued = Σ debits − Σ reversals clamped >= 0; a
    forged debit/credit cannot inflate/deflate a victim; tenants are isolated (keyed org_id == tenant_id).
The prune-survival + build==scan properties live in test_snapshot_fold_postpaid.py; the launch-gate integration
(draw-against-the-line / over-limit refuse / settle reverses) in test_postpaid_gate.py.
"""
from __future__ import annotations

import itertools
import tempfile

from sigil.governor.authn import signed_payload
from sigil.governor.postpaid import (POSTPAID_CREDIT_SIGNAL, POSTPAID_DEBIT_SIGNAL, POSTPAID_SIGNAL,
                                     PostpaidArrearsLedger, PostpaidRegistry)
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
    return PostpaidRegistry(store, owner_key=OWNER, trusted_pubkey=OP)


def _arr(store):
    return PostpaidArrearsLedger(store, owner_key=OWNER, trusted_pubkey=OP)


# ---- account registry (LWW) --------------------------------------------------------------------------
def test_set_then_read():
    s = _store()
    r = _reg(s)
    r.set_account("acme", 500, 30, issued_at=_issue())
    a = r.account("acme")
    assert a.enabled and a.credit_limit == 500 and a.net_terms_days == 30
    assert r.is_postpaid("acme") is True
    assert "acme" in {x.org_id for x in r.accounts()}


def test_absent_reads_none_and_not_postpaid():
    s = _store()
    r = _reg(s)
    assert r.account("ghost") is None
    assert r.is_postpaid("ghost") is False
    assert r.is_postpaid("") is False and r.account("") is None


def test_raise_limit_is_a_fresh_set():
    s = _store()
    r = _reg(s)
    r.set_account("acme", 500, 30, issued_at=10.0)
    r.set_account("acme", 900, 15, issued_at=20.0)
    a = r.account("acme")
    assert a.credit_limit == 900 and a.net_terms_days == 15


def test_stale_set_is_ignored_replay_guard():
    s = _store()
    r = _reg(s)
    r.set_account("acme", 500, 30, issued_at=10.0)
    r.set_account("acme", 50, 30, issued_at=5.0)       # STALE (<= high-water) -> inert
    assert r.account("acme").credit_limit == 500


def test_replayed_enable_does_not_resurrect_a_disabled_line():
    s = _store()
    r = _reg(s)
    seq = r.set_account("acme", 500, 30, issued_at=10.0)
    captured = s.get(seq).payload                       # a captured owner-signed enable
    r.disable("acme")                                   # owner closes the line (on sight)
    assert r.is_postpaid("acme") is False
    s.append(kind="event", source="governor", actor="WARDEN", payload=captured)   # replay the enable
    assert r.is_postpaid("acme") is False, "a replayed stale enable must not re-open a closed line (high-water)"


def test_disable_on_sight_then_reopen_fresh():
    s = _store()
    r = _reg(s)
    r.set_account("acme", 500, 30, issued_at=10.0)
    r.disable("acme")                                   # owner-manual latch (issued_at 0.0) -> on sight
    assert r.is_postpaid("acme") is False
    assert r.account("acme").enabled is False and r.account("acme").credit_limit == 500  # line retained for arrears view
    r.set_account("acme", 300, 30, issued_at=20.0)      # fresh re-open
    assert r.is_postpaid("acme") is True and r.account("acme").credit_limit == 300


def test_webhook_close_fresh_applies_stale_ignored():
    s = _store()
    r = _reg(s)
    r.set_account("acme", 500, 30, issued_at=100.0)
    r.disable("acme", issued_at=50.0)                   # STALE webhook close (< open hw) -> ignored
    assert r.is_postpaid("acme") is True
    r.disable("acme", issued_at=200.0)                  # FRESH webhook close (> open hw) -> applies
    assert r.is_postpaid("acme") is False


def test_bare_disable_never_opened_reads_absent():
    s = _store()
    r = _reg(s)
    r.disable("ghost")                                  # never had a line
    assert r.account("ghost") is None and r.is_postpaid("ghost") is False
    assert "ghost" not in {x.org_id for x in r.accounts()}


def test_forged_enable_is_inert():
    s = _store()
    r = _reg(s)
    core = {"signal": POSTPAID_SIGNAL, "org_id": "acme", "credit_limit": 999, "net_terms_days": 30,
            "enabled": True, "issued_at": 50.0}
    s.append(kind="event", source="governor", actor="WARDEN", payload={**signed_payload(core, ATTACKER)})
    assert r.is_postpaid("acme") is False and r.account("acme") is None   # not the owner key -> inert


def test_set_requires_owner_key():
    # the constructor coerces owner_key=None -> owner_keypair(), so null it AFTER construction to exercise the
    # "no owner signing key" guard deterministically (a keyless/unprovisioned process), independent of SIGIL_HOME.
    s = _store()
    import pytest
    r = PostpaidRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    r.owner_key = None
    with pytest.raises(ValueError):
        r.set_account("acme", 500, 30, issued_at=1.0)


def test_limit_and_terms_validated_fail_closed():
    s = _store()
    r = _reg(s)
    import pytest
    for bad in (-1, True, "x", 1.5):
        with pytest.raises(ValueError):
            r.set_account("acme", bad, 30, issued_at=_issue())
    for bad in (-1, 400, True, "x"):
        with pytest.raises(ValueError):
            r.set_account("acme", 500, bad, issued_at=_issue())


# ---- arrears ledger (ADDITIVE) ----------------------------------------------------------------------
def test_accrue_and_accrued():
    s = _store()
    a = _arr(s)
    a.accrue("acme", 100, engagement_id="e1", entry_id="r:1", issued_at=1.0)
    a.accrue("acme", 50, engagement_id="e2", entry_id="r:2", issued_at=2.0)
    assert a.accrued("acme") == 150
    assert a.accrued("ghost") == 0 and a.accrued("") == 0


def test_accrue_idempotent_per_entry_id():
    s = _store()
    a = _arr(s)
    a.accrue("acme", 100, entry_id="r:1", issued_at=1.0)
    a.accrue("acme", 100, entry_id="r:1", issued_at=1.0)   # replay same entry_id -> no double-count
    assert a.accrued("acme") == 100


def test_reverse_lowers_arrears_and_clamps_nonnegative():
    s = _store()
    a = _arr(s)
    a.accrue("acme", 100, entry_id="r:1", issued_at=1.0)
    a.reverse("acme", 40, entry_id="s:1", issued_at=2.0)
    assert a.accrued("acme") == 60
    a.reverse("acme", 10_000, entry_id="s:2", issued_at=3.0)   # over-reverse -> clamped >= 0 (inert)
    assert a.accrued("acme") == 0


def test_reverse_idempotent_per_entry_id():
    s = _store()
    a = _arr(s)
    a.accrue("acme", 100, entry_id="r:1", issued_at=1.0)
    a.reverse("acme", 30, entry_id="s:1", issued_at=2.0)
    a.reverse("acme", 30, entry_id="s:1", issued_at=2.0)   # replay -> no double-reverse
    assert a.accrued("acme") == 70


def test_was_accrued_detects_a_postpaid_draw():
    s = _store()
    a = _arr(s)
    a.accrue("acme", 100, entry_id="reserve-postpaid:slug:n1", issued_at=1.0)
    assert a.was_accrued("acme", "reserve-postpaid:slug:n1") is True
    assert a.was_accrued("acme", "nope") is False
    assert a.was_accrued("ghost", "reserve-postpaid:slug:n1") is False
    assert a.was_accrued("", "x") is False
    # a reversal's entry_id is a CREDIT, not a debit -> was_accrued discriminates (returns False for it)
    a.reverse("acme", 10, entry_id="settle-postpaid:slug:n1", issued_at=2.0)
    assert a.was_accrued("acme", "settle-postpaid:slug:n1") is False


def test_forged_arrears_records_are_inert():
    s = _store()
    a = _arr(s)
    a.accrue("acme", 100, entry_id="r:1", issued_at=1.0)
    # a forged DEBIT (attacker key) must not inflate arrears; a forged CREDIT must not deflate it.
    dcore = {"signal": POSTPAID_DEBIT_SIGNAL, "org_id": "acme", "entry_id": "forge-d", "credits": 1000,
             "engagement_id": "", "issued_at": 2.0}
    ccore = {"signal": POSTPAID_CREDIT_SIGNAL, "org_id": "acme", "entry_id": "forge-c", "credits": 1000,
             "issued_at": 3.0}
    s.append(kind="event", source="governor", actor="WARDEN", payload={**signed_payload(dcore, ATTACKER)})
    s.append(kind="event", source="governor", actor="WARDEN", payload={**signed_payload(ccore, ATTACKER)})
    assert a.accrued("acme") == 100 and a.was_accrued("acme", "forge-d") is False


def test_tenant_isolation():
    s = _store()
    a = _arr(s)
    a.accrue("org_a", 100, entry_id="a:1", issued_at=1.0)
    a.accrue("org_b", 20, entry_id="b:1", issued_at=1.0)
    assert a.accrued("org_a") == 100 and a.accrued("org_b") == 20


def test_accrue_requires_owner_key_and_validates_credits():
    s = _store()
    import pytest
    a0 = PostpaidArrearsLedger(s, owner_key=OWNER, trusted_pubkey=OP)
    a0.owner_key = None            # null AFTER construction (constructor coerces None -> owner_keypair())
    with pytest.raises(ValueError):
        a0.accrue("acme", 10, entry_id="x", issued_at=1.0)
    with pytest.raises(ValueError):
        _arr(s).accrue("acme", 0, entry_id="x", issued_at=1.0)       # credits clamped > 0 at binding
    with pytest.raises(ValueError):
        _arr(s).accrue("acme", -5, entry_id="x", issued_at=1.0)
