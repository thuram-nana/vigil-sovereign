"""Behavioral tests for the SaaS per-tenant invoice / billing-history ledger (`governor/invoices.py`).

Load-bearing invariants (a false-green here would let a forged line appear in a tenant's billing history, let
a tampered amount/plan be billed, let a replayed webhook duplicate a charge, or leak another tenant's invoices):
  * each invoice is owner-signed + verified — a forged/attacker-signed line is INERT (never in the history);
  * `amount_minor`/`price_id`/`currency`/`credits`/`period_*` are INSIDE the signed core — a tampered money
    amount or plan breaks the signature and is dropped (the money-doctrine integrity guard);
  * idempotent per (org_id, invoice_id) — a replayed webhook (same event_id) folds ONCE (no duplicate charge);
  * tenants are isolated — `invoices(org)` returns ONLY that org's lines (the IDOR class, defended at the read);
  * bad kind / negative amount / empty-or-oversized invoice_id / bad currency refused fail-closed at binding.
The prune-survival + anti-replay-across-a-prune properties live in test_snapshot_fold_invoices.py.
"""
from __future__ import annotations

import itertools
import tempfile

import pytest

from sigil.governor.authn import signed_payload
from sigil.governor.invoices import INVOICE_SIGNAL, InvoiceRegistry, _INVOICE_CORE
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
    return InvoiceRegistry(store, owner_key=OWNER, trusted_pubkey=OP)


def _forge(store, core_overrides, *, signer):
    """Append a `governor.invoice` record signed by `signer` with the given core fields (fills defaults)."""
    core = {"signal": INVOICE_SIGNAL, "org_id": "acme", "invoice_id": "x", "kind": "topup", "price_id": "p",
            "amount_minor": 100, "currency": "USD", "credits": 10, "period_start": 0.0, "period_end": 0.0,
            "issued_at": 1.0}
    core.update(core_overrides)
    return store.append(kind="event", source="governor", actor="WARDEN",
                        payload={**signed_payload(core, signer)})


# --- record / read roundtrip -----------------------------------------------------
def test_record_then_read():
    s = _store()
    r = _reg(s)
    r.record("acme", invoice_id="evt_1", kind="subscription", price_id="pro", amount_minor=4900,
             currency="usd", credits=1000, period_start=100.0, period_end=2000.0, issued_at=_issue())
    invs = r.invoices("acme")
    assert len(invs) == 1
    inv = invs[0]
    assert (inv.invoice_id, inv.kind, inv.price_id, inv.amount_minor) == ("evt_1", "subscription", "pro", 4900)
    assert inv.currency == "USD"                     # normalized uppercase
    assert (inv.credits, inv.period_start, inv.period_end) == (1000, 100.0, 2000.0)


def test_newest_first_ordering():
    s = _store()
    r = _reg(s)
    r.record("acme", invoice_id="a", kind="topup", price_id="t", amount_minor=1, credits=1, issued_at=100.0)
    r.record("acme", invoice_id="b", kind="topup", price_id="t", amount_minor=1, credits=1, issued_at=300.0)
    r.record("acme", invoice_id="c", kind="topup", price_id="t", amount_minor=1, credits=1, issued_at=200.0)
    assert [i.invoice_id for i in r.invoices("acme")] == ["b", "c", "a"]   # by issued_at DESC


# --- idempotency (a replayed webhook must not duplicate a charge) ----------------
def test_idempotent_replay():
    s = _store()
    r = _reg(s)
    seq = r.record("acme", invoice_id="evt_1", kind="topup", price_id="t", amount_minor=999, credits=500,
                   issued_at=_issue())
    captured = s.get(seq).payload
    s.append(kind="event", source="governor", actor="WARDEN", payload=captured)   # replay verbatim
    invs = r.invoices("acme")
    assert len(invs) == 1, "a replayed invoice (same invoice_id) must fold once — no duplicate charge"
    assert invs[0].amount_minor == 999


# --- forgery / tamper (unsigned/attacker-signed/tampered lines are inert) --------
def test_forged_invoice_ignored():
    s = _store()
    r = _reg(s)
    r.record("acme", invoice_id="real", kind="topup", price_id="t", amount_minor=100, credits=10,
             issued_at=_issue())
    _forge(s, {"invoice_id": "forged", "amount_minor": 999999}, signer=ATTACKER)   # attacker, not owner
    invs = r.invoices("acme")
    assert [i.invoice_id for i in invs] == ["real"], "an attacker-signed invoice must not appear in the history"


def test_tampered_amount_breaks_signature_and_is_dropped():
    # the money amount is INSIDE the signed core: flipping it after signing must drop the record (money doctrine).
    s = _store()
    r = _reg(s)
    seq = r.record("acme", invoice_id="evt_1", kind="subscription", price_id="pro", amount_minor=4900,
                   currency="USD", credits=1000, issued_at=_issue())
    p = dict(s.get(seq).payload)
    p["amount_minor"] = 1                               # tamper the billed amount AFTER signing
    s2 = _store()
    s2.append(kind="event", source="governor", actor="WARDEN", payload=p)
    assert _reg(s2).invoices("acme") == [], "a record whose signed amount was tampered must not verify"


# --- tenant isolation (the IDOR class) -------------------------------------------
def test_tenants_are_isolated():
    s = _store()
    r = _reg(s)
    r.record("acme", invoice_id="a1", kind="topup", price_id="t", amount_minor=100, credits=10, issued_at=_issue())
    r.record("beta", invoice_id="b1", kind="topup", price_id="t", amount_minor=200, credits=20, issued_at=_issue())
    assert [i.invoice_id for i in r.invoices("acme")] == ["a1"]
    assert [i.invoice_id for i in r.invoices("beta")] == ["b1"]
    assert r.invoices("acme")[0].org_id == "acme"
    assert r.invoices("zzz") == []                      # unknown org reads empty (fail-closed)
    assert {i.org_id for i in r.all_invoices()} == {"acme", "beta"}


# --- binding-time validation (fail-closed) ---------------------------------------
def test_bad_kind_refused():
    s = _store()
    r = _reg(s)
    with pytest.raises(ValueError):
        r.record("acme", invoice_id="x", kind="refund", price_id="t", amount_minor=1, issued_at=_issue())


def test_negative_amount_or_credits_refused():
    s = _store()
    r = _reg(s)
    with pytest.raises(ValueError):
        r.record("acme", invoice_id="x", kind="topup", price_id="t", amount_minor=-1, issued_at=_issue())
    with pytest.raises(ValueError):
        r.record("acme", invoice_id="x", kind="topup", price_id="t", amount_minor=1, credits=-5, issued_at=_issue())


def test_bad_invoice_id_and_currency_refused():
    s = _store()
    r = _reg(s)
    for bad_id in ("", "   ", "x" * 129, "has\nctrl"):
        with pytest.raises(ValueError):
            r.record("acme", invoice_id=bad_id, kind="topup", price_id="t", amount_minor=1, issued_at=_issue())
    with pytest.raises(ValueError):
        r.record("acme", invoice_id="ok", kind="topup", price_id="t", amount_minor=1, currency="US$",
                 issued_at=_issue())


def test_bad_org_id_refused():
    s = _store()
    r = _reg(s)
    with pytest.raises(ValueError):
        r.record("has spaces", invoice_id="x", kind="topup", price_id="t", amount_minor=1, issued_at=_issue())


def test_zero_amount_is_allowed():
    # unlike a wallet grant (> 0), an invoice may carry amount 0 (e.g. no catalog price configured yet).
    s = _store()
    r = _reg(s)
    r.record("acme", invoice_id="z", kind="topup", price_id="t", amount_minor=0, currency="", credits=0,
             issued_at=_issue())
    assert r.invoices("acme")[0].amount_minor == 0


# --- has_purchased_credits: a PAID top-up, never a grant ---------------------------------
def test_has_purchased_credits_needs_a_signed_topup_with_credits():
    s = _store()
    r = _reg(s)
    assert r.has_purchased_credits("acme") is False                       # no history at all
    for bad in ("", None, 7, b"acme"):
        assert r.has_purchased_credits(bad) is False                      # fail-closed, never raises
    r.record("acme", invoice_id="sub_1", kind="subscription", price_id="pro", amount_minor=4900, currency="USD",
             credits=6000, period_start=1.0, period_end=2.0, issued_at=_issue())
    r.record("acme", invoice_id="pp_1", kind="postpaid", price_id="pp", amount_minor=100, currency="USD",
             credits=0, issued_at=_issue())
    r.record("acme", invoice_id="pay_1", kind="payment", price_id="pp", amount_minor=100, currency="USD",
             credits=0, issued_at=_issue())
    r.record("acme", invoice_id="tu_0", kind="topup", price_id="t", amount_minor=500, currency="USD",
             credits=0, issued_at=_issue())                               # a top-up line that granted nothing
    assert r.has_purchased_credits("acme") is False, "only a top-up that granted credits is a credit purchase"
    _forge(s, {"invoice_id": "forged", "kind": "topup", "credits": 500}, signer=ATTACKER)
    assert r.has_purchased_credits("acme") is False, "a forged top-up line is inert"
    r.record("acme", invoice_id="tu_1", kind="topup", price_id="t", amount_minor=0, currency="",
             credits=500, issued_at=_issue())                             # catalog-unpriced: still a purchase
    assert r.has_purchased_credits("acme") is True


def test_has_purchased_credits_is_tenant_scoped():
    s = _store()
    r = _reg(s)
    r.record("acme", invoice_id="tu_1", kind="topup", price_id="t", amount_minor=500, currency="USD",
             credits=500, issued_at=_issue())
    assert r.has_purchased_credits("acme") is True
    for other in ("globex", "acm", "acme2", "ACME", " acme"):
        assert r.has_purchased_credits(other) is False, f"{other!r} must not see acme's purchase"


def test_has_purchased_credits_reads_the_same_through_the_fold_cache(monkeypatch):
    s = _store()
    r = _reg(s)
    r.record("acme", invoice_id="tu_1", kind="topup", price_id="t", amount_minor=500, currency="USD",
             credits=500, issued_at=_issue())
    r.record("globex", invoice_id="sub_1", kind="subscription", price_id="pro", amount_minor=4900,
             currency="USD", credits=6000, period_start=1.0, period_end=2.0, issued_at=_issue())
    want = {o: r.has_purchased_credits(o) for o in ("acme", "globex", "initech")}
    assert want == {"acme": True, "globex": False, "initech": False}
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "1")
    cached = _reg(s)
    assert {o: cached.has_purchased_credits(o) for o in want} == want
    cached.record("initech", invoice_id="tu_2", kind="topup", price_id="t", amount_minor=500, currency="USD",
                  credits=100, issued_at=_issue())
    assert cached.has_purchased_credits("initech") is True                # the cache picks up a new line


def test_a_str_subclass_cannot_widen_the_tenant_match(monkeypatch):
    class Sly(str):
        __slots__ = ()

        def __eq__(self, other):                    # matches every tenant on a naive `==` filter
            return True

        __hash__ = str.__hash__

    s = _store()
    r = _reg(s)
    r.record("acme", invoice_id="tu_1", kind="topup", price_id="t", amount_minor=500, currency="USD",
             credits=500, issued_at=_issue())
    assert r.invoices(Sly("zzz")) == [] and r.has_purchased_credits(Sly("zzz")) is False
    assert r.has_purchased_credits(Sly("acme")) is True                    # a well-behaved value still works
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "1")
    assert _reg(s).has_purchased_credits(Sly("zzz")) is False
