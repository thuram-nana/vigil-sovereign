"""Red-Pen R2 — the per-(org, repo, calendar-month) spend ledger + the refuse-new-at-limit gate (decision O-2).

Invariants pinned here:
  * the monthly fold sums owner-signed charges for (org, repo) in the calendar month, idempotent per nonce;
  * the enqueue gate refuses NEW reviews once charged >= limit (the boundary REACHED refuses) and flags notify;
  * a limit of 0 (or unset) means no limit;
  * the limit re-arms next calendar month (a new month starts at 0);
  * a forged (non-owner) charge is inert — it can neither push a repo over its limit nor under-report.
"""
from __future__ import annotations

import itertools
import tempfile
from datetime import datetime, timezone

import pytest

from sigil.governor.redpen_spend import RedPenSpendLedger, month_key
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64
ATTACKER = generate_keypair()
_c = itertools.count(1)
REPO = "github.com/acme/widgets"

# two timestamps in DIFFERENT calendar months (UTC)
JAN = datetime(2026, 1, 15, tzinfo=timezone.utc).timestamp()
FEB = datetime(2026, 2, 3, tzinfo=timezone.utc).timestamp()
JAN_END = datetime(2026, 1, 31, 23, 59, tzinfo=timezone.utc).timestamp()


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _led(store, key=OWNER, pub=OP):
    return RedPenSpendLedger(store, owner_key=key, trusted_pubkey=pub)


def _n() -> str:
    return f"rev{next(_c)}"


def test_the_monthly_fold_sums_owner_signed_charges():
    s = _store()
    led = _led(s)
    led.record_charge("acme", REPO, 10, nonce=_n(), now=JAN)
    led.record_charge("acme", REPO, 7, nonce=_n(), now=JAN_END)
    assert led.charged("acme", REPO, now=JAN) == 17
    # a different repo / org is isolated
    led.record_charge("acme", "github.com/acme/other", 100, nonce=_n(), now=JAN)
    assert led.charged("acme", REPO, now=JAN) == 17


def test_the_fold_is_idempotent_per_nonce():
    s = _store()
    led = _led(s)
    non = _n()
    led.record_charge("acme", REPO, 10, nonce=non, now=JAN)
    led.record_charge("acme", REPO, 10, nonce=non, now=JAN)     # a retried settle re-appends the SAME nonce
    assert led.charged("acme", REPO, now=JAN) == 10             # counted once


def test_the_gate_refuses_new_reviews_at_the_limit_and_flags_notify():
    s = _store()
    led = _led(s)
    led.record_charge("acme", REPO, 49, nonce=_n(), now=JAN)
    assert led.review_refusal("acme", REPO, monthly_limit_credits=50, now=JAN) is None   # 49 < 50 -> allow
    led.record_charge("acme", REPO, 1, nonce=_n(), now=JAN)                              # now 50
    refusal = led.review_refusal("acme", REPO, monthly_limit_credits=50, now=JAN)
    assert refusal is not None and refusal["refused"] and refusal["notify"] is True
    assert refusal["charged"] == 50 and refusal["limit"] == 50


def test_the_boundary_is_exact_reaching_the_limit_refuses():
    s = _store()
    led = _led(s)
    led.record_charge("acme", REPO, 100, nonce=_n(), now=JAN)
    assert led.review_refusal("acme", REPO, monthly_limit_credits=100, now=JAN) is not None   # == refuses
    assert led.review_refusal("acme", REPO, monthly_limit_credits=101, now=JAN) is None       # one more allowed


def test_a_zero_or_unset_limit_means_no_limit():
    s = _store()
    led = _led(s)
    led.record_charge("acme", REPO, 10_000, nonce=_n(), now=JAN)
    assert led.review_refusal("acme", REPO, monthly_limit_credits=0, now=JAN) is None


def test_the_limit_re_arms_next_calendar_month():
    s = _store()
    led = _led(s)
    led.record_charge("acme", REPO, 50, nonce=_n(), now=JAN)
    assert led.review_refusal("acme", REPO, monthly_limit_credits=50, now=JAN) is not None   # January is full
    assert led.charged("acme", REPO, now=FEB) == 0                                           # February starts fresh
    assert led.review_refusal("acme", REPO, monthly_limit_credits=50, now=FEB) is None
    assert month_key(JAN) == "2026-01" and month_key(FEB) == "2026-02"


def test_a_forged_charge_is_inert():
    s = _store()
    # a charge signed by a NON-owner (trusted root = owner) must not count toward the limit
    RedPenSpendLedger(s, owner_key=ATTACKER, trusted_pubkey=OP).record_charge("acme", REPO, 999, nonce=_n(), now=JAN)
    assert _led(s).charged("acme", REPO, now=JAN) == 0


def test_record_charge_requires_the_owner_key_and_validates():
    s = _store()
    with pytest.raises(ValueError, match="owner signing key"):
        RedPenSpendLedger(s, owner_key=None, trusted_pubkey=OP).record_charge("acme", REPO, 1, nonce=_n(), now=JAN)
    with pytest.raises(ValueError):
        _led(s).record_charge("acme", REPO, -1, nonce=_n(), now=JAN)
    with pytest.raises(ValueError):
        _led(s).record_charge("acme", REPO, 1, nonce="bad:nonce", now=JAN)
