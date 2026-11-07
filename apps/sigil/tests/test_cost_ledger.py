"""Behavioral tests for the EC-4 per-tenant TOKEN-COST ENVELOPE ledger (`governor/cost_ledger.py`).

Load-bearing invariants (a false-green would let a forged/replayed record charge a tenant, let a forged
over-report draw the pool past the reserved envelope, or cross a tenant's cost onto another):
  * reserve + settle are BOTH owner-signed; an unsigned/forged record of either kind is inert in the fold;
  * the ledger is ADDITIVE + idempotent per (signal, org_id, entry_id); a replay counts once;
  * settle CLAMPS the actual tokens to the reserved envelope (a forged over-report can never charge past it);
  * tokens are clamped >= 0 at the fold (a forged NEGATIVE record cannot refund cost / draw the pool back);
  * in_flight = Σ reserved-but-unsettled (the pending pool draw); committed = Σ settled actual;
  * tenants are isolated (keyed org_id == tenant_id) — a tenant can never be charged another's cost.
The prune-survival + build==scan properties live in test_snapshot_fold_cost_ledger.py.
"""
from __future__ import annotations

import itertools
import tempfile

import pytest

from sigil.governor.authn import signed_payload
from sigil.governor.cost_ledger import (COST_RESERVE_SIGNAL, COST_SETTLE_SIGNAL, CostEnvelopeLedger, TenantCost,
                                        _as_tokens)
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


def _led(store):
    return CostEnvelopeLedger(store, owner_key=OWNER, trusted_pubkey=OP)


# ---- reserve/settle + the derived reads --------------------------------------------------------------
def test_reserve_then_settle_reads():
    s = _store()
    L = _led(s)
    L.reserve("acme", 1000, entry_id="reserve-cost:acme:n1", issued_at=_issue())
    assert L.reserved_total("acme") == 1000
    assert L.in_flight_envelope("acme") == 1000          # reserved, not yet settled
    assert L.committed_cost("acme") == 0
    L.settle("acme", 700, entry_id="settle-cost:acme:n1", issued_at=_issue())
    assert L.committed_cost("acme") == 700
    assert L.in_flight_envelope("acme") == 0             # settle landed -> no longer in-flight
    assert L.reserved_total("acme") == 1000              # reserved is lifetime (unchanged by settle)
    tc = L.tenant_cost("acme")
    assert tc == TenantCost(org_id="acme", committed_tokens=700, reserved_tokens=1000, in_flight_tokens=0)


def test_absent_reads_all_zero():
    s = _store()
    L = _led(s)
    assert L.committed_cost("ghost") == 0 and L.reserved_total("ghost") == 0
    assert L.in_flight_envelope("ghost") == 0 and L.was_reserved("ghost", "x") is False
    assert L.committed_cost("") == 0 and L.tenant_cost("").org_id == ""
    assert L.tenant_costs() == []


def test_settle_clamps_actual_to_the_reserved_envelope():
    # a run (or a forged completion signal) reporting MORE tokens than reserved can never charge past the cap.
    s = _store()
    L = _led(s)
    L.reserve("acme", 1000, entry_id="reserve-cost:acme:n1", issued_at=_issue())
    L.settle("acme", 5000, entry_id="settle-cost:acme:n1", reserved_cap=1000, issued_at=_issue())
    assert L.committed_cost("acme") == 1000, "settle clamped to the reserved envelope"


def test_settle_at_zero_is_allowed_reserve_at_zero_is_refused():
    s = _store()
    L = _led(s)
    with pytest.raises(ValueError):
        L.reserve("acme", 0, entry_id="reserve-cost:acme:n0", issued_at=_issue())  # a 0 reserve is meaningless
    L.reserve("acme", 1000, entry_id="reserve-cost:acme:n1", issued_at=_issue())
    L.settle("acme", 0, entry_id="settle-cost:acme:n1", issued_at=_issue())        # a fully cache-served run: 0 ok
    assert L.committed_cost("acme") == 0 and L.in_flight_envelope("acme") == 0


def test_negative_and_junk_tokens_refused_at_bind():
    s = _store()
    L = _led(s)
    for bad in (-1, -1000, 1.5, "10", True, None):
        with pytest.raises(ValueError):
            L.reserve("acme", bad, entry_id="reserve-cost:acme:x", issued_at=_issue())  # type: ignore[arg-type]


def test_as_tokens_clamps_negatives_and_junk():
    # the fold's per-record reader: a NEGATIVE value never CANCELS real cost (fail-open refund); junk -> 0.
    assert _as_tokens(-5) == 0 and _as_tokens(0) == 0 and _as_tokens(5) == 5
    assert _as_tokens("nan") == 0 and _as_tokens(None) == 0 and _as_tokens(True) == 0
    assert _as_tokens(float("inf")) == 0 and _as_tokens(float("nan")) == 0   # OverflowError / ValueError -> 0


def test_idempotent_replay_counts_once():
    s = _store()
    L = _led(s)
    seq = L.reserve("acme", 1000, entry_id="reserve-cost:acme:n1", issued_at=_issue())
    captured = s.get(seq).payload
    s.append(kind="event", source="governor", actor="WARDEN", payload=captured)   # verbatim replay
    s.append(kind="event", source="governor", actor="WARDEN", payload=captured)
    assert L.reserved_total("acme") == 1000, "a replayed reserve is idempotent per (signal, org, entry_id)"
    assert L.in_flight_envelope("acme") == 1000


def test_forged_records_are_inert():
    s = _store()
    L = _led(s)
    L.reserve("acme", 1000, entry_id="reserve-cost:acme:n1", issued_at=1.0)
    L.settle("acme", 700, entry_id="settle-cost:acme:n1", issued_at=2.0)
    # a forged RESERVE (attacker key) must not inflate the pool draw; a forged SETTLE must not add committed cost.
    rcore = {"signal": COST_RESERVE_SIGNAL, "org_id": "acme", "entry_id": "reserve-cost:acme:forge",
             "tokens": 999999, "engagement_id": "", "issued_at": 3.0}
    score = {"signal": COST_SETTLE_SIGNAL, "org_id": "acme", "entry_id": "settle-cost:acme:forge",
             "tokens": 999999, "engagement_id": "", "issued_at": 4.0}
    s.append(kind="event", source="governor", actor="WARDEN", payload={**signed_payload(rcore, ATTACKER)})
    s.append(kind="event", source="governor", actor="WARDEN", payload={**signed_payload(score, ATTACKER)})
    assert L.reserved_total("acme") == 1000 and L.committed_cost("acme") == 700
    assert L.in_flight_envelope("acme") == 0        # the forged reserve never entered the in-flight scan
    assert L.was_reserved("acme", "reserve-cost:acme:forge") is False


def test_tampered_amount_breaks_the_signature():
    # a genuine owner-signed reserve whose `tokens` is edited after signing is inert (the amount is in the core).
    s = _store()
    L = _led(s)
    seq = L.reserve("acme", 1000, entry_id="reserve-cost:acme:n1", issued_at=1.0)
    tampered = dict(s.get(seq).payload)
    tampered["tokens"] = 999999
    s.append(kind="event", source="governor", actor="WARDEN", payload=tampered)
    assert L.reserved_total("acme") == 1000, "the tampered copy fails verify; only the genuine 1000 counts"


def test_tenant_isolation():
    s = _store()
    L = _led(s)
    L.reserve("org_a", 1000, entry_id="reserve-cost:org_a:n1", issued_at=_issue())
    L.settle("org_a", 800, entry_id="settle-cost:org_a:n1", issued_at=_issue())
    L.reserve("org_b", 50, entry_id="reserve-cost:org_b:n1", issued_at=_issue())
    assert L.committed_cost("org_a") == 800 and L.committed_cost("org_b") == 0
    assert L.in_flight_envelope("org_b") == 50 and L.in_flight_envelope("org_a") == 0
    costs = {c.org_id: c for c in L.tenant_costs()}
    assert set(costs) == {"org_a", "org_b"}
    assert costs["org_a"].committed_tokens == 800 and costs["org_b"].reserved_tokens == 50


def test_was_reserved_discriminator():
    s = _store()
    L = _led(s)
    L.reserve("acme", 1000, entry_id="reserve-cost:acme:n1", issued_at=_issue())
    assert L.was_reserved("acme", "reserve-cost:acme:n1") is True
    assert L.was_reserved("acme", "reserve-cost:acme:n2") is False      # never reserved
    assert L.was_reserved("acme", "") is False and L.was_reserved("", "x") is False


def test_reserve_and_settle_require_the_owner_key():
    s = _store()
    L = CostEnvelopeLedger(s, owner_key=OWNER, trusted_pubkey=OP)
    L.owner_key = None            # null AFTER construction (constructor coerces None -> owner_keypair())
    with pytest.raises(ValueError):
        L.reserve("acme", 10, entry_id="reserve-cost:acme:n1", issued_at=1.0)
    with pytest.raises(ValueError):
        L.settle("acme", 10, entry_id="settle-cost:acme:n1", issued_at=1.0)


def test_entry_id_validation():
    s = _store()
    L = _led(s)
    for bad in ("", "   ", "x" * 129, "has\x00null", "has\x7fdel"):
        with pytest.raises(ValueError):
            L.reserve("acme", 10, entry_id=bad, issued_at=1.0)


def test_reserve_settle_enforce_the_entry_id_prefix():
    # RED-PEN LOW cluster: the prefix-AGNOSTIC fold (reserved_total/committed/was_reserved sum every record) and
    # the prefix-GATED in-flight pairing (keys on the {slug}:{nonce} suffix after the prefix) must agree on what a
    # reservation is — so a reserve MUST be under reserve-cost: and a settle under settle-cost:, enforced at bind.
    s = _store()
    L = _led(s)
    with pytest.raises(ValueError):
        L.reserve("acme", 10, entry_id="acme:n1", issued_at=1.0)                  # no reserve-cost: prefix
    with pytest.raises(ValueError):
        L.reserve("acme", 10, entry_id="settle-cost:acme:n1", issued_at=1.0)      # wrong prefix on a reserve
    with pytest.raises(ValueError):
        L.settle("acme", 10, entry_id="acme:n1", issued_at=1.0)                   # no settle-cost: prefix
    with pytest.raises(ValueError):
        L.settle("acme", 10, entry_id="reserve-cost:acme:n1", issued_at=1.0)      # wrong prefix on a settle
    # the correct prefixes are accepted and pair across the fold + in-flight readers consistently
    L.reserve("acme", 10, entry_id="reserve-cost:acme:n1", issued_at=1.0)
    L.settle("acme", 10, entry_id="settle-cost:acme:n1", issued_at=2.0)
    assert L.committed_cost("acme") == 10 and L.in_flight_envelope("acme") == 0


def test_in_flight_pairs_by_suffix_not_raw_entry_id():
    # the in-flight scan pairs a reserve to its settle by the {slug}:{nonce} SUFFIX after the prefix — a settle for
    # a DIFFERENT suffix must not clear an unrelated reserve.
    s = _store()
    L = _led(s)
    L.reserve("acme", 1000, entry_id="reserve-cost:acme:n1", issued_at=_issue())
    L.reserve("acme", 500, entry_id="reserve-cost:acme:n2", issued_at=_issue())
    L.settle("acme", 700, entry_id="settle-cost:acme:n1", issued_at=_issue())     # settles n1 only
    assert L.in_flight_envelope("acme") == 500, "only n2 remains in-flight"
    assert L.committed_cost("acme") == 700
