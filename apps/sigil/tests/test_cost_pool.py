"""EC-5 — behavioral tests for the GLOBAL cost POOL meter + graduated kill-switch (`governor/cost_pool.py`)
and its launch-gate wiring (`ui/launch_gate.py`).

Load-bearing invariants (a false-green would let an unset pool meter/charge when it must be byte-identical,
let an ARMED pool that cannot measure keep admitting, let a forged cost record move the pool, or let a new
launch draw past the owner capacity):
  * DEFAULT-OFF BYTE-IDENTICAL: an unbounded pool short-circuits to NORMAL / full admit WITHOUT folding, and
    the gate writes NO cost record with the write flag off — spine + result identical to pre-EC-5;
  * FAIL-CLOSED SAFE DIRECTION: an ARMED pool whose meter raises postures REFUSE_NEW (never NORMAL);
  * MONOTONE GRADUATION: posture bands are totally ordered and the admitted envelope is non-increasing in the
    used-fraction, floored >= 1, never > the request;
  * global_position() is a SINGLE-PASS equivalence-oracle match for summing tenant_costs(); a forged/unsigned
    cost record is inert in it (verify_signed inheritance);
  * the gate's reserve/settle cost pair is written ONLY when cost_ledger_write_enabled() and is idempotent;
  * the pool-REFUSE conjunct refuses a NEW reserve when armed+over-threshold, and in-flight launches still
    settle and FREE the pool (auto-relax).
"""
from __future__ import annotations

import itertools
import tempfile

import pytest

from sigil.governor.cost_ledger import (COST_RESERVE_SIGNAL, COST_SETTLE_SIGNAL, CostEnvelopeLedger,
                                        GlobalCostPosition)
from sigil.governor.cost_pool import GlobalCostPool, PoolBands, PoolPosture
from sigil.governor.authn import signed_payload
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


class _FakeLedger:
    """A cost ledger stand-in whose global draw is whatever `used` is set to (committed+in_flight)."""
    def __init__(self, used: int):
        self._used = used

    def global_position(self) -> GlobalCostPosition:
        return GlobalCostPosition(committed_tokens=self._used, in_flight_tokens=0)


class _RaisingLedger:
    """A cost ledger whose fold RAISES — the corrupt/unmeasurable store the fail-closed direction guards."""
    def global_position(self) -> GlobalCostPosition:
        raise RuntimeError("spine read blew up")


# ======================================================================================================
# 1) DEFAULT-OFF unbounded short-circuit — NORMAL + full admit, NO fold (proven via a RAISING ledger)
# ======================================================================================================
def test_default_off_unbounded_short_circuits_without_folding():
    # An UNBOUNDED pool (budget None) must NOT fold the ledger. We prove it by giving it a ledger that RAISES
    # on any fold: a correct short-circuit returns NORMAL / full admit; a mutant that folds-when-off would hit
    # the raising ledger and (fail-closed) return REFUSE_NEW instead.
    pool = GlobalCostPool(_RaisingLedger(), budget_tokens=None)
    assert pool.is_armed() is False
    assert pool.posture() is PoolPosture.NORMAL
    admitted, posture, _reason = pool.admit(100)
    assert admitted == 100 and posture is PoolPosture.NORMAL      # FULL admit, before any fold
    assert pool.gate_refusal() is None                           # byte-identical no-op in the gate


@pytest.mark.parametrize("budget", [None, 0, -5, "", "x"])
def test_budget_none_zero_or_junk_is_unbounded(budget):
    # 0 / negative / non-numeric budget all collapse to UNBOUNDED (mirrors config.global_pool_tokens).
    pool = GlobalCostPool(_RaisingLedger(), budget_tokens=budget)
    assert pool.is_armed() is False and pool.posture() is PoolPosture.NORMAL
    assert pool.admit(42)[0] == 42


# ======================================================================================================
# 2) FAIL-CLOSED — an ARMED pool whose meter RAISES postures REFUSE_NEW (never NORMAL)
# ======================================================================================================
def test_fail_closed_refuse_new_on_armed_read_error():
    pool = GlobalCostPool(_RaisingLedger(), budget_tokens=1000)
    assert pool.is_armed() is True
    assert pool.posture() is PoolPosture.REFUSE_NEW             # NOT NORMAL — the access-reducing direction
    admitted, posture, _r = pool.admit(100)
    assert admitted == 0 and posture is PoolPosture.REFUSE_NEW   # admit NOTHING when it cannot measure
    assert pool.gate_refusal() is not None                      # and the gate conjunct refuses


def test_fail_closed_position_reports_refuse_new():
    pool = GlobalCostPool(_RaisingLedger(), budget_tokens=1000)
    pos = pool.position()
    assert pos.posture is PoolPosture.REFUSE_NEW and pos.pool_tokens == 1000


# ======================================================================================================
# 3) GRADUATION bands + the >= boundary (the band comparison is load-bearing)
# ======================================================================================================
# budget 1000; defaults throttle 0.75, degrade 0.85, refuse 0.95, hard_stop 1.0
@pytest.mark.parametrize("used,expected", [
    (0, PoolPosture.NORMAL),
    (740, PoolPosture.NORMAL),
    (750, PoolPosture.THROTTLE),       # >= 0.75
    (849, PoolPosture.THROTTLE),
    (850, PoolPosture.DEGRADE),        # >= 0.85
    (949, PoolPosture.DEGRADE),
    (950, PoolPosture.REFUSE_NEW),     # >= 0.95
    (999, PoolPosture.REFUSE_NEW),
    (1000, PoolPosture.HARD_STOP),     # >= 1.0
    (5000, PoolPosture.HARD_STOP),
])
def test_graduation_bands(used, expected):
    pool = GlobalCostPool(_FakeLedger(used), budget_tokens=1000)
    assert pool.posture() is expected


def test_band_boundary_is_inclusive_ge_not_strict_gt():
    # The band threshold is `>=` (a used-fraction that REACHES a band engages it). 950/1000 == 0.95 EXACTLY
    # must be REFUSE_NEW; one token less is DEGRADE. A mutant using `>` would push the boundary down a band.
    assert GlobalCostPool(_FakeLedger(950), budget_tokens=1000).posture() is PoolPosture.REFUSE_NEW
    assert GlobalCostPool(_FakeLedger(949), budget_tokens=1000).posture() is PoolPosture.DEGRADE
    assert GlobalCostPool(_FakeLedger(1000), budget_tokens=1000).posture() is PoolPosture.HARD_STOP
    assert GlobalCostPool(_FakeLedger(999), budget_tokens=1000).posture() is PoolPosture.REFUSE_NEW


# ======================================================================================================
# 4) admit() graduation — monotone non-increasing, floor >= 1, never > requested, admit 0 at the top
# ======================================================================================================
def test_admit_envelope_is_monotone_non_increasing_and_bounded():
    req = 100
    useds = [0, 740, 750, 850, 950, 1000]          # ascending fraction across every band
    admits = [GlobalCostPool(_FakeLedger(u), budget_tokens=1000).admit(req)[0] for u in useds]
    assert admits == [100, 100, 100, 50, 0, 0]      # NORMAL/THROTTLE full, DEGRADE half, REFUSE/HARD_STOP 0
    for a, b in zip(admits, admits[1:]):
        assert b <= a, "admitted envelope must be NON-INCREASING in the used-fraction"
    assert all(a <= req for a in admits), "admitted must NEVER exceed the request"


def test_admit_degrade_floors_at_one_and_never_exceeds_request():
    # DEGRADE shrinks by the factor (0.5) but floors at >= 1 (a lease requires units_reserved >= 1), and a
    # 1-token request still admits exactly 1 (floor), never 0 and never > the request.
    degrade = GlobalCostPool(_FakeLedger(900), budget_tokens=1000)   # 0.90 -> DEGRADE
    admitted, posture, _r = degrade.admit(1)
    assert posture is PoolPosture.DEGRADE and admitted == 1
    admitted2, _p, _r2 = degrade.admit(3)
    assert admitted2 == 1 and admitted2 <= 3        # int(3*0.5)=1


def test_admit_refuse_and_hard_stop_admit_zero():
    assert GlobalCostPool(_FakeLedger(960), budget_tokens=1000).admit(100)[0] == 0   # REFUSE_NEW
    assert GlobalCostPool(_FakeLedger(2000), budget_tokens=1000).admit(100)[0] == 0  # HARD_STOP


def test_posture_total_order_matches_enum_value():
    # the enum value IS the order NORMAL<THROTTLE<DEGRADE<REFUSE_NEW<HARD_STOP (monotone-graduation invariant)
    order = [PoolPosture.NORMAL, PoolPosture.THROTTLE, PoolPosture.DEGRADE,
             PoolPosture.REFUSE_NEW, PoolPosture.HARD_STOP]
    assert [p.value for p in order] == sorted(p.value for p in order)


def test_bands_from_config_non_monotone_override_reverts_to_safe_defaults(monkeypatch):
    # a hostile/typo override that would INVERT the graduation (refuse below throttle) must fall back wholesale
    monkeypatch.setenv("VIGIL_GLOBAL_POOL_REFUSE_AT", "0.10")     # refuse < throttle (0.75) — non-monotone
    b = PoolBands.from_config()
    assert (b.throttle_at, b.degrade_at, b.refuse_at, b.hard_stop_at) == (0.75, 0.85, 0.95, 1.0)


@pytest.mark.parametrize("env,val", [
    ("VIGIL_GLOBAL_POOL_REFUSE_AT", "1.5"),      # a percent-vs-fraction typo (150%) — monotone but out-of-domain
    ("VIGIL_GLOBAL_POOL_HARD_STOP_AT", "2.0"),   # hard_stop above 1.0 — the used-fraction can never reach it
    ("VIGIL_GLOBAL_POOL_THROTTLE_AT", "80"),     # 80 (meant 0.80): would keep the whole band > 1.0
])
def test_bands_above_one_revert_to_safe_defaults_so_the_kill_switch_cannot_be_silently_disarmed(monkeypatch, env, val):
    # A threshold ABOVE 1.0 (a percent-vs-fraction typo) is monotone-but-out-of-domain: the used-fraction (used/budget)
    # can never reach it, so an ARMED pool would NEVER refuse — the kill-switch is silently disarmed. The band
    # validation's h <= 1.0 upper bound must reject it wholesale, reverting to the safe (armable) defaults.
    monkeypatch.setenv(env, val)
    b = PoolBands.from_config()
    assert (b.throttle_at, b.degrade_at, b.refuse_at, b.hard_stop_at) == (0.75, 0.85, 0.95, 1.0)
    assert b.degrade_factor == 0.5


# ======================================================================================================
# 5) global_position() — SINGLE-PASS correctness + the sum-of-tenant_costs equivalence oracle
# ======================================================================================================
def test_global_position_aggregates_committed_and_in_flight_across_orgs():
    s = _store()
    L = _led(s)
    # org_a: reserve 1000 (n1) settle 700 (n1); reserve 500 (n2) left IN-FLIGHT
    L.reserve("org_a", 1000, entry_id="reserve-cost:org_a:n1", issued_at=_issue())
    L.settle("org_a", 700, entry_id="settle-cost:org_a:n1", reserved_cap=1000, issued_at=_issue())
    L.reserve("org_a", 500, entry_id="reserve-cost:org_a:n2", issued_at=_issue())
    # org_b: reserve 2000 (n1) settle 2000 (n1); reserve 300 (n2) left IN-FLIGHT
    L.reserve("org_b", 2000, entry_id="reserve-cost:org_b:n1", issued_at=_issue())
    L.settle("org_b", 2000, entry_id="settle-cost:org_b:n1", reserved_cap=2000, issued_at=_issue())
    L.reserve("org_b", 300, entry_id="reserve-cost:org_b:n2", issued_at=_issue())
    gp = L.global_position()
    assert gp.committed_tokens == 700 + 2000                     # Σ settled ACTUAL across orgs
    assert gp.in_flight_tokens == 500 + 300                      # Σ reserved-but-unsettled across orgs
    assert gp.used_tokens == 3500


def test_global_position_equals_sum_of_tenant_costs_equivalence_oracle():
    s = _store()
    L = _led(s)
    L.reserve("org_a", 1000, entry_id="reserve-cost:org_a:n1", issued_at=_issue())
    L.settle("org_a", 700, entry_id="settle-cost:org_a:n1", reserved_cap=1000, issued_at=_issue())
    L.reserve("org_a", 500, entry_id="reserve-cost:org_a:n2", issued_at=_issue())
    L.reserve("org_b", 2000, entry_id="reserve-cost:org_b:n1", issued_at=_issue())
    L.settle("org_b", 2000, entry_id="settle-cost:org_b:n1", reserved_cap=2000, issued_at=_issue())
    L.reserve("org_b", 300, entry_id="reserve-cost:org_b:n2", issued_at=_issue())
    gp = L.global_position()
    # EQUIVALENCE ORACLE: the single-pass global == summing the per-tenant O(orgs×spine) view
    tcs = L.tenant_costs()
    assert gp.committed_tokens == sum(c.committed_tokens for c in tcs)
    assert gp.in_flight_tokens == sum(c.in_flight_tokens for c in tcs)
    assert gp.used_tokens == sum(c.committed_tokens + c.in_flight_tokens for c in tcs)


def test_global_position_empty_is_zero():
    gp = _led(_store()).global_position()
    assert gp.committed_tokens == 0 and gp.in_flight_tokens == 0 and gp.used_tokens == 0


def test_global_position_forged_cost_record_is_inert():
    # verify_signed inheritance: a forged (attacker-signed) reserve/settle must NOT move the global pool.
    s = _store()
    L = _led(s)
    L.reserve("org_a", 1000, entry_id="reserve-cost:org_a:n1", issued_at=1.0)
    L.settle("org_a", 700, entry_id="settle-cost:org_a:n1", reserved_cap=1000, issued_at=2.0)
    before = L.global_position()
    rcore = {"signal": COST_RESERVE_SIGNAL, "org_id": "org_a", "entry_id": "reserve-cost:org_a:forge",
             "tokens": 10_000_000, "engagement_id": "", "issued_at": 3.0}
    score = {"signal": COST_SETTLE_SIGNAL, "org_id": "org_a", "entry_id": "settle-cost:org_a:forge",
             "tokens": 10_000_000, "engagement_id": "", "issued_at": 4.0}
    s.append(kind="event", source="governor", actor="WARDEN", payload={**signed_payload(rcore, ATTACKER)})
    s.append(kind="event", source="governor", actor="WARDEN", payload={**signed_payload(score, ATTACKER)})
    after = L.global_position()
    assert (after.committed_tokens, after.in_flight_tokens) == (before.committed_tokens, before.in_flight_tokens)
    assert after.used_tokens == 700                              # only the genuine owner-signed settle counts


def test_global_position_negative_record_cannot_lower_the_pool():
    # a forged NEGATIVE settle would, if honored, REFUND the pool (fail-open) — _as_tokens clamps it to 0,
    # and the attacker key makes it inert regardless.
    s = _store()
    L = _led(s)
    L.reserve("org_a", 1000, entry_id="reserve-cost:org_a:n1", issued_at=1.0)
    L.settle("org_a", 700, entry_id="settle-cost:org_a:n1", reserved_cap=1000, issued_at=2.0)
    score = {"signal": COST_SETTLE_SIGNAL, "org_id": "org_a", "entry_id": "settle-cost:org_a:neg",
             "tokens": -10_000_000, "engagement_id": "", "issued_at": 3.0}
    s.append(kind="event", source="governor", actor="WARDEN", payload={**signed_payload(score, ATTACKER)})
    assert L.global_position().used_tokens == 700               # not lowered


# ======================================================================================================
# 6) FATAL-2 — cost_pool is sovereign (assert_no_offense) and imports nothing from the engine/offense plane
# ======================================================================================================
def test_fatal2_cost_pool_is_offense_free():
    import inspect
    import sys
    from sigil.governor import cost_pool
    cost_pool.assert_no_offense()                                # must not raise (ran at import too)
    # no offense-plane module leaked into the process via this import
    assert not any(m == "framework" or m.startswith("framework.") or m == "strix" or m.startswith("strix.")
                   for m in list(sys.modules)), "an offense-plane module is loaded"
    # and the module source imports only the sovereign seam (cost_ledger / config / vigil_core envelope)
    src = inspect.getsource(cost_pool)
    for forbidden in ("import framework", "from framework", "import strix", "from strix", "kernel.routing"):
        assert forbidden not in src, f"cost_pool must not reference {forbidden!r}"


# ======================================================================================================
# 7) LAUNCH-GATE wiring — the cost pair + the pool conjunct (full gate harness)
# ======================================================================================================
_giss = itertools.count(1)


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    # EC-5 flags default OFF in every test unless a test explicitly arms them
    monkeypatch.delenv("VIGIL_GLOBAL_POOL_TOKENS", raising=False)
    monkeypatch.delenv("VIGIL_COST_LEDGER_WRITE", raising=False)


def _gstore():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _setup(store, org, host, *, credits=100, now=1000.0):
    """Seat a member + wallet credits + an ownership proof + a minted EngagementAuthority (gate conjuncts 1-3)."""
    from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.governor.orgs import OrgRegistry
    from sigil.governor.wallet import WalletRegistry
    from sigil.ui.target_authorization import add_customer_target
    ensure_owner_keypair()
    orgs = OrgRegistry(store)
    orgs.create_org(org, org, owner="u", issued_at=float(next(_giss)))
    orgs.grant_membership(org, "u", "operator", issued_at=float(next(_giss)))
    WalletRegistry(store).grant(org, credits, "trial", entry_id=f"trial:{org}", issued_at=float(next(_giss)))
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(org, host, issued_at=float(next(_giss)))
    reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=now, ttl_seconds=1e12)
    r = add_customer_target(host, org_id=org, store=store, now=now)
    assert r["ok"], r


def _gate(store, **kw):
    from sigil.ui.launch_gate import LaunchGate
    return LaunchGate(store, **kw)


def _cost(store):
    return CostEnvelopeLedger(store)


def _avail(store, org):
    from sigil.governor.wallet import WalletRegistry
    return WalletRegistry(store).available(org)


def test_launch_gate_off_by_default_writes_no_cost_record_byte_identical():
    # DEFAULT-OFF: unbounded pool + write flag off => reserve+settle succeed exactly as pre-EC-5 and append
    # NO cost record (committed/reserved/in_flight all 0 on the cost ledger).
    s = _gstore()
    _setup(s, "org_a", "apme.cm", credits=100)
    r = _gate(s).reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=30, now=2000.0)
    assert r["ok"] and _avail(s, "org_a") == 70
    out = _gate(s).settle_launch(signed_lease=r["lease"], consumed_units=10, now=3000.0)
    assert out["ok"] and _avail(s, "org_a") == 90
    cl = _cost(s)
    assert cl.reserved_total("org_a") == 0 and cl.committed_cost("org_a") == 0
    assert cl.in_flight_envelope("org_a") == 0                  # NO cost record was appended


def test_launch_gate_cost_pair_written_only_when_enabled_and_idempotent(monkeypatch):
    from vigil_core import ENVELOPE_TOKENS_PER_CREDIT as E
    monkeypatch.setenv("VIGIL_COST_LEDGER_WRITE", "1")           # arm the write (pool still unbounded)
    s = _gstore()
    _setup(s, "org_a", "apme.cm", credits=100)
    g = _gate(s)
    r = g.reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=30, now=2000.0)
    assert r["ok"], r
    cl = _cost(s)
    assert cl.in_flight_envelope("org_a") == 30 * E             # cost RESERVE written (envelope = units * E)
    assert cl.committed_cost("org_a") == 0
    out = g.settle_launch(signed_lease=r["lease"], consumed_units=10, now=3000.0)
    assert out["ok"], out
    assert cl.committed_cost("org_a") == 10 * E                 # cost SETTLE written (consumed * E)
    assert cl.in_flight_envelope("org_a") == 0                  # settle landed -> no longer in-flight
    # IDEMPOTENT: a re-settle is a no-op (already-settled); the committed cost does not double
    out2 = g.settle_launch(signed_lease=r["lease"], consumed_units=10, now=4000.0)
    assert out2["ok"] and cl.committed_cost("org_a") == 10 * E


def test_launch_gate_cost_settle_clamps_to_reserved_envelope(monkeypatch):
    # the settle-write passes reserved_cap = reserved*E, so an over-consumed settle clamps to the signed cap
    # (a mutant dropping reserved_cap would let a forged over-report over-settle past the envelope).
    from vigil_core import ENVELOPE_TOKENS_PER_CREDIT as E
    monkeypatch.setenv("VIGIL_COST_LEDGER_WRITE", "1")
    s = _gstore()
    _setup(s, "org_a", "apme.cm", credits=100)
    g = _gate(s)
    r = g.reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=30, now=2000.0)
    # consumed is clamped to reserved (30) by the gate's own refund math, so the cost settle is 30*E, never more
    out = g.settle_launch(signed_lease=r["lease"], consumed_units=999, now=3000.0)
    assert out["ok"] and out["net_spend"] == 30
    assert _cost(s).committed_cost("org_a") == 30 * E           # clamped to the reserved envelope


def test_launch_gate_unbounded_pool_conjunct_is_a_noop():
    # the pool conjunct must be a no-op when unbounded: a normal launch is admitted (injected raising-ledger
    # unbounded pool proves the conjunct never folds).
    s = _gstore()
    _setup(s, "org_a", "apme.cm", credits=100)
    pool = GlobalCostPool(_RaisingLedger(), budget_tokens=None)
    r = _gate(s, pool=pool).reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=30, now=2000.0)
    assert r["ok"], r                                           # unbounded => conjunct never refuses / folds


def test_launch_gate_pool_refuses_new_when_armed_and_over_threshold():
    # an ARMED pool past the REFUSE_NEW band refuses a NEW launch and mints NOTHING / debits NOTHING (mirror
    # the PP-3 overdue refusal). Injected over-threshold pool keeps the assertion deterministic.
    s = _gstore()
    _setup(s, "org_a", "apme.cm", credits=100)
    over = GlobalCostPool(_FakeLedger(960), budget_tokens=1000)   # 0.96 -> REFUSE_NEW
    r = _gate(s, pool=over).reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=30, now=2000.0)
    assert r["ok"] is False and "cost pool" in r["error"].lower()
    assert _avail(s, "org_a") == 100                             # NOTHING debited on the pool refusal


def test_launch_gate_hard_stop_refuses_new():
    s = _gstore()
    _setup(s, "org_a", "apme.cm", credits=100)
    hard = GlobalCostPool(_FakeLedger(5000), budget_tokens=1000)  # 5.0 -> HARD_STOP
    r = _gate(s, pool=hard).reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=30, now=2000.0)
    assert r["ok"] is False and "cost pool" in r["error"].lower()
    assert _avail(s, "org_a") == 100


def test_launch_gate_armed_pool_read_error_fails_closed_refuses():
    # FAIL-CLOSED in the live path: an armed pool whose meter raises refuses the new launch (never admits).
    s = _gstore()
    _setup(s, "org_a", "apme.cm", credits=100)
    broken = GlobalCostPool(_RaisingLedger(), budget_tokens=1000)
    r = _gate(s, pool=broken).reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=30, now=2000.0)
    assert r["ok"] is False and "cost pool" in r["error"].lower()
    assert _avail(s, "org_a") == 100


def test_launch_gate_in_flight_settles_and_pool_self_heals(monkeypatch):
    # END-TO-END with the REAL pool reading REAL cost records: one in-flight reserve pushes the pool to
    # REFUSE_NEW, a NEW reserve is refused, the in-flight launch STILL settles (cancel frees the envelope),
    # and a fresh launch admits again — the auto-relax invariant, no owner-signed un-latch.
    from vigil_core import ENVELOPE_TOKENS_PER_CREDIT as E
    units = 30
    envelope = units * E
    budget = envelope + envelope // 20          # frac = 1/1.05 = 0.952 -> REFUSE_NEW after ONE reserve
    monkeypatch.setenv("VIGIL_GLOBAL_POOL_TOKENS", str(budget))   # arms the pool AND the cost write
    s = _gstore()
    _setup(s, "org_a", "apme.cm", credits=400)
    # r1 admits (pool empty at its gate-check; its own reserve is written AFTER the check)
    r1 = _gate(s).reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=units, now=2000.0, nonce="a1")
    assert r1["ok"], r1
    assert _cost(s).global_position().used_tokens == envelope    # now in-flight draw == one envelope
    # r2 is REFUSED — the pool is over the refuse threshold from r1's in-flight draw
    r2 = _gate(s).reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=units, now=2100.0, nonce="a2")
    assert r2["ok"] is False and "cost pool" in r2["error"].lower()
    # the in-flight r1 STILL settles (cancel) — settle is NOT gated by the pool — freeing the envelope
    out = _gate(s).settle_launch(signed_lease=r1["lease"], consumed_units=0, now=2200.0)
    assert out["ok"] and out["net_spend"] == 0
    assert _cost(s).global_position().used_tokens == 0           # pool freed (committed 0, in-flight 0)
    # SELF-HEAL: a fresh launch admits again now the pool has relaxed
    r3 = _gate(s).reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=units, now=2300.0, nonce="a3")
    assert r3["ok"], r3
