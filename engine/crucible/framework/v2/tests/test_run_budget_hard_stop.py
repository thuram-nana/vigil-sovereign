"""EC-3 — the RUN-SCOPED HARD token budget enforced at the engine (kernel chokepoint + engage stop/settle).

The fail-CLOSED run ceiling: the kernel ``complete_with_failover`` charges each call's actual tokens to the
per-run accumulator and RAISES ``RunBudgetExceeded`` BEFORE the egress that would spend past the owner-signed
reserved envelope; ``engage.run_engagement`` turns that terminal raise into a PARTIAL EngagementResult (so the
worker settles it COMPLETED, never FAILED/free-run). The ceiling is ``units_reserved × ENVELOPE_TOKENS_PER_CREDIT``
read from the VERIFIED lease. Everything here is offline/hermetic (no key, no network, no provider).

Mutation-verify targets (each neuter reds a NAMED test here):
  * make _rb_check a no-op / stop raising when over      -> test_kernel_charges_then_stops_before_egress
  * make _rb_ act even when the run is UNARMED           -> test_kernel_unarmed_is_byte_identical_noop
  * charge dry-run tokens (drop the is_dryrun skip)      -> test_kernel_dry_run_charges_zero
  * engage re-raises RunBudgetExceeded instead of partial -> test_run_engagement_budget_stop_returns_a_partial_that_can_settle
  * _arm_run_budget reads the lease when the flag is OFF  -> test_arm_default_off_reads_no_lease
  * ceiling != units × ENVELOPE_TOKENS_PER_CREDIT         -> test_arm_from_verified_lease_is_units_times_envelope
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from framework.v2 import engage as engage_mod
from framework.v2 import launch_lease as LL
from framework.v2.common import paths as _paths
from framework.v2.engage import EngagementResult, run_engagement
from framework.v2.kernel import llm
from framework.v2.phase_ledger import P_SCAN

from vigil_core import ENVELOPE_TOKENS_PER_CREDIT, RunBudgetExceeded
from vigil_core import run_budget as rb


@pytest.fixture(autouse=True)
def _clean_budget(monkeypatch, tmp_path):
    """Default-OFF + unarmed between tests; keep the advisory token-budget store off the real FS so the
    _tb_ sibling never pollutes ``.vigil-live`` while we exercise the _rb_ hard stop beside it."""
    monkeypatch.delenv(rb._ENABLE_ENV, raising=False)
    monkeypatch.delenv("VIGIL_RUN_TOKEN_CEILING", raising=False)
    monkeypatch.setenv("VIGIL_TOKEN_BUDGET_FILE", str(tmp_path / "tb.json"))
    rb.reset()
    yield
    rb.reset()


def _on(monkeypatch):
    monkeypatch.setenv(rb._ENABLE_ENV, "1")


# =============================================================================== kernel chokepoint
def _fake_backend(name="prim", *, tokens_in=0, tokens_out=0, is_dryrun=False):
    """A backend whose .complete() records a provider round-trip and returns a trace carrying the tokens the
    run budget charges. ``state['calls']`` counts egress round-trips so we can prove the STOPPING call never
    reached the provider."""
    state = {"calls": 0}

    class _B:
        pass
    b = _B()
    b.name = name
    b.is_available = lambda: (True, "ready")

    def _c(prompt):
        state["calls"] += 1
        return SimpleNamespace(parsed="ok", raw_response="",
                               trace=SimpleNamespace(backend=name, tokens_in=tokens_in,
                                                     tokens_out=tokens_out, is_dryrun=is_dryrun, cached=False))
    b.complete = _c
    return b, state


def _wire(monkeypatch, backend):
    monkeypatch.delenv(llm._ENV_OVERRIDE, raising=False)
    monkeypatch.setattr(llm, "get_backend", lambda: backend)
    monkeypatch.setattr(llm, "_construct", lambda nm: backend)
    monkeypatch.setattr(llm.sovereignty, "current",
                        lambda: SimpleNamespace(permitted_preference=lambda: (backend.name,)))


def test_kernel_charges_then_stops_before_egress(monkeypatch):
    _on(monkeypatch)
    b, state = _fake_backend(tokens_in=100, tokens_out=0)   # each real call spends exactly 100
    _wire(monkeypatch, b)
    rb.arm(100)                                             # ceiling == one call's spend

    llm.complete_with_failover(prompt=SimpleNamespace())    # call 1: spent 0 < 100 → egress + charge → 100
    assert state["calls"] == 1
    assert rb.spent() == 100

    with pytest.raises(RunBudgetExceeded):                  # call 2: spent 100 >= 100 → STOP before egress
        llm.complete_with_failover(prompt=SimpleNamespace())
    assert state["calls"] == 1                              # NO provider round-trip on the stopping call
    assert rb.was_exceeded() is True


def test_kernel_unarmed_is_byte_identical_noop(monkeypatch):
    # Flag ON but the run is never armed (no lease / no ceiling): the _rb_ helpers are inert and the call
    # proceeds unchanged however many tokens it "spends".
    _on(monkeypatch)
    b, state = _fake_backend(tokens_in=10**6, tokens_out=10**6)
    _wire(monkeypatch, b)
    assert rb.current_ceiling() is None
    for _ in range(4):
        llm.complete_with_failover(prompt=SimpleNamespace())
    assert state["calls"] == 4                              # never stopped
    assert rb.spent() == 0                                  # nothing charged (unarmed)


def test_kernel_dry_run_charges_zero(monkeypatch):
    _on(monkeypatch)
    b, state = _fake_backend(tokens_in=10**6, tokens_out=10**6, is_dryrun=True)
    _wire(monkeypatch, b)
    rb.arm(50)
    for _ in range(4):
        llm.complete_with_failover(prompt=SimpleNamespace())
    assert state["calls"] == 4                              # dry-run calls are never stopped
    assert rb.spent() == 0                                  # dry-run charges 0 (determinism / make-gate safe)


def test_kernel_l2_hit_charges_zero_and_is_not_blocked(monkeypatch):
    # A cache HIT reaches no provider and spends nothing, so it is NEVER stopped — even past the ceiling.
    _on(monkeypatch)
    b, _state = _fake_backend()
    _wire(monkeypatch, b)
    rb.arm(10)
    rb.charge(10)                                           # already AT the ceiling
    canned = SimpleNamespace(parsed="cached", raw_response="",
                             trace=SimpleNamespace(backend="prim", tokens_in=0, tokens_out=0,
                                                   is_dryrun=False, cached=True))
    monkeypatch.setattr(llm, "_l2_backend_for_failover", lambda p: b)
    monkeypatch.setattr(llm, "_l2_lookup", lambda p, bk: canned)
    got = llm.complete_with_failover(prompt=SimpleNamespace())   # returns BEFORE _rb_check
    assert got is canned
    assert rb.spent() == 10                                 # unchanged — the hit charged nothing


# =============================================================================== _arm_run_budget (ceiling)
def test_arm_from_verified_lease_is_units_times_envelope(monkeypatch):
    _on(monkeypatch)
    monkeypatch.setattr(LL, "customer_engagement_requires_lease", lambda slug: True)
    monkeypatch.setattr(LL, "read_verified_launch_units", lambda slug, host, tenant, **k: 7)
    armed = engage_mod._arm_run_budget("cust_x", "http://target.example/")
    assert armed == 7 * ENVELOPE_TOKENS_PER_CREDIT          # the SAME reserved envelope, in tokens
    assert rb.current_ceiling() == 7 * ENVELOPE_TOKENS_PER_CREDIT


def test_arm_default_off_reads_no_lease(monkeypatch):
    # Flag UNSET: arm is a no-op AND must not even read the lease (byte-identical preflight).
    seen = {"read": False}

    def _spy(*_a, **_k):
        seen["read"] = True
        return 9
    monkeypatch.setattr(LL, "customer_engagement_requires_lease", lambda slug: True)
    monkeypatch.setattr(LL, "read_verified_launch_units", _spy)
    assert engage_mod._arm_run_budget("cust_x", "http://target.example/") is None
    assert rb.current_ceiling() is None
    assert seen["read"] is False                            # no lease read when the flag is off


def test_arm_flag_on_no_lease_no_env_is_unarmed(monkeypatch):
    # Flag ON but NOT a customer run and no operator override → still UNARMED (greenfield/make-gate safe).
    _on(monkeypatch)
    monkeypatch.setattr(LL, "customer_engagement_requires_lease", lambda slug: False)
    assert engage_mod._arm_run_budget("eng_local", "http://target.example/") is None
    assert rb.current_ceiling() is None


def test_arm_operator_env_ceiling_without_a_lease(monkeypatch):
    _on(monkeypatch)
    monkeypatch.setattr(LL, "customer_engagement_requires_lease", lambda slug: False)
    monkeypatch.setenv("VIGIL_RUN_TOKEN_CEILING", "12345")
    assert engage_mod._arm_run_budget("eng_local", "http://target.example/") == 12345
    assert rb.current_ceiling() == 12345


# =============================================================================== engage partial result
_CHARTER = """\
# Engagement charter — `{slug}`

**Status:** Final

## 1. Operator attestation

Signed: `tester`     Date: `2026-05-04`

## 2. In-scope systems

| Host / Surface | Notes | Auth |
|----------------|-------|------|
| `127.0.0.1` | Test app | Yes |

## 3. Out of scope

- Anything not listed above.

## 7. Posture

- [x] **TEST**
"""


@pytest.fixture()
def isolate(tmp_path, monkeypatch):
    targets = tmp_path / "targets"
    targets.mkdir()
    monkeypatch.setattr(_paths, "target_dir", lambda s: targets / s)
    monkeypatch.setattr(_paths, "charter_path", lambda s: targets / s / "charter.md")
    monkeypatch.setattr(_paths, "killswitch_path", lambda s: targets / s / ".halt")

    def build(slug: str):
        td = targets / slug
        td.mkdir(parents=True, exist_ok=True)
        (td / "charter.md").write_text(_CHARTER.format(slug=slug), encoding="utf-8")
        return td
    return build


def _campaign_that_hits_the_ceiling():
    """A WebScanCampaign stand-in whose .run() raises RunBudgetExceeded — the kernel stop propagating out
    of the scan phase (the one LLM-bearing phase that is NOT wrapped by PhaseLedger.run_phase)."""
    class _Fake:
        def __init__(self, *_a, **_k):
            pass

        def run(self, _seed):
            raise RunBudgetExceeded(ceiling=50, spent=60)
    return _Fake


def test_run_engagement_budget_stop_returns_a_partial_that_can_settle(isolate, monkeypatch):
    isolate("eng_budget")
    seed = "http://127.0.0.1:9/"
    monkeypatch.setattr(engage_mod, "WebScanCampaign", _campaign_that_hits_the_ceiling())

    # The run must RETURN (not raise) — a raise would make engage_worker emit FAILED → full refund → free run.
    result = run_engagement("eng_budget", seed, enable_chaining=False)

    assert isinstance(result, EngagementResult)
    assert result.stopped_reason is not None and "budget" in result.stopped_reason.lower()
    assert result.report.target == seed                    # findings-so-far retained (empty on a mid-scan stop)
    assert result.report.active_findings == []


def test_run_engagement_no_budget_stop_leaves_stopped_reason_none(isolate, monkeypatch):
    # A normal run (no RunBudgetExceeded) is byte-identical: stopped_reason stays None.
    from framework.v2.scanner.campaign import ScanReport

    class _Fake:
        def __init__(self, *_a, **_k):
            pass

        def run(self, _seed):
            return ScanReport(target=_seed, pages_crawled=1)
    isolate("eng_ok")
    monkeypatch.setattr(engage_mod, "WebScanCampaign", _Fake)
    result = run_engagement("eng_ok", "http://127.0.0.1:9/", enable_chaining=False)
    assert result.stopped_reason is None


# =============================================================================== cross-plane (importorskip)
# These exercise the OWNER-SIGNED verify (lease units) and the SOVEREIGN settle semantics. They run on the
# integration/sovereign leg (vigil_integration + sigil present) and skip cleanly on crucible-core, exactly
# like test_launch_lease.py — the two-env boundary stays green either way.
def test_read_verified_launch_units_returns_reserved_without_consuming(monkeypatch):
    import tempfile
    from datetime import datetime, timedelta, timezone

    clb = pytest.importorskip("vigil_integration.live.credit_lease_broker")
    from vigil_core import (
        AuthorizerKey, CreditLaunchLease, TrustRoot, generate_keypair, sign_credit_launch_lease,
    )
    slug, host, org = "cust_units1", "apme.cm", "org_a"
    owner = generate_keypair()
    root = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=owner.public_key_b64)])
    t = datetime.fromtimestamp(1000.0, tz=timezone.utc)
    doc = CreditLaunchLease(engagement_slug=slug, org_id=org, scope_host=host, units_reserved=10,
                            not_before=t - timedelta(hours=1), not_after=t + timedelta(hours=8),
                            nonce="n1", issued_at=1000.0)
    signed = sign_credit_launch_lease(doc, {"owner": owner.private_key_b64})
    base = tempfile.mkdtemp()
    clb.write_credit_lease(base, slug, signed, root)
    monkeypatch.setattr("framework.v2.authority.store.load_authority_root", lambda: root)

    # the OWNER-SIGNED units, keyless, and the read does NOT burn the single-use floor
    assert LL.read_verified_launch_units(slug, host, org, base_dir=base, now=1000.0) == 10
    assert LL.read_verified_launch_units(slug, host, org, base_dir=base, now=1000.0) == 10
    assert LL.verify_customer_launch_lease(slug, host, org, base_dir=base, now=1000.0, consume=True)[0]
    # fail-closed: wrong host / wrong tenant / absent ⇒ None (no ceiling derivable)
    assert LL.read_verified_launch_units(slug, "evil.cm", org, base_dir=base, now=1000.0) is None
    assert LL.read_verified_launch_units(slug, host, "org_evil", base_dir=base, now=1000.0) is None
    assert LL.read_verified_launch_units("cust_absent", host, org, base_dir=base, now=1000.0) is None

# NOTE: the SOVEREIGN settle side of the composition (completion_spool._consumed: a COMPLETED run settles the
# full reserved units FLAT-PER-RUN; a FAILED run refunds fully) is asserted in the sovereign-only leg
# (apps/sigil/tests/test_ec3_settle_composition.py) — it imports ``sigil.*``, which assert_no_offense() forbids
# in any process that has loaded ``framework.*`` (the FATAL-2 two-env boundary), so it cannot share this file.


# ============================================================= self-consistency sweep (parallel) under the cap
def test_run_consistent_parallel_sweep_is_charged_and_then_stops(monkeypatch):
    """The EC-3 self-consistency FIX, end to end at the kernel. A PARALLEL sweep (max_workers>1) runs each
    sample inside a ``copy_context`` of the armed run (``kernel.consistency.run_consistent``), so the budget
    hooks a sample invokes — ``llm._rb_charge`` after each call, ``llm._rb_check`` before — land on THIS run's
    accumulator and the fail-closed STOP holds. Before the fix (a bare ``ThreadPoolExecutor.map``, fresh child
    contexts) the cost-dominant parallel reasoning path charged NOTHING and stopped NEVER — escaping the hard
    cap. check-before/charge-after is per-sample, so a single sweep may overshoot before the stop fires; the
    cap is a HARD ceiling at SWEEP granularity (bounded by the in-flight batch), which is what this asserts.
    MUTATION-VERIFY: reverting run_consistent's parallel branch to a bare ``ex.map`` (no copy_context) leaves
    ``rb.spent() == 0`` here (the sweep spend escapes) and the follow-on ``_rb_check`` never stops."""
    from framework.v2.kernel.consistency import run_consistent
    _on(monkeypatch)
    rb.arm(100)                                            # ceiling 100 tokens; 40/sample

    def run_fn():
        llm._rb_check()                                   # STOP before (raises once cumulative >= ceiling)
        llm._rb_charge(SimpleNamespace(tokens_in=40, tokens_out=0, is_dryrun=False))   # CHARGE actual tokens
        return ({"answer": "x"}, None)

    try:
        try:
            run_consistent(run_fn, samples=5, max_workers=4)
            stopped_in_sweep = False
        except RunBudgetExceeded:
            stopped_in_sweep = True
        # EITHER a sample's check stopped the sweep, OR it overshot — but every parallel sample CHARGED the
        # one shared run accumulator (the copy_context fix). Without the fix this would be 0 (spend escaped).
        assert rb.spent() >= 100
        if not stopped_in_sweep:
            with pytest.raises(RunBudgetExceeded):        # the stop then fires on the next reasoning call
                llm._rb_check()
    finally:
        rb.reset()


def test_arm_clears_a_stale_budget_leaked_by_a_prior_raised_run(monkeypatch):
    """Disarm-after-raise safety (closes the LOW): ``run_engagement``'s tail ``reset()`` is skipped when a run
    RAISES after arming (an OOB-allowlist / fleet-admission refusal out of the scan block), leaving a ceiling
    on the thread. ``_arm_run_budget`` RESETS at its START, so the NEXT run on the same (pooled/reused) thread
    never inherits that stale ceiling — the cross-run leak is closed by construction, without wrapping the
    whole 400-line run body in a try/finally.  MUTATION-VERIFY: dropping that start-of-run ``reset()`` leaves
    the stale 999 ceiling visible to the next run here."""
    _on(monkeypatch)
    rb.arm(999)                                           # a ceiling leaked by a prior run that raised post-arm
    assert rb.current_ceiling() == 999
    # the next run arms: flag ON, a non-customer run with no operator override → unarmed, stale slot cleared.
    monkeypatch.setattr(LL, "customer_engagement_requires_lease", lambda slug: False)
    assert engage_mod._arm_run_budget("eng_local", "http://target.example/") is None
    assert rb.current_ceiling() is None                   # the prior run's stale ceiling is GONE
    assert rb.spent() == 0
