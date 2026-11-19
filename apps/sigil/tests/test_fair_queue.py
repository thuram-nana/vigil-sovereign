"""Consumer PR-F — the SOVEREIGN pure fair cross-tenant launch queue (``governor.fair_queue``).

Invariants pinned here (each a named test; the three SELF-RED-PEN scenarios are called out):
  * FAIRNESS — a tenant that floods the queue can NEVER starve another tenant's launch (RED-PEN #1);
  * SERIAL-PER-TARGET — at most one runnable slot per (tenant, target); one target is NEVER parallelized
    (RED-PEN #2 — target safety);
  * DETERMINISM — the order/admission are a pure function of the inputs (reproducible, total tie-break);
  * CAPACITY — the cross-tenant concurrency bound is honored; over-capacity launches are honestly QUEUED;
  * IDOR-SAFE — a position is COUNTS only, and a tenant can only name its own launch (no cross-tenant leak);
  * CLAIM-DISCIPLINE — the surface carries no FACT and no model identifier (only the oracle mints facts).
"""
from __future__ import annotations

import pytest

from sigil.governor.fair_queue import (
    Admission, QueueItem, QueuePosition, admit, fair_order, make_items, position_of,
)


def _it(tenant: str, seq: int, target: str = "", job_id: str = "") -> QueueItem:
    return QueueItem(tenant=tenant, seq=seq, target=target or f"{tenant}-t{seq}", job_id=job_id)


# -- fair_order --------------------------------------------------------------------------------------

def test_fair_order_is_round_robin_across_tenants():
    # A arrives first and floods; B and C each arrive once, later.
    items = [_it("A", 1), _it("A", 2), _it("A", 3), _it("B", 4), _it("C", 5), _it("A", 6)]
    order = fair_order(items)
    # round 0 = each tenant's oldest, in arrival order: A1, B4, C5; then round 1: A2, A3? no — A's 2nd is rank1.
    tenants = [i.tenant for i in order]
    # The first three dequeued cover A, B and C (round 0) — no tenant waits behind another's backlog.
    assert set(tenants[:3]) == {"A", "B", "C"}


def test_fair_order_preserves_per_tenant_fifo():
    items = [_it("A", 5), _it("A", 1), _it("A", 3)]
    order = [i.seq for i in fair_order(items)]
    assert order == [1, 3, 5]  # one tenant: pure arrival order, untouched


def test_fair_order_is_deterministic_and_total_even_on_equal_seq():
    # Two items of one tenant share a seq — the (target, job_id) tail keeps the order total + stable.
    a = [_it("A", 1, target="z"), _it("A", 1, target="a"), _it("B", 1, target="b")]
    assert fair_order(a) == fair_order(list(a)) == fair_order(tuple(a))  # pure: same input, same output
    # within tenant A, target "a" (smaller) ranks before "z"
    a_order = [i.target for i in fair_order(a) if i.tenant == "A"]
    assert a_order == ["a", "z"]


def test_fair_order_does_not_mutate_input():
    items = [_it("A", 2), _it("B", 1)]
    snapshot = list(items)
    fair_order(items)
    assert items == snapshot


# -- RED-PEN #1 — one tenant floods and starves others -----------------------------------------------

def test_redpen_flooding_tenant_cannot_starve_a_single_tenant():
    # A floods 100 launches that ALL arrive before B's single launch.
    flood = [_it("A", i) for i in range(1, 101)]
    b = _it("B", 101)
    order = fair_order(flood + [b])
    b_pos = next(k for k, i in enumerate(order) if i.tenant == "B")
    # B (its own rank 0) is served right after A's rank-0 launch — position 1, NOT behind A's 99-deep backlog.
    assert b_pos == 1, f"B starved at position {b_pos} behind A's flood"
    # And under a tight capacity, a fair admit still runs B this round (one slot per tenant before any second).
    adm = admit(flood + [b], capacity=2)
    assert any(i.tenant == "B" for i in adm.admitted), "B starved out of a 2-wide admit by A's flood"


def test_redpen_flood_is_fair_across_many_rounds():
    # Three tenants, A floods — over successive rounds every tenant gets a turn before anyone gets a third.
    items = [_it("A", i) for i in range(1, 51)] + [_it("B", 100), _it("B", 101), _it("C", 200)]
    order = fair_order(items)
    # B's two launches and C's one all appear within the first 6 dequeued (rounds 0-1 across 3 tenants),
    # never buried under A's 50-deep backlog.
    head = order[:6]
    assert any(i.tenant == "C" for i in head)
    assert sum(1 for i in head if i.tenant == "B") == 2


# -- RED-PEN #2 — break serial-per-target ------------------------------------------------------------

def test_redpen_one_target_is_never_parallelized():
    # Two launches of the SAME (tenant, target) — only one may be runnable; the other is queued.
    same = [QueueItem("A", 1, "tgt"), QueueItem("A", 2, "tgt")]
    adm = admit(same, capacity=10)
    assert len(adm.admitted) == 1, "serial-per-target broken: one target admitted twice (parallelized)"
    assert len(adm.queued) == 1
    assert adm.admitted[0].seq == 1  # the oldest of the target runs; its sibling waits


def test_redpen_target_already_running_is_not_admitted_again():
    running = [QueueItem("A", 0, "tgt")]  # a live run of this target
    pending = [QueueItem("A", 1, "tgt"), QueueItem("B", 2, "other")]
    adm = admit(pending, running=running, capacity=10)
    admitted = {(i.tenant, i.target) for i in adm.admitted}
    assert ("A", "tgt") not in admitted, "re-admitted a target that is already running (parallelized a target)"
    assert ("B", "other") in admitted  # a different target is free to run


def test_serial_busy_target_does_not_consume_a_capacity_slot():
    # A's target is running; with capacity 1, B's different target must still get the one slot — the busy
    # A launch must not 'use up' capacity it cannot run on.
    running = [QueueItem("A", 0, "atgt")]
    pending = [QueueItem("A", 1, "atgt"), QueueItem("B", 2, "btgt")]
    adm = admit(pending, running=running, capacity=1)
    assert [(i.tenant) for i in adm.admitted] == ["B"]


def test_running_accepts_bare_tenant_target_pairs():
    pending = [QueueItem("A", 1, "tgt")]
    adm = admit(pending, running=[("A", "tgt")], capacity=5)
    assert adm.admitted == ()
    assert len(adm.queued) == 1


# -- capacity ----------------------------------------------------------------------------------------

def test_capacity_none_is_unbounded_but_still_serial():
    items = [_it("A", 1), _it("B", 2), _it("C", 3)]
    adm = admit(items, capacity=None)
    assert len(adm.admitted) == 3 and adm.queued == ()


def test_capacity_zero_or_negative_admits_nothing():
    items = [_it("A", 1), _it("B", 2)]
    for cap in (0, -1):
        adm = admit(items, capacity=cap)
        assert adm.admitted == ()
        assert len(adm.queued) == 2  # everything honestly queued (e.g. a REFUSE_NEW pool posture)


def test_capacity_one_is_fair_over_repeated_admits():
    # With capacity 1 the head of the fair order runs; it is A's oldest, not a monopoly beyond one slot.
    items = [_it("A", 1), _it("A", 2), _it("B", 3)]
    adm = admit(items, capacity=1)
    assert len(adm.admitted) == 1 and adm.admitted[0].tenant == "A" and adm.admitted[0].seq == 1


# -- position_of (IDOR-safe) -------------------------------------------------------------------------

def test_position_of_reports_admitted_for_a_runnable_launch():
    items = [_it("A", 1, target="a"), _it("B", 2, target="b")]
    pos = position_of(items, tenant="A", target="a", seq=1, capacity=5)
    assert pos == QueuePosition(state="admitted", ahead=0, queue_depth=0)


def test_position_of_reports_honest_queue_depth_and_ahead():
    # A floods; B's launch is queued behind nothing of A's except A's rank-0.
    items = [_it("A", 1, target="a1"), _it("A", 2, target="a2"), _it("A", 3, target="a3"), _it("B", 4, target="b")]
    pos = position_of(items, tenant="A", target="a3", seq=3, capacity=1)
    assert pos is not None and pos.state == "queued"
    # ahead is a COUNT, and the depth is the total queued — both counts, no identities.
    assert pos.ahead >= 0 and pos.queue_depth == len(admit(items, capacity=1).queued)


def test_position_of_is_idor_safe_counts_only():
    items = [_it("A", 1, target="a"), _it("B", 2, target="b")]
    pos = position_of(items, tenant="B", target="b", seq=2, capacity=0)
    assert pos is not None
    # The whole surface is ints + a safe state string — no tenant id, host, target or lease of ANY other tenant.
    assert isinstance(pos.ahead, int) and isinstance(pos.queue_depth, int)
    assert pos.state in ("admitted", "queued")
    # A caller cannot discover another tenant's launch: naming a target it cannot forge yields None.
    assert position_of(items, tenant="B", target="a", seq=1, capacity=0) is None


def test_position_of_absent_launch_is_none():
    items = [_it("A", 1, target="a")]
    assert position_of(items, tenant="Z", target="z", seq=99) is None


# -- make_items (source adapter) ---------------------------------------------------------------------

def test_make_items_normalizes_and_drops_malformed_rows():
    rows = [
        {"tenant": "A", "seq": 1, "target": "a", "job_id": "j1"},
        {"tenant": "", "seq": 2, "target": "b"},        # no tenant -> dropped
        {"tenant": "B", "seq": "x", "target": "c"},      # bad seq -> dropped
        {"tenant": "C", "seq": 3, "target": ""},         # no target -> dropped
        {"tenant": "D", "seq": 4, "target": "d"},        # ok, no job_id
    ]
    items = make_items(rows)
    assert [(i.tenant, i.seq, i.target, i.job_id) for i in items] == [("A", 1, "a", "j1"), ("D", 4, "d", "")]


# -- claim discipline --------------------------------------------------------------------------------

_MODEL_TOKENS = ("claude", "opus", "sonnet", "gpt", "anthropic", "model", "llm")


def test_surface_leaks_no_fact_or_model_identifier():
    # A queue position is a UI notice, never a FACT and never a model name.
    items = [_it("A", 1, target="a")]
    pos = position_of(items, tenant="A", target="a", seq=1, capacity=0)
    blob = repr(pos).lower()
    assert "fact" not in blob
    for tok in _MODEL_TOKENS:
        assert tok not in blob, f"model identifier {tok!r} leaked into a customer-facing position"
    # The dataclasses expose only counts + a safe state — no signing, no spine, no engine handle.
    assert set(vars(Admission()).keys()) == {"admitted", "queued"}
