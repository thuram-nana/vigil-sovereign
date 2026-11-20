"""Consumer PR-F — the SOVEREIGN side of the tenant-fair claim (``governor.fair_queue`` over ``vigil_core.fair_share``).

Invariants pinned here (each a named test; the self-red-pen scenarios are called out):
  * STREAMING FAIRNESS — the queue drains one freed slot at a time, so fairness is tested THAT way: a hog with jobs
    running cannot take a latecomer's slot; 50 launches from 10 tenants at one slot per tick serve every tenant in
    the first 10; repeated single-slot admits alternate tenants (RED-PEN #1 — each RED on a pending-set-only rank);
  * SERIAL-PER-TARGET — a target is never admitted twice or while it runs; a busy target never takes a slot
    (RED-PEN #2 — target safety);
  * CAPACITY is the TOTAL bound — running launches count toward it;
  * DETERMINISM — the order/admission are a pure function of (items, running, state);
  * THE LIVE SOURCE — ``launch_positions`` / ``read_launch_positions`` answer for ONE org's own launches with counts,
    over the engine queue's real file layout; no queue / an oversized queue ⇒ no position, never a guess;
  * CLAIM-DISCIPLINE — a position carries no FACT and no model identifier (only the oracle mints facts).
"""
from __future__ import annotations

import json

from sigil.governor.fair_queue import (
    Admission, QueueItem, QueuePosition, admit, fair_order, launch_positions, make_items, position_of,
    read_launch_positions,
)
from vigil_core.fair_share import FairJob, FairState, QueueSnapshot, record_service


def _it(tenant: str, seq: int, target: str = "", job_id: str = "") -> QueueItem:
    return QueueItem(tenant=tenant, seq=seq, target=target or f"{tenant}-t{seq}", job_id=job_id)


def _drain(items, *, capacity, running=(), state=None):
    """Drain the way a real queue does: admit into the free slots, then ONE running launch finishes; repeat.
    Returns the tenants in admission order."""
    pending, run, st, order = list(items), list(running), state, []
    while pending:
        adm = admit(pending, running=run, capacity=capacity, state=st)
        st = adm.state
        for it in adm.admitted:
            pending.remove(it)
            run.append(it)
            order.append(it.tenant)
        if run:
            run.pop(0)
    return order


# -- fair_order ------------------------------------------------------------------------------------------------

def test_fair_order_is_round_robin_across_tenants():
    # A arrives first and floods; B and C each arrive once, later.
    items = [_it("A", 1), _it("A", 2), _it("A", 3), _it("B", 4), _it("C", 5), _it("A", 6)]
    tenants = [i.tenant for i in fair_order(items)]
    assert set(tenants[:3]) == {"A", "B", "C"}            # no tenant waits behind another's backlog
    assert tenants == ["A", "B", "C", "A", "A", "A"]


def test_fair_order_preserves_per_tenant_fifo():
    items = [_it("A", 5), _it("A", 1), _it("A", 3)]
    assert [i.seq for i in fair_order(items)] == [1, 3, 5]   # one tenant: pure arrival order, untouched


def test_fair_order_is_deterministic_and_total_even_on_equal_seq():
    a = [_it("A", 1, target="z"), _it("A", 1, target="a"), _it("B", 1, target="b")]
    assert fair_order(a) == fair_order(list(a)) == fair_order(tuple(a))   # pure: same input, same output
    assert [i.target for i in fair_order(a) if i.tenant == "A"] == ["a", "z"]


def test_fair_order_does_not_mutate_input():
    items = [_it("A", 2), _it("B", 1)]
    snapshot = list(items)
    fair_order(items)
    assert items == snapshot


def test_fair_order_honours_what_is_running_and_who_was_served_last():
    items = [_it("A", 1), _it("B", 2)]
    assert [i.tenant for i in fair_order(items, running=[_it("A", 0)])] == ["B", "A"]        # fewest running
    st = record_service(record_service(None, "B"), "A")                                      # A served last
    assert [i.tenant for i in fair_order(items, state=st)] == ["B", "A"]


# -- RED-PEN #1 — one tenant floods; the queue drains a slot at a time ---------------------------------------------

def test_redpen_flooding_tenant_cannot_starve_a_single_tenant():
    flood = [_it("A", i) for i in range(1, 101)]          # A floods 100 launches, all before B's single launch
    b = _it("B", 101)
    b_pos = next(k for k, i in enumerate(fair_order(flood + [b])) if i.tenant == "B")
    assert b_pos == 1, f"B starved at position {b_pos} behind A's flood"
    assert any(i.tenant == "B" for i in admit(flood + [b], capacity=2).admitted)


def test_redpen_a_hog_with_running_jobs_cannot_take_the_latecomers_slot():
    # the streaming case: the hog has 2 RUNNING and a 38-deep backlog; one of 3 slots frees; B arrived last.
    running = [_it("A", 0), _it("A", 1)]
    backlog = [_it("A", i) for i in range(2, 40)]
    late = _it("B", 1000)
    adm = admit(backlog + [late], running=running, capacity=3, state=record_service(record_service(None, "A"), "A"))
    assert [i.tenant for i in adm.admitted] == ["B"], "the hog's backlog took the slot a latecomer was owed"
    assert _drain(backlog + [late], capacity=3, running=running)[0] == "B"


def test_redpen_fifty_launches_ten_tenants_one_slot_per_tick():
    # the plan's acceptance case: 10 tenants each queue 5 launches (in blocks); ONE slot frees per tick.
    tenants = [f"T{k}" for k in range(10)]
    items = [_it(t, 5 * k + i) for k, t in enumerate(tenants) for i in range(5)]
    order = _drain(items, capacity=1)
    assert set(order[:10]) == set(tenants), f"a tenant waited behind another's backlog: {order[:10]}"
    assert max(order.index(t) for t in tenants) == 9
    assert sorted(order) == sorted(i.tenant for i in items)


def test_capacity_one_is_fair_over_repeated_admits():
    # capacity 1, admitted again and again as each run finishes: A's backlog does not monopolize the slot.
    assert _drain([_it("A", 1), _it("A", 2), _it("B", 3)], capacity=1) == ["A", "B", "A"]


def test_redpen_flood_is_fair_across_many_rounds():
    items = [_it("A", i) for i in range(1, 51)] + [_it("B", 100), _it("B", 101), _it("C", 200)]
    head = fair_order(items)[:6]
    assert any(i.tenant == "C" for i in head)
    assert sum(1 for i in head if i.tenant == "B") == 2


# -- RED-PEN #2 — break serial-per-target -----------------------------------------------------------------------

def test_redpen_one_target_is_never_parallelized():
    same = [QueueItem("A", 1, "tgt"), QueueItem("A", 2, "tgt")]
    adm = admit(same, capacity=10)
    assert len(adm.admitted) == 1, "serial-per-target broken: one target admitted twice (parallelized)"
    assert len(adm.queued) == 1
    assert adm.admitted[0].seq == 1                       # the oldest of the target runs; its sibling waits


def test_redpen_target_already_running_is_not_admitted_again():
    running = [QueueItem("A", 0, "tgt")]
    adm = admit([QueueItem("A", 1, "tgt"), QueueItem("B", 2, "other")], running=running, capacity=10)
    admitted = {(i.tenant, i.target) for i in adm.admitted}
    assert ("A", "tgt") not in admitted, "re-admitted a target that is already running (parallelized a target)"
    assert ("B", "other") in admitted


def test_a_running_launch_counts_against_capacity_but_a_busy_pending_one_takes_no_slot():
    running = [QueueItem("A", 0, "atgt")]
    pending = [QueueItem("A", 1, "atgt"), QueueItem("B", 2, "btgt")]
    # capacity is the TOTAL bound: 1 running of 1 ⇒ nothing more runs (the old pass admitted B: 2 of 1)
    assert admit(pending, running=running, capacity=1).admitted == ()
    # 2 of 2: one slot free — A's pending launch waits on its busy target WITHOUT taking that slot, B gets it
    assert [i.tenant for i in admit(pending, running=running, capacity=2).admitted] == ["B"]


def test_admission_never_exceeds_the_total_bound_over_a_drain():
    pending = [_it(t, 10 * k + i) for k, t in enumerate("ABCD") for i in range(6)]
    run: "list[QueueItem]" = []
    st = None
    while pending:
        adm = admit(pending, running=run, capacity=3, state=st)
        st = adm.state
        for it in adm.admitted:
            pending.remove(it)
            run.append(it)
        assert len(run) <= 3, f"{len(run)} concurrent against a bound of 3"
        run.pop(0)


def test_running_accepts_bare_tenant_target_pairs():
    adm = admit([QueueItem("A", 1, "tgt")], running=[("A", "tgt")], capacity=5)
    assert adm.admitted == ()
    assert len(adm.queued) == 1


# -- capacity ----------------------------------------------------------------------------------------------------

def test_capacity_none_is_unbounded_but_still_serial():
    adm = admit([_it("A", 1), _it("B", 2), _it("C", 3)], capacity=None)
    assert len(adm.admitted) == 3 and adm.queued == ()


def test_capacity_zero_or_negative_admits_nothing():
    items = [_it("A", 1), _it("B", 2)]
    for cap in (0, -1):
        adm = admit(items, capacity=cap)
        assert adm.admitted == ()
        assert len(adm.queued) == 2                       # everything honestly queued (e.g. a REFUSE_NEW posture)


def test_admit_returns_the_history_to_feed_back():
    adm = admit([_it("A", 1), _it("B", 2)], capacity=1)
    assert [i.tenant for i in adm.admitted] == ["A"] and adm.state.served_map() == {"A": 1}
    nxt = admit([_it("A", 3), _it("B", 2)], capacity=1, state=adm.state)
    assert [i.tenant for i in nxt.admitted] == ["B"]     # A was served last; B goes next


# -- position_of -------------------------------------------------------------------------------------------------

def test_position_of_reports_admitted_for_a_runnable_launch():
    items = [_it("A", 1, target="a"), _it("B", 2, target="b")]
    assert position_of(items, tenant="A", target="a", seq=1, capacity=5) == \
        QueuePosition(state="admitted", ahead=0, queue_depth=0)


def test_position_of_reports_honest_queue_depth_and_ahead():
    items = [_it("A", 1, target="a1"), _it("A", 2, target="a2"), _it("A", 3, target="a3"), _it("B", 4, target="b")]
    pos = position_of(items, tenant="A", target="a3", seq=3, capacity=1)
    # A1 runs; the claimer then serves B (A has one running), A2, A3 — so two are ahead of A3, three queued.
    assert pos == QueuePosition(state="queued", ahead=2, queue_depth=3)
    assert position_of(items, tenant="B", target="b", seq=4, capacity=1) == QueuePosition("queued", 0, 3)


def test_position_of_carries_counts_only():
    pos = position_of([_it("A", 1, target="a"), _it("B", 2, target="b")], tenant="B", target="b", seq=2, capacity=0)
    assert set(vars(pos)) == {"state", "ahead", "queue_depth"}
    assert isinstance(pos.ahead, int) and isinstance(pos.queue_depth, int) and pos.state in ("admitted", "queued")


def test_position_of_absent_launch_is_none():
    assert position_of([_it("A", 1, target="a")], tenant="Z", target="z", seq=99) is None


# -- make_items (row adapter) --------------------------------------------------------------------------------------

def test_make_items_normalizes_and_drops_malformed_rows():
    rows = [
        {"tenant": "A", "seq": 1, "target": "a", "job_id": "j1"},
        {"tenant": "", "seq": 2, "target": "b"},        # no tenant -> dropped
        {"tenant": "B", "seq": "x", "target": "c"},      # bad seq -> dropped
        {"tenant": "C", "seq": 3, "target": ""},         # no target -> dropped
        {"tenant": "D", "seq": 4, "target": "d"},        # ok, no job_id
        {"tenant": "E", "seq": True, "target": "e"},     # a bool is not a seq -> dropped
    ]
    assert [(i.tenant, i.seq, i.target, i.job_id) for i in make_items(rows)] == \
        [("A", 1, "a", "j1"), ("D", 4, "d", "")]


# -- the live source the launches read uses ----------------------------------------------------------------------

def _snap(pending, running=(), state=None):
    return QueueSnapshot(pending=tuple(pending), running=tuple(running), state=state or FairState())


def test_launch_positions_answer_only_for_the_asking_orgs_own_launches():
    snap = _snap([FairJob("org_a", 1, "cust_a1", nonce="na1"), FairJob("org_a", 2, "cust_a2", nonce="na2"),
                  FairJob("org_b", 3, "cust_b1", nonce="nb1")],
                 running=[FairJob("org_a", 0, "cust_a0", nonce="na0")])
    # org_a has one running: the claimer serves org_b first, then org_a's two in arrival order
    assert launch_positions("org_b", snap) == {("cust_b1", "nb1"): 0}
    assert launch_positions("org_a", snap) == {("cust_a1", "na1"): 1, ("cust_a2", "na2"): 2}
    assert launch_positions("", snap) == {} and launch_positions("org_zz", snap) == {}


def test_launch_positions_skip_jobs_that_name_no_launch():
    snap = _snap([FairJob("org_a", 1, "repo-x"), FairJob("org_a", 2, "cust_a", nonce="n")])
    assert launch_positions("org_a", snap) == {("cust_a", "n"): 1}   # the repo scan counts, but is not a launch


def _write_queue(root, pending=(), running=()):
    for sub, jobs in (("queue", pending), ("running", running)):
        (root / sub).mkdir(parents=True, exist_ok=True)
        for seq, tenant, slug, nonce in jobs:
            doc = {"slug": slug, "seed_url": "", "job_id": f"j{seq}", "seq": seq,
                   "params": {"tenant_id": tenant, "engagement_slug": slug, "extra": {"nonce": nonce}}}
            (root / sub / f"{seq:015d}.json").write_text(json.dumps(doc), encoding="utf-8")


def test_read_launch_positions_reads_the_engine_queue_layout(tmp_path):
    root = tmp_path / "jobs"
    _write_queue(root, pending=[(1, "org_a", "cust_a", "na"), (2, "org_b", "cust_b", "nb")],
                 running=[(0, "org_a", "cust_a0", "n0")])
    assert read_launch_positions("org_b", root=str(root)) == {("cust_b", "nb"): 0}
    assert read_launch_positions("org_a", root=str(root)) == {("cust_a", "na"): 1}


def test_read_launch_positions_defaults_to_the_launch_drain_queue_root(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path))
    _write_queue(tmp_path / "jobs", pending=[(5, "org_a", "cust_a", "na")])
    assert read_launch_positions("org_a") == {("cust_a", "na"): 0}


def test_no_queue_or_an_oversized_queue_shows_no_position(tmp_path, monkeypatch):
    import sigil.governor.fair_queue as fq
    assert read_launch_positions("org_a", root=str(tmp_path / "absent")) == {}
    root = tmp_path / "jobs"
    _write_queue(root, pending=[(i, "org_a", f"cust_{i}", f"n{i}") for i in range(4)])
    monkeypatch.setattr(fq, "SNAPSHOT_LIMIT", 3)
    assert read_launch_positions("org_a", root=str(root)) == {}


# -- claim discipline ---------------------------------------------------------------------------------------------

_MODEL_TOKENS = ("claude", "opus", "sonnet", "gpt", "anthropic", "model", "llm")


def test_surface_leaks_no_fact_or_model_identifier():
    pos = position_of([_it("A", 1, target="a")], tenant="A", target="a", seq=1, capacity=0)
    blob = repr(pos).lower()
    assert "fact" not in blob
    for tok in _MODEL_TOKENS:
        assert tok not in blob, f"model identifier {tok!r} leaked into a customer-facing position"
    # the server-side admission is items + the service history — no signing, no spine, no engine handle
    assert set(vars(Admission()).keys()) == {"admitted", "queued", "state"}
