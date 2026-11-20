"""Consumer PR-F — the TENANT-FAIR claim on the real engagement-scheduler claim path (``VIGIL_CUSTOMER_FAIR_QUEUE``).

The scheduler is THE dequeue of the production job queue (``SecurityJobQueue.claim_next`` → ``claim_next`` here →
``JobRunner.run_one``). These tests drive it the way a queue actually drains — one freed slot at a time — because
a fairness rule that only looks at the pending set reverts to arrival order under exactly that drain.

Pinned:
  * STREAMING FAIRNESS — a hog with jobs running cannot take the next slot from a latecomer; 50 jobs from 10
    tenants at one free slot per tick give every tenant its first slot within the first 10 claims; repeated claims
    alternate tenants instead of draining one tenant's backlog first;
  * PER-TENANT FIFO + SERIAL PER SLUG — a tenant's jobs keep their order; a job whose slug is running waits (and
    when every job waits, the claim still returns one so ``run_next`` reports the slug busy, as before);
  * CRASH SAFETY — ``requeue_stale`` is untouched; a torn state file costs history, never a claim; concurrent
    claimers never double-claim;
  * FLAG OFF ⇒ the arrival-order claim, byte-identical: same order, no ``fair/`` directory, the fair policy never
    even imported; the flag is read per claim.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import types

import pytest

from framework.v2.engagement_scheduler import EngagementScheduler
from framework.v2.slug_lease import SlugLease

_FLAG = "VIGIL_CUSTOMER_FAIR_QUEUE"


@pytest.fixture
def fair_on(monkeypatch):
    monkeypatch.setenv(_FLAG, "1")


@pytest.fixture
def fair_off(monkeypatch):
    monkeypatch.delenv(_FLAG, raising=False)


def _enq(sch: EngagementScheduler, tenant: str, slug: str, *, nonce: str = ""):
    """Enqueue a job shaped like a SecurityJob customer launch (``params.tenant_id`` + ``extra.nonce``)."""
    return sch.enqueue(slug, f"https://{slug}.example/", params={
        "tenant_id": tenant, "source": "api", "engagement_slug": slug, "extra": {"nonce": nonce or slug}})


def _tenant(job) -> str:
    return str((job.params or {}).get("tenant_id") or "")


def _drain_one_slot_per_tick(sch: EngagementScheduler, n: int) -> "list[str]":
    """Claim → run → complete one job per tick (a single free slot): the tenant of each claim, in order."""
    order: "list[str]" = []
    for _ in range(n):
        out = sch.run_next(lambda job: None)
        assert out.status == "ran", out
        order.append(_tenant(out.job))
    return order


# -- streaming fairness (each of these is RED on a stateless pending-set rank, i.e. arrival order) ---------------

def test_a_hog_with_jobs_running_cannot_take_the_latecomers_slot(tmp_path, fair_on):
    sch = EngagementScheduler(tmp_path / "q")
    for i in range(40):
        _enq(sch, "org_hog", f"hog{i:02d}")
    first, second = sch.claim_next(), sch.claim_next()      # the hog now has 2 jobs RUNNING and a 38-job backlog
    assert {_tenant(first), _tenant(second)} == {"org_hog"}
    _enq(sch, "org_late", "late00")                          # a single latecomer, sequence 40 — behind the backlog
    nxt = sch.claim_next()
    assert _tenant(nxt) == "org_late", "the hog's backlog was served before a tenant with nothing running"


def test_the_hog_case_is_arrival_order_with_the_flag_off(tmp_path, fair_off):
    # the same scenario, flag off: the arrival-order claim serves the hog's 3rd job (the gap this PR closes)
    sch = EngagementScheduler(tmp_path / "q")
    for i in range(40):
        _enq(sch, "org_hog", f"hog{i:02d}")
    sch.claim_next(), sch.claim_next()
    _enq(sch, "org_late", "late00")
    assert _tenant(sch.claim_next()) == "org_hog"


def test_fifty_jobs_from_ten_tenants_each_tenant_served_within_the_first_ten(tmp_path, fair_on):
    # the plan's acceptance case: 10 tenants enqueue 5 jobs each, in blocks; one free slot per tick.
    sch = EngagementScheduler(tmp_path / "q")
    tenants = [f"org_t{k}" for k in range(10)]
    for t in tenants:
        for i in range(5):
            _enq(sch, t, f"{t}-s{i}")
    order = _drain_one_slot_per_tick(sch, 50)
    first_slot = {t: order.index(t) for t in tenants}
    assert set(order[:10]) == set(tenants), f"a tenant waited behind another tenant's backlog: {order[:10]}"
    assert max(first_slot.values()) <= 9
    assert sorted(order) == sorted(t for t in tenants for _ in range(5))   # nothing lost, nothing doubled


def test_fifty_jobs_flag_off_shows_the_starvation_the_policy_removes(tmp_path, fair_off):
    sch = EngagementScheduler(tmp_path / "q")
    tenants = [f"org_t{k}" for k in range(10)]
    for t in tenants:
        for i in range(5):
            _enq(sch, t, f"{t}-s{i}")
    order = _drain_one_slot_per_tick(sch, 50)
    assert order.index("org_t9") == 45                       # arrival order: the last tenant waits behind 45 jobs


def test_repeated_claims_alternate_tenants_by_least_recent_service(tmp_path, fair_on):
    sch = EngagementScheduler(tmp_path / "q")
    for i in range(3):
        _enq(sch, "org_a", f"a{i}")
    for i in range(3):
        _enq(sch, "org_b", f"b{i}")
    assert _drain_one_slot_per_tick(sch, 6) == ["org_a", "org_b"] * 3


def test_fewest_running_wins_over_least_recent_service(tmp_path, fair_on):
    sch = EngagementScheduler(tmp_path / "q")
    _enq(sch, "org_a", "a0")
    _enq(sch, "org_a", "a1")
    _enq(sch, "org_b", "b0")
    _enq(sch, "org_b", "b1")
    a0 = sch.claim_next()                                    # org_a: 1 running
    b0 = sch.claim_next()                                    # org_b: 1 running (served after a)
    assert (_tenant(a0), _tenant(b0)) == ("org_a", "org_b")
    sch.complete(a0)                                         # org_a: 0 running, org_b still 1
    assert _tenant(sch.claim_next()) == "org_a"              # fewest running decides, not "a was served first"


def test_per_tenant_order_is_arrival_order(tmp_path, fair_on):
    sch = EngagementScheduler(tmp_path / "q")
    for i in range(4):
        _enq(sch, "org_a", f"a{i}")
    got = [sch.run_next(lambda j: None).job.slug for _ in range(4)]
    assert got == ["a0", "a1", "a2", "a3"]


# -- serial per slug ----------------------------------------------------------------------------------------

def test_a_job_whose_slug_is_running_waits_for_a_free_slug(tmp_path, fair_on):
    sch = EngagementScheduler(tmp_path / "q")
    _enq(sch, "org_a", "x", nonce="n1")
    _enq(sch, "org_a", "x", nonce="n2")                      # a second launch of the SAME target
    _enq(sch, "org_a", "z", nonce="n3")
    first = sch.claim_next()
    assert first.slug == "x"
    nxt = sch.claim_next()                                   # x is running: its second job waits, z goes
    assert nxt.slug == "z"


def test_when_every_job_waits_on_a_busy_slug_run_next_reports_busy_and_requeues(tmp_path, fair_on):
    root = tmp_path / "q"
    lease = SlugLease(root / "leases")
    sch = EngagementScheduler(root, lease=lease)
    _enq(sch, "org_a", "x", nonce="n1")
    _enq(sch, "org_a", "x", nonce="n2")
    first = sch.claim_next()                                 # x running (claimed, not completed)
    held = lease.acquire("x")
    assert held.ok
    out = sch.run_next(lambda j: pytest.fail("a busy slug must never run concurrently"))
    assert out.status == "busy" and out.job.slug == "x"      # a job came back (never a false "empty") ...
    assert [j.params["extra"]["nonce"] for j in sch.pending()] == ["n2"]   # ... and was requeued at its seq
    lease.release("x", held.token)
    sch.complete(first)


# -- crash safety / concurrency --------------------------------------------------------------------------------

def test_requeue_stale_is_unchanged_under_the_fair_claim(tmp_path, fair_on):
    sch = EngagementScheduler(tmp_path / "q")
    _enq(sch, "org_a", "a0")
    job = sch.claim_next()
    path = sch.running / sch._name(job.seq)
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["_claimer"] = {"pid": 2_147_483_600, "boot_id": "old", "ts": 0}   # a crashed worker (as the FIFO suite)
    path.write_text(json.dumps(doc), encoding="utf-8")
    assert sch.requeue_stale() == 1
    assert sch.claim_next().seq == job.seq                   # recovered and claimable again


def test_a_torn_state_file_costs_history_not_the_claim(tmp_path, fair_on):
    sch = EngagementScheduler(tmp_path / "q")
    _enq(sch, "org_a", "a0")
    _enq(sch, "org_b", "b0")
    sch.run_next(lambda j: None)
    (tmp_path / "q" / "fair" / "state.json").write_text("{not json", encoding="utf-8")
    out = sch.run_next(lambda j: None)
    assert out.status == "ran" and _tenant(out.job) == "org_b"
    state = json.loads((tmp_path / "q" / "fair" / "state.json").read_text(encoding="utf-8"))
    assert state["v"] == 1 and "org_b" in state["served"]


def test_concurrent_fair_claimers_never_double_claim(tmp_path, fair_on):
    sch = EngagementScheduler(tmp_path / "q")
    for t in ("org_a", "org_b", "org_c"):
        for i in range(10):
            _enq(sch, t, f"{t}-{i}")
    claimed: "list[int]" = []
    lock = threading.Lock()

    def worker():
        mine = EngagementScheduler(tmp_path / "q")
        while True:
            job = mine.claim_next()
            if job is None:
                return
            with lock:
                claimed.append(job.seq)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for th in threads:
        th.start()
    for th in threads:
        th.join(timeout=60)
    assert sorted(claimed) == sorted(set(claimed)) and len(claimed) == 30   # each job exactly once


def test_the_state_stays_one_entry_per_live_tenant(tmp_path, fair_on):
    sch = EngagementScheduler(tmp_path / "q")
    _enq(sch, "org_a", "a0")
    sch.run_next(lambda j: None)                             # org_a done, nothing left for it
    _enq(sch, "org_b", "b0")
    sch.run_next(lambda j: None)
    state = json.loads((tmp_path / "q" / "fair" / "state.json").read_text(encoding="utf-8"))
    assert set(state["served"]) == {"org_b"} and state["tick"] == 2   # org_a pruned once it had nothing live


# -- the on-disk format both planes read (the sovereign "queued" surface parses these very files) ---------------

def test_the_snapshot_reader_parses_the_files_this_scheduler_writes(tmp_path, fair_on):
    from vigil_core.fair_share import FairJob, read_queue_snapshot
    sch = EngagementScheduler(tmp_path / "q")
    a = _enq(sch, "org_a", "cust_a", nonce="na")
    b = _enq(sch, "org_b", "cust_b", nonce="nb")
    fleet = sch.enqueue("fleet1", params={"tenant": "org_f"})         # make_fleet_runner's "tenant" convention
    sch.claim_next()                                                 # org_a's job is running now
    snap = read_queue_snapshot(tmp_path / "q")
    assert snap.running == (FairJob(tenant="org_a", seq=a.seq, slug="cust_a", job_id=a.job_id, nonce="na"),)
    assert snap.pending == (FairJob(tenant="org_b", seq=b.seq, slug="cust_b", job_id=b.job_id, nonce="nb"),
                            FairJob(tenant="org_f", seq=fleet.seq, slug="fleet1", job_id=fleet.job_id))
    assert snap.state.served_map() == {"org_a": 1}


# -- flag OFF ⇒ byte-identical ----------------------------------------------------------------------------------

def test_flag_off_never_imports_the_policy_and_creates_no_fair_state(tmp_path, fair_off, monkeypatch):
    poisoned = types.ModuleType("vigil_core.fair_share")

    def _boom(name):
        raise AssertionError(f"flag OFF touched the fair policy ({name})")

    poisoned.__getattr__ = _boom                     # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "vigil_core.fair_share", poisoned)
    sch = EngagementScheduler(tmp_path / "q")
    for t, s in (("org_a", "a0"), ("org_a", "a1"), ("org_b", "b0")):
        _enq(sch, t, s)
    got = [sch.run_next(lambda j: None).job.slug for _ in range(3)]
    assert got == ["a0", "a1", "b0"]                                  # strict arrival order
    assert sorted(os.listdir(tmp_path / "q")) == ["done", "leases", "queue", "running"]   # no fair/ dir


def test_the_flag_is_read_per_claim(tmp_path, monkeypatch):
    sch = EngagementScheduler(tmp_path / "q")
    for s in ("a0", "a1", "a2"):
        _enq(sch, "org_a", s)
    _enq(sch, "org_b", "b0")
    monkeypatch.setenv(_FLAG, "yes")
    assert sch.run_next(lambda j: None).job.slug == "a0"             # no history yet: the oldest head
    monkeypatch.delenv(_FLAG, raising=False)
    assert sch.run_next(lambda j: None).job.slug == "a1"             # OFF at THIS claim: arrival order (fair = b0)
    monkeypatch.setenv(_FLAG, "on")
    assert sch.run_next(lambda j: None).job.slug == "b0"             # ON again: org_b was never served
