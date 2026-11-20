"""vigil_core.fair_share — the ONE tenant-fair claim policy both planes use (consumer PR-F, plan Area 5).

Pinned:
  * the decision — fewest running, then least recent service, then the oldest head; per-tenant FIFO; a job whose
    slug is running waits; the plain fair order only when every job waits (never a false "empty");
  * STATEFUL fairness under a streaming drain (one freed slot at a time) — the case a pending-set-only rank gets
    wrong: a hog with jobs running, 50 jobs from 10 tenants at one slot per tick, repeated single-slot claims;
  * ``claim_order`` (the heap) equals ``choose`` applied repeatedly (randomised property, fixed seeds);
  * the state codec and the on-disk reader are total over torn / hostile input and bounded.
"""
from __future__ import annotations

import json
import os
import random

import pytest

from vigil_core.fair_share import (
    FAIR_DIR, QUEUE_DIR, RUNNING_DIR, STATE_NAME, FairJob, FairState, QueueSnapshot, busy_slugs, choose,
    claim_order, dump_state, job_from_doc, load_state, parse_state, pick_next, read_queue_snapshot, record_service,
    running_counts, scan_job_dir,
)


def J(tenant, seq, slug="", job_id="", nonce=""):
    return FairJob(tenant=tenant, seq=seq, slug=slug or f"{tenant}-{seq}", job_id=job_id, nonce=nonce)


# -- the decision -----------------------------------------------------------------------------------------------

def test_empty_queue_picks_nothing():
    assert pick_next([]) is None and choose([]) is None and claim_order([]) == []


def test_fewest_running_tenant_is_served_first():
    pending = [J("a", 1), J("b", 2)]
    assert choose(pending, running=[J("a", 0)]).tenant == "b"


def test_least_recent_service_breaks_an_equal_running_count():
    pending = [J("a", 1), J("b", 2)]
    st = record_service(record_service(None, "b"), "a")      # b served at tick 1, a at tick 2
    assert choose(pending, state=st).tenant == "b"


def test_a_never_served_tenant_beats_a_served_one():
    pending = [J("a", 1), J("b", 2)]
    assert choose(pending, state=record_service(None, "a")).tenant == "b"


def test_the_oldest_head_breaks_a_full_tie_and_per_tenant_order_is_arrival_order():
    pending = [J("b", 7), J("a", 9), J("a", 3)]
    assert choose(pending) == J("a", 3)
    assert [j.seq for j in claim_order([J("a", 5), J("a", 1), J("a", 3)])] == [1, 3, 5]


def test_a_job_whose_slug_is_running_waits_but_another_target_of_the_tenant_goes():
    pending = [J("a", 1, slug="x"), J("a", 2, slug="z")]
    assert choose(pending, running=[J("a", 0, slug="x")]) == J("a", 2, slug="z")
    assert pick_next(pending, [J("a", 0, slug="x")], serial=False) == J("a", 1, slug="x")


def test_when_every_job_waits_the_claim_still_returns_one():
    pending = [J("a", 1, slug="x")]
    running = [J("a", 0, slug="x")]
    assert pick_next(pending, running) is None               # nothing free ...
    assert choose(pending, running) == J("a", 1, slug="x")   # ... but the claimer is never told "empty"


def test_an_empty_slug_is_never_busy():
    assert busy_slugs([FairJob("a", 0)]) == set()
    assert pick_next([FairJob("a", 1)], [FairJob("a", 0)]) == FairJob("a", 1)   # the serial pick, not the fallback


def test_the_decision_is_pure_and_deterministic():
    pending = [J("b", 2), J("a", 1), J("c", 3)]
    snapshot = list(pending)
    first = claim_order(pending, [J("a", 0)], record_service(None, "c"))
    assert first == claim_order(tuple(pending), (J("a", 0),), record_service(None, "c"))
    assert pending == snapshot                                # inputs untouched


def test_running_counts():
    assert running_counts([J("a", 1), J("a", 2), J("b", 3)]) == {"a": 2, "b": 1}


# -- STATEFUL fairness under a streaming drain ------------------------------------------------------------------

def _drain(pending, *, slots, running=(), state=None):
    """Simulate a queue draining one freed slot at a time: fill free slots with ``choose``, then finish the OLDEST
    running job, repeat. Returns the claim order (tenants)."""
    pending, running, st, order = list(pending), list(running), state, []
    while pending:
        while pending and len(running) < slots:
            nxt = choose(pending, running, st)
            pending.remove(nxt)
            running.append(nxt)
            live = {j.tenant for j in pending} | {j.tenant for j in running}
            st = record_service(st, nxt.tenant, live=live)
            order.append(nxt.tenant)
        running.pop(0)
    return order


def test_a_hog_with_g_running_cannot_take_the_latecomers_slot():
    hog_running = [J("hog", i) for i in range(2)]
    backlog = [J("hog", i) for i in range(2, 40)]
    late = J("late", 1000)
    # one slot frees: the latecomer, not the 3rd of the hog's 40
    assert choose(backlog + [late], hog_running, record_service(record_service(None, "hog"), "hog")) == late
    assert _drain(backlog + [late], slots=3, running=hog_running)[0] == "late"


def test_fifty_jobs_ten_tenants_one_slot_per_tick_every_tenant_within_the_first_ten():
    tenants = [f"t{k}" for k in range(10)]
    pending = [J(t, 5 * k + i) for k, t in enumerate(tenants) for i in range(5)]
    order = _drain(pending, slots=1)
    assert set(order[:10]) == set(tenants), order[:10]
    assert order == tenants * 5                               # strict round-robin while every tenant is backlogged


def test_repeated_single_slot_claims_alternate_tenants():
    assert _drain([J("a", 1), J("a", 2), J("b", 3)], slots=1) == ["a", "b", "a"]


def test_a_flood_cannot_starve_a_single_launch_from_a_cold_start():
    order = claim_order([J("a", i) for i in range(1, 101)] + [J("b", 101)])
    assert [j.tenant for j in order].index("b") == 1


# -- claim_order == choose applied repeatedly ------------------------------------------------------------------

def _naive_order(pending, running, state):
    pending, running, st, out = list(pending), list(running), state, []
    while pending:
        nxt = choose(pending, running, st)
        pending.remove(nxt)
        running.append(nxt)
        st = record_service(st, nxt.tenant)
        out.append(nxt)
    return out


@pytest.mark.parametrize("seed", range(40))
def test_claim_order_equals_naive_repeated_choose(seed):
    rnd = random.Random(seed)
    tenants = [f"o{k}" for k in range(rnd.randint(1, 6))]
    slugs = [f"s{k}" for k in range(rnd.randint(1, 8))]          # few slugs ⇒ plenty of serial waiting + sharing

    def job(seq):
        return FairJob(tenant=rnd.choice(tenants), seq=seq, slug=rnd.choice(slugs + [""]),
                       job_id=f"j{rnd.randint(0, 3)}")

    seqs = rnd.sample(range(1000), rnd.randint(0, 40))
    pending = [job(s) for s in seqs[: len(seqs) * 3 // 4]]
    running = [job(s) for s in seqs[len(seqs) * 3 // 4:]]
    st = FairState()
    for t in rnd.sample(tenants, rnd.randint(0, len(tenants))):
        st = record_service(st, t)
    assert claim_order(pending, running, st) == _naive_order(pending, running, st)
    if pending:
        assert claim_order(pending, running, st)[0] == choose(pending, running, st)


# -- record_service / the state codec ---------------------------------------------------------------------------

def test_record_service_advances_the_tick_and_prunes_dead_tenants():
    st = record_service(record_service(None, "a"), "b")
    assert st.tick == 2 and st.served_map() == {"a": 1, "b": 2}
    st = record_service(st, "c", live={"c", "b"})
    assert st.served_map() == {"b": 2, "c": 3}                   # a had nothing live: pruned
    assert record_service(st, "z", live=()).served_map() == {"z": 4}


def test_state_round_trips_through_its_codec():
    st = record_service(record_service(None, "a"), "b")
    assert parse_state(json.loads(dump_state(st))) == st


@pytest.mark.parametrize("raw", [None, [], "x", {"tick": "9"}, {"served": [1]}, {"tick": -3, "served": {}}])
def test_a_malformed_state_degrades_to_empty(raw):
    assert parse_state(raw) == FairState(tick=0, served=())


def test_a_partly_hostile_state_keeps_only_the_sound_entries_and_a_monotonic_tick():
    st = parse_state({"tick": 2, "served": {"a": 5, "b": -1, "c": True, "d": "7", 9: 1, "x" * 999: 3}})
    assert st.served_map() == {"a": 5} and st.tick == 5


def test_load_state_is_total(tmp_path):
    assert load_state(tmp_path / "absent.json") == FairState()
    (tmp_path / "torn.json").write_text("{", encoding="utf-8")
    assert load_state(tmp_path / "torn.json") == FairState()
    good = tmp_path / "good.json"
    good.write_text(dump_state(record_service(None, "a")), encoding="utf-8")
    os.symlink(good, tmp_path / "link.json")
    assert load_state(tmp_path / "link.json") == FairState()        # never through a symlink
    assert load_state(good).served_map() == {"a": 1}
    (tmp_path / "huge.json").write_bytes(b" " * (4 * 1024 * 1024 + 1))
    assert load_state(tmp_path / "huge.json") == FairState()        # bounded


# -- the on-disk reader -----------------------------------------------------------------------------------------

def _engine_job(slug, seq, *, tenant_key="tenant_id", tenant="org_a", nonce="n1", job_id="abc"):
    """A queue file exactly as framework.v2.engagement_scheduler.EngagementJob.to_json writes it."""
    params = {tenant_key: tenant, "source": "api", "engagement_slug": slug, "extra": {"nonce": nonce}}
    return json.dumps({"slug": slug, "seed_url": "", "params": params, "job_id": job_id, "seq": seq}, sort_keys=True)


def test_job_from_doc_reads_the_engine_shape_and_degrades_hostile_documents():
    assert job_from_doc(json.loads(_engine_job("cust_x", 4)), 4) == FairJob("org_a", 4, "cust_x", "abc", "n1")
    assert job_from_doc(json.loads(_engine_job("f", 2, tenant_key="tenant", tenant="org_f")), 2).tenant == "org_f"
    for bad in (None, [], "x", {"params": "nope", "slug": 5, "job_id": {}}):
        assert job_from_doc(bad, 3) == FairJob("", 3)
    assert job_from_doc({"params": {"tenant_id": "t" * 9999}}, 1).tenant == "t" * 256   # clipped


def _queue_root(tmp_path, pending=(), running=(), state=None):
    root = tmp_path / "jobs"
    for sub in (QUEUE_DIR, RUNNING_DIR):
        (root / sub).mkdir(parents=True)
    for seq, body in pending:
        (root / QUEUE_DIR / f"{seq:015d}.json").write_text(body, encoding="utf-8")
    for seq, body in running:
        (root / RUNNING_DIR / f"{seq:015d}.json").write_text(body, encoding="utf-8")
    if state is not None:
        (root / FAIR_DIR).mkdir()
        (root / FAIR_DIR / STATE_NAME).write_text(dump_state(state), encoding="utf-8")
    return root


def test_read_queue_snapshot_reads_pending_running_and_state(tmp_path):
    root = _queue_root(tmp_path, pending=[(2, _engine_job("cust_b", 2, tenant="org_b", nonce="nb")),
                                          (1, _engine_job("cust_a", 1, nonce="na"))],
                       running=[(0, _engine_job("cust_a", 0, nonce="n0"))], state=record_service(None, "org_a"))
    (root / QUEUE_DIR / "not-a-job.txt").write_text("x", encoding="utf-8")       # ignored
    snap = read_queue_snapshot(root)
    assert [j.seq for j in snap.pending] == [1, 2]
    assert snap.running == (FairJob("org_a", 0, "cust_a", "abc", "n0"),)
    assert snap.state.served_map() == {"org_a": 1}


def test_a_torn_job_file_is_an_anonymous_claimable_job(tmp_path):
    root = _queue_root(tmp_path, pending=[(3, "{torn")])
    assert read_queue_snapshot(root).pending == (FairJob("", 3),)


def test_the_reader_never_follows_a_symlinked_job(tmp_path):
    root = _queue_root(tmp_path)
    secret = tmp_path / "secret.json"
    secret.write_text(_engine_job("cust_s", 9, tenant="org_secret"), encoding="utf-8")
    os.symlink(secret, root / QUEUE_DIR / f"{9:015d}.json")
    assert read_queue_snapshot(root).pending == (FairJob("", 9),)


def test_no_queue_or_an_oversized_queue_gives_no_snapshot(tmp_path):
    assert read_queue_snapshot(tmp_path / "nowhere") is None
    root = _queue_root(tmp_path, pending=[(i, _engine_job(f"s{i}", i)) for i in range(5)])
    assert read_queue_snapshot(root, limit=4) is None                 # never a guessed position
    assert len(read_queue_snapshot(root, limit=5).pending) == 5
    assert scan_job_dir(tmp_path / "absent") == []
    assert scan_job_dir(root / QUEUE_DIR, limit=4) is None


def test_snapshot_defaults_are_empty():
    snap = QueueSnapshot()
    assert snap.pending == () and snap.running == () and snap.state == FairState()
