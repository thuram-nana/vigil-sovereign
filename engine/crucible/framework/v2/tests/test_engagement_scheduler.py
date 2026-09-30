"""D1 — the engagement scheduler above the run boundary: durable, ordered, crash-safe, per-slug exclusive.

Proves:
  * ordering — enqueue is FIFO and claim/dequeue returns jobs in enqueue order;
  * per-slug exclusivity — while a slug is leased (a live engagement of it) its queued job is deferred, not
    run concurrently, and its FIFO position is preserved for the retry;
  * crash recovery — a job whose claiming worker died is requeued;
  * the run boundary — run_next acquires+releases the slug lease around the runner, and the default runner
    forwards to run_engagement.
"""
from __future__ import annotations

import sys
import types

from framework.v2.engagement_scheduler import (
    EngagementJob,
    EngagementScheduler,
    default_engagement_runner,
)
from framework.v2.slug_lease import SlugLease


def test_enqueue_and_dequeue_are_fifo(tmp_path):
    sch = EngagementScheduler(tmp_path / "sched")
    j1 = sch.enqueue("s1", "http://127.0.0.1/1")
    j2 = sch.enqueue("s2", "http://127.0.0.1/2")
    j3 = sch.enqueue("s3", "http://127.0.0.1/3")
    assert [j.seq for j in (j1, j2, j3)] == sorted(j.seq for j in (j1, j2, j3))
    assert j1.seq < j2.seq < j3.seq                      # strictly monotonic
    assert [j.slug for j in sch.pending()] == ["s1", "s2", "s3"]
    # claim in order
    assert sch.claim_next().slug == "s1"
    assert sch.claim_next().slug == "s2"
    assert sch.claim_next().slug == "s3"
    assert sch.claim_next() is None                      # queue drained


def test_run_next_runs_in_order_and_records_done(tmp_path):
    sch = EngagementScheduler(tmp_path / "sched")
    for i in range(4):
        sch.enqueue(f"slug{i}", f"http://127.0.0.1/{i}")
    ran: list[str] = []
    outcomes = sch.drain(lambda job: ran.append(job.slug))
    assert ran == ["slug0", "slug1", "slug2", "slug3"]   # strict FIFO execution
    assert all(o.status == "ran" for o in outcomes)
    assert sch.pending() == []
    # every job is recorded in done/ (audit trail)
    assert len(list((tmp_path / "sched" / "done").iterdir())) == 4


def test_a_busy_slug_defers_its_job_and_preserves_fifo(tmp_path):
    root = tmp_path / "sched"
    lease = SlugLease(root / "leases")
    sch = EngagementScheduler(root, lease=lease)
    sch.enqueue("dup", "http://127.0.0.1/a")             # head
    sch.enqueue("other", "http://127.0.0.1/b")
    # simulate a live engagement of "dup" already holding the lease (a concurrent run of that slug)
    held = lease.acquire("dup")
    assert held.ok is True
    ran: list[str] = []
    out = sch.run_next(lambda job: ran.append(job.slug))
    assert out.status == "busy" and out.job.slug == "dup"
    assert ran == []                                     # the busy slug did NOT run concurrently
    assert [j.slug for j in sch.pending()] == ["dup", "other"]   # FIFO position preserved
    # free the slug → the deferred job now runs, still ahead of "other"
    assert lease.release("dup", held.token) is True
    out2 = sch.run_next(lambda job: ran.append(job.slug))
    assert out2.status == "ran" and ran == ["dup"]


def test_run_next_releases_the_lease_even_if_the_runner_raises(tmp_path):
    root = tmp_path / "sched"
    lease = SlugLease(root / "leases")
    sch = EngagementScheduler(root, lease=lease)
    sch.enqueue("boom", "http://127.0.0.1/x")

    def _explode(job):
        raise RuntimeError("kaboom")

    out = sch.run_next(_explode)
    assert out.status == "ran" and "kaboom" in out.error
    assert lease.is_held("boom") is False                # the lease was released despite the raise
    # a follow-up engagement of the slug can proceed
    assert lease.acquire("boom").ok is True


def test_requeue_stale_recovers_a_crashed_workers_job(tmp_path):
    root = tmp_path / "sched"
    sch = EngagementScheduler(root)
    job = sch.enqueue("orphan", "http://127.0.0.1/o")
    claimed = sch.claim_next()                           # moves queue/ -> running/ and stamps THIS pid
    assert claimed.slug == "orphan"
    # rewrite the running record so its claimer is a DEAD pid (a crashed worker)
    running_file = sch.running / sch._name(job.seq)
    import json
    doc = json.loads(running_file.read_text(encoding="utf-8"))
    doc["_claimer"] = {"pid": 2_147_483_600, "boot_id": "old", "ts": 0}
    running_file.write_text(json.dumps(doc), encoding="utf-8")
    assert sch.requeue_stale() == 1                      # the crashed job is recovered
    assert [j.slug for j in sch.pending()] == ["orphan"]
    assert sch.claim_next().seq == job.seq               # same job, same FIFO sequence


def test_enqueue_rejects_an_empty_slug(tmp_path):
    sch = EngagementScheduler(tmp_path / "sched")
    import pytest
    with pytest.raises(ValueError):
        sch.enqueue("")


def test_default_runner_forwards_to_run_engagement(tmp_path, monkeypatch):
    # tie the scheduler to the run boundary WITHOUT importing the heavy engine: inject a fake engage module.
    calls: list[tuple] = []
    fake = types.ModuleType("framework.v2.engage")
    fake.run_engagement = lambda slug, seed, **kw: calls.append((slug, seed, kw)) or "RESULT"  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "framework.v2.engage", fake)
    job = EngagementJob(slug="s", seed_url="http://127.0.0.1/", params={"max_pages": 3})
    assert default_engagement_runner(job) == "RESULT"
    assert calls == [("s", "http://127.0.0.1/", {"max_pages": 3})]
