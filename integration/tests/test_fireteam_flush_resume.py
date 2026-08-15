"""
Net-new checkpoint: fireteam per-member spine flush + wave resume.

Proves the three slice guarantees against the real orchestrator / spine-queue / progress-store:

  (a) PERSIST — each member's spine records are flushed the instant that member completes (not only after
      ``gather``), and each completed member is recorded in the :class:`WaveProgressStore`.
  (b) RESUME  — a re-run of the same ``wave_id`` SKIPS already-completed members (never re-executing them
      or re-writing their spine records) and CONTINUES the members that had not finished.
  (c) FAIL-OPEN — a flush/progress failure (unwritable store, corrupt store, a writer that raises, a hard
      crash mid-wave) never breaks the wave; a member whose records were lost is re-run, never skipped.

The end-to-end test simulates a genuine process crash mid-wave (a ``BaseException`` that escapes the
per-member ``except Exception`` isolation, exactly as a real ``kill -9`` would escape it) and then resumes
in a FRESH spine queue (a fresh process) over a DURABLE spine sink + a DURABLE progress file — the real
crash-recovery shape.
"""

from __future__ import annotations

import asyncio
import json
import os

import pytest

from vigil_integration.agent import ActionType, Finding, LLMDecision, OutputAnalysis, ToolCall
from vigil_integration.fireteam import (
    MemberFindingClaim,
    MemberResult,
    MemberStatus,
    SingleWriterSpineQueue,
    WaveProgressStore,
    run_fireteam,
)
from vigil_integration.fireteam.wave_progress import MemberProgress


# --- helpers ------------------------------------------------------------------------------------

def _durable_writer(sink: list):
    """A spine writer backed by a list that PERSISTS across (simulated) process restarts — a stand-in for
    the real append-only signed spine. Returns a stable, unique ref per appended record."""

    def writer(rec):
        ref = f"ref-{rec['member_id']}-{rec['seq']}-{len(sink)}"
        sink.append(dict(rec))
        return ref

    return writer


def _writing_runner(calls: list):
    """A member runner that records its invocation and submits ONE spine record, then returns a lead."""

    def runner(member, ctx):
        calls.append(member.member_id)
        if ctx.spine is not None:
            ctx.spine.submit(member_id=member.member_id, seq=ctx.seq, kind="step",
                             record={"m": member.member_id})
        return MemberResult(member_id=member.member_id, status=MemberStatus.SUCCESS,
                            leads=[Finding(ref=f"f-{member.member_id}", title=f"lead {member.member_id}")])

    return runner


_PLAN = {"wave_id": "wave-1", "members": [{"member_id": "a", "tools": ["nmap"]},
                                          {"member_id": "b", "tools": ["dirb"]}]}


# --- (a) PERSIST --------------------------------------------------------------------------------

def test_checkpoint_persists_each_member_as_it_completes(tmp_path):
    """After a clean wave, every member's spine record is durably written AND every member is recorded in
    the progress store with its result + refs."""
    sink: list = []
    calls: list = []
    store = WaveProgressStore(tmp_path / "progress.json")
    q = SingleWriterSpineQueue(_durable_writer(sink))

    out = asyncio.run(run_fireteam(_PLAN, _writing_runner(calls), spine=q, progress=store,
                                   max_concurrent=2))

    assert not out.refused
    assert sorted(calls) == ["a", "b"]                       # both ran once
    assert {rec["member_id"] for rec in sink} == {"a", "b"}  # both records reached the durable spine
    assert len(out.spine_refs) == 2

    # the progress store persisted BOTH members, each with a result and its flushed refs
    done = store.completed("wave-1")
    assert set(done) == {"a", "b"}
    assert all(isinstance(v, MemberProgress) for v in done.values())
    assert done["a"].result.member_id == "a" and done["a"].result.leads[0].ref == "f-a"
    assert len(done["a"].refs) == 1 and done["a"].refs[0].startswith("ref-a-")

    # the on-disk document is real JSON with the expected shape (a checkpoint records STATE)
    doc = json.loads((tmp_path / "progress.json").read_text())
    assert set(doc["waves"]["wave-1"]["members"]) == {"a", "b"}


# --- (b) RESUME: skips done, continues the rest -------------------------------------------------

def test_resume_skips_completed_members_and_runs_the_rest(tmp_path):
    """Pre-seed the store as if member 'a' finished on a prior run that then died. A resume over the full
    plan must SKIP 'a' (not re-run, not re-written to the spine) and RUN only 'b'."""
    sink: list = []
    store = WaveProgressStore(tmp_path / "progress.json")

    # simulate "run 1 completed 'a' then the process crashed before 'b'": record 'a' directly + put its
    # record on the durable spine (as the completed run would have).
    a_ref = _durable_writer(sink)({"member_id": "a", "seq": 0, "kind": "step", "m": "a"})
    ok = store.record("wave-1", "a",
                      MemberResult(member_id="a", status=MemberStatus.SUCCESS,
                                   leads=[Finding(ref="f-a", title="lead a")]),
                      refs=[a_ref])
    assert ok is True

    calls: list = []
    q2 = SingleWriterSpineQueue(_durable_writer(sink))     # a FRESH queue = a fresh process
    out = asyncio.run(run_fireteam(_PLAN, _writing_runner(calls), spine=q2, progress=store,
                                   max_concurrent=1))

    assert calls == ["b"]                                   # 'a' SKIPPED, only 'b' re-run
    ids = [r.member_id for r in out.member_results]
    assert ids == ["a", "b"]                                # plan order preserved, 'a' restored
    # 'a' was NOT re-written to the durable spine (its one record from run 1 is still the only one)
    assert [rec["member_id"] for rec in sink].count("a") == 1
    assert [rec["member_id"] for rec in sink].count("b") == 1
    # outcome refs = 'a' restored + 'b' fresh; each member's lead appears exactly once (no double-count)
    assert len(out.spine_refs) == 2
    assert len(out.leads) == 2
    assert sorted(l.ref for l in out.leads) == ["f-a", "f-b"]              # ref preserved from each member
    assert {l.source for l in out.leads} == {"wave-1:a", "wave-1:b"}      # attributed to its member/wave


def test_resume_all_done_runs_nothing(tmp_path):
    """If every member is already recorded, a resume runs NO member yet still returns the full restored
    outcome in plan order."""
    store = WaveProgressStore(tmp_path / "progress.json")
    for mid in ("a", "b"):
        store.record("wave-1", mid,
                     MemberResult(member_id=mid, leads=[Finding(ref=f"f-{mid}")]), refs=[f"r-{mid}"])

    calls: list = []
    out = asyncio.run(run_fireteam(_PLAN, _writing_runner(calls), spine=SingleWriterSpineQueue(lambda r: "x"),
                                   progress=store, max_concurrent=2))
    assert calls == []                                      # nothing re-run
    assert [r.member_id for r in out.member_results] == ["a", "b"]
    assert out.spine_refs == ["r-a", "r-b"]                 # restored refs, plan order


def test_resume_is_idempotent_no_double_execute_end_to_end(tmp_path):
    """Full crash→resume flow with a durable spine + progress file. A hard crash mid-wave keeps the
    finished member's records; the resume runs the survivor exactly once. Across BOTH runs each member's
    runner fires exactly once and each spine record appears exactly once."""
    sink: list = []
    store = WaveProgressStore(tmp_path / "progress.json")
    all_calls: list = []

    # RUN 1 — serial so 'a' fully completes (flush + record) before 'b' hard-crashes the process.
    def crashing_runner(member, ctx):
        all_calls.append(member.member_id)
        if member.member_id == "b":
            raise KeyboardInterrupt("simulated kill -9 mid-wave")   # escapes `except Exception`
        ctx.spine.submit(member_id=member.member_id, seq=ctx.seq, kind="step", record={"m": member.member_id})
        return MemberResult(member_id=member.member_id, leads=[Finding(ref=f"f-{member.member_id}")])

    q1 = SingleWriterSpineQueue(_durable_writer(sink))
    with pytest.raises(BaseException):     # noqa: PT011 — the crash propagates, modelling process death
        asyncio.run(run_fireteam(_PLAN, crashing_runner, spine=q1, progress=store, max_concurrent=1))

    # 'a' finished BEFORE the crash → its record is on the durable spine and it is checkpointed.
    assert [rec["member_id"] for rec in sink] == ["a"]      # crash-durability: 'a' survived
    assert set(store.completed("wave-1")) == {"a"}          # 'b' never recorded (it crashed)

    # RUN 2 (resume, fresh process/queue, same durable sink + store) — normal runner over the full plan.
    resume_calls: list = []
    q2 = SingleWriterSpineQueue(_durable_writer(sink))
    out = asyncio.run(run_fireteam(_PLAN, _writing_runner(resume_calls), spine=q2, progress=store,
                                   max_concurrent=1))

    assert resume_calls == ["b"]                            # only the survivor re-runs
    assert all_calls == ["a", "b"]                          # across both runs: 'a' once, 'b' once (crash)
    assert [rec["member_id"] for rec in sink] == ["a", "b"] # each record on the spine exactly once
    assert [r.member_id for r in out.member_results] == ["a", "b"]
    assert len(out.leads) == 2                              # no double-count at fan-in


# --- (c) FAIL-OPEN ------------------------------------------------------------------------------

def test_unwritable_progress_store_never_breaks_the_wave(tmp_path):
    """A progress path that cannot be written (it is a DIRECTORY) makes every record() a no-op, but the
    wave still runs to completion and returns a full outcome."""
    bad = tmp_path / "iam-a-dir"
    os.makedirs(bad)
    store = WaveProgressStore(bad)                          # os.replace onto a dir will fail → fail-open
    assert store.record("wave-1", "a", MemberResult(member_id="a")) is False

    calls: list = []
    q = SingleWriterSpineQueue(_durable_writer([]))
    out = asyncio.run(run_fireteam(_PLAN, _writing_runner(calls), spine=q, progress=store))
    assert not out.refused and sorted(calls) == ["a", "b"]  # the wave completed despite the dead store
    assert store.completed("wave-1") == {}                  # nothing was (or could be) recorded


def test_corrupt_progress_store_fails_open_to_full_rerun(tmp_path):
    """A corrupt checkpoint file loads as 'nothing done' — the wave re-runs everyone, never raises, never
    wrongly skips a member."""
    p = tmp_path / "progress.json"
    p.write_text("{ this is not json ]]]")
    store = WaveProgressStore(p)
    assert store.completed("wave-1") == {}                  # fail-open read

    calls: list = []
    out = asyncio.run(run_fireteam(_PLAN, _writing_runner(calls),
                                   spine=SingleWriterSpineQueue(_durable_writer([])), progress=store))
    assert not out.refused and sorted(calls) == ["a", "b"]


def test_flush_failure_leaves_member_uncheckpointed_so_it_reruns(tmp_path):
    """If a member's spine write is DROPPED (the writer raises for it), that member must NOT be recorded —
    so on resume it is re-run (its lost record re-written), never skipped-without-durable-records."""
    store = WaveProgressStore(tmp_path / "progress.json")

    def writer_that_hates_a(rec):
        if rec["member_id"] == "a":
            raise RuntimeError("spine write failed for a")
        return f"ref-{rec['member_id']}-{rec['seq']}"

    calls: list = []
    q = SingleWriterSpineQueue(writer_that_hates_a)
    out = asyncio.run(run_fireteam(_PLAN, _writing_runner(calls), spine=q, progress=store,
                                   max_concurrent=1))
    assert not out.refused and sorted(calls) == ["a", "b"]  # the wave still completes (fail-open)

    done = store.completed("wave-1")
    assert "b" in done                                      # 'b' flushed fine → checkpointed
    assert "a" not in done                                  # 'a' write dropped → NOT checkpointed

    # resume: 'a' (whose record was lost) re-runs; 'b' is skipped.
    resume_calls: list = []
    q2 = SingleWriterSpineQueue(lambda rec: f"ref-{rec['member_id']}-{rec['seq']}")   # now 'a' writes ok
    out2 = asyncio.run(run_fireteam(_PLAN, _writing_runner(resume_calls), spine=q2, progress=store,
                                    max_concurrent=1))
    assert resume_calls == ["a"]                            # only the un-checkpointed member re-runs


def test_progress_none_still_flushes_per_member(tmp_path):
    """With NO progress store wired, per-member flush still happens (durability without resume): a crash
    after some members finish keeps their records."""
    sink: list = []
    all_calls: list = []

    def crashing_runner(member, ctx):
        all_calls.append(member.member_id)
        if member.member_id == "b":
            raise KeyboardInterrupt("crash")
        ctx.spine.submit(member_id=member.member_id, seq=ctx.seq, kind="step", record={"m": member.member_id})
        return MemberResult(member_id=member.member_id)

    q = SingleWriterSpineQueue(_durable_writer(sink))
    with pytest.raises(BaseException):     # noqa: PT011
        asyncio.run(run_fireteam(_PLAN, crashing_runner, spine=q, progress=None, max_concurrent=1))
    assert [rec["member_id"] for rec in sink] == ["a"]      # 'a' flushed on completion, before the crash


# --- spine_queue.flush_member unit proofs -------------------------------------------------------

def test_flush_member_drains_only_that_member():
    """flush_member writes ONLY the named member's records (deterministic (seq, kind) order), leaves the
    others buffered, and returns just that member's delta (also appended to refs)."""
    seen: list = []
    q = SingleWriterSpineQueue(lambda rec: (seen.append((rec["member_id"], rec["seq"], rec["kind"])),
                                            f"r-{rec['member_id']}-{rec['seq']}")[1])
    q.submit(member_id="a", seq=2, kind="y", record={})
    q.submit(member_id="b", seq=1, kind="x", record={})
    q.submit(member_id="a", seq=1, kind="x", record={})

    assert q.pending_for("a") == 2 and q.pending_for("b") == 1
    delta = q.flush_member("a")
    assert delta == ["r-a-1", "r-a-2"]                      # a's two records, seq-ordered
    assert seen == [("a", 1, "x"), ("a", 2, "y")]           # only a was written
    assert q.pending_for("a") == 0 and q.pending_for("b") == 1   # b still buffered
    assert q.refs == ["r-a-1", "r-a-2"]                     # appended to the append-only ref list

    # the final flush drains the remaining member
    assert q.flush() == ["r-a-1", "r-a-2", "r-b-1"]


def test_flush_member_is_fail_open_on_writer_error():
    """A writer that raises inside flush_member drops that record (returns a short delta) but never
    raises — the count mismatch is how the orchestrator learns the flush was not fully durable."""
    def bad(rec):
        raise RuntimeError("boom")

    q = SingleWriterSpineQueue(bad)
    q.submit(member_id="a", seq=1, kind="x", record={})
    attempted = q.pending_for("a")
    delta = q.flush_member("a")
    assert attempted == 1 and delta == []                   # dropped, not raised → len(delta) != attempted


def test_flush_member_no_writer_writes_nothing():
    q = SingleWriterSpineQueue(None)
    q.submit(member_id="a", seq=1, kind="x", record={})
    assert q.flush_member("a") == [] and q.refs == []


# --- WaveProgressStore unit proofs --------------------------------------------------------------

def test_progress_store_roundtrip(tmp_path):
    store = WaveProgressStore(tmp_path / "p.json")
    mr = MemberResult(member_id="m", status=MemberStatus.SUCCESS,
                      leads=[Finding(ref="f1", title="t")],
                      claims=[MemberFindingClaim(raw_output="x",
                                                 analysis=OutputAnalysis(exploit_succeeded=True))])
    assert store.record("w", "m", mr, refs=["r1", "r2"]) is True
    done = store.completed("w")
    assert set(done) == {"m"}
    assert done["m"].result == mr                           # exact pydantic round-trip
    assert done["m"].refs == ("r1", "r2")
    assert store.completed("other-wave") == {}              # isolation by wave_id


def test_progress_store_two_members_accumulate(tmp_path):
    store = WaveProgressStore(tmp_path / "p.json")
    store.record("w", "a", MemberResult(member_id="a"), refs=["ra"])
    store.record("w", "b", MemberResult(member_id="b"), refs=["rb"])
    done = store.completed("w")
    assert set(done) == {"a", "b"} and done["a"].refs == ("ra",) and done["b"].refs == ("rb",)


def test_progress_store_bad_path_is_disabled_noop():
    store = WaveProgressStore(object())                     # os.fspath(object()) fails → disabled store
    assert store.record("w", "m", MemberResult(member_id="m")) is False
    assert store.completed("w") == {}
