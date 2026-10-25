"""repo-connect Slice 2b — the reconciliation safety-net poller.

Exercises the REAL SecurityJobQueue so the delivery_id/fingerprint dedup and the durable-before-cursor
contract are genuinely tested. Pins:
  * list → normalize → ENQUEUE, then the per-repo checkpoint ADVANCES to the new cursor;
  * a replayed PR-head is COALESCED by the queue (stable delivery_id), and the cursor still advances;
  * re-scan-safety AFTER completion: a stable delivery_id's PERMANENT marker suppresses a re-list even once
    the work fingerprint has cleared (no re-scan loop);
  * durable-before-cursor: a transient enqueue failure does NOT advance the checkpoint (re-list next cycle);
  * fail-open per repo (a flaky lister for one repo is skipped, the others reconcile);
  * the default empty lister is an inert no-op; a malformed PR row is dropped, never fatal;
  * TriggerSource conformance (poll()).

Uses the real queue, so (like the other spine tests) it runs in the OFFENSE CI leg and skips in the
sovereign leg via importorskip.
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("framework.v2.engagement_scheduler",
                    reason="reconciliation enqueues onto the real SecurityJobQueue; runs in the offense CI leg")

from vigil_integration.jobs.model import SecurityJob        # noqa: E402
from vigil_integration.jobs.queue import SecurityJobQueue   # noqa: E402  (after importorskip)
from vigil_integration.jobs.reconciliation import (          # noqa: E402
    ChangedPR,
    Reconciler,
    ReconciliationCheckpoints,
    ReconciliationTrigger,
    empty_lister,
    reconcile_once,
)


def _lister(mapping: dict):
    """A fixture git-host lister: repo -> (list[ChangedPR], new_cursor). Unknown repo ⇒ no change."""
    def _l(repo: str, cursor: str):
        return mapping.get(repo, ([], cursor))
    return _l


def _setup(tmp_path: Path):
    q = SecurityJobQueue(tmp_path / "queue")
    cp = ReconciliationCheckpoints(tmp_path / "cp")
    return q, cp


def test_lists_normalizes_enqueues_and_advances_cursor(tmp_path):
    q, cp = _setup(tmp_path)
    repo = "github.com/acme/widget"
    lister = _lister({repo: ([ChangedPR(7, "aaa", "c7"), ChangedPR(8, "bbb", "c8")], "c8")})
    out = reconcile_once(repos=[repo], lister=lister, checkpoints=cp, queue=q)
    assert out["enqueued"] == 2 and out["duplicate"] == 0 and q.pending_count() == 2
    assert cp.load(SecurityJob(repo=repo).slug) == "c8"   # checkpoint advanced to the new cursor


def test_replayed_prs_coalesce_and_cursor_still_advances(tmp_path):
    q, cp = _setup(tmp_path)
    repo = "github.com/acme/widget"
    lister = _lister({repo: ([ChangedPR(7, "aaa", "c7")], "c7")})
    assert reconcile_once(repos=[repo], lister=lister, checkpoints=cp, queue=q)["enqueued"] == 1
    # same PR-head again (a webhook already enqueued it, or an overlapping cycle) → coalesced, not re-enqueued
    out = reconcile_once(repos=[repo], lister=lister, checkpoints=cp, queue=q)
    assert out["enqueued"] == 0 and out["duplicate"] == 1 and q.pending_count() == 1


def test_stable_delivery_id_prevents_rescan_after_completion(tmp_path):
    q, cp = _setup(tmp_path)
    repo = "github.com/acme/widget"
    lister = _lister({repo: ([ChangedPR(7, "aaa", "c7")], "c7")})
    reconcile_once(repos=[repo], lister=lister, checkpoints=cp, queue=q)
    q.complete(q.claim_next())                         # the scan finishes → work fingerprint cleared
    # a re-list of the SAME PR-head must STILL be suppressed (permanent delivery marker) — no re-scan loop
    out = reconcile_once(repos=[repo], lister=lister, checkpoints=cp, queue=q)
    assert out["enqueued"] == 0 and out["duplicate"] == 1 and q.pending_count() == 0


def test_durable_failure_does_not_advance_cursor(tmp_path):
    class _BoomQueue:
        def enqueue(self, job):
            raise OSError("durable insert failed")
    _, cp = _setup(tmp_path)
    repo = "github.com/acme/widget"
    slug = SecurityJob(repo=repo).slug
    lister = _lister({repo: ([ChangedPR(7, "aaa", "c7")], "c7")})
    out = reconcile_once(repos=[repo], lister=lister, checkpoints=cp, queue=_BoomQueue())
    assert out["failed"] == 1 and out["enqueued"] == 0
    assert cp.load(slug) == ""                         # NOT advanced → the next cycle re-lists (durable-before-cursor)


def test_fail_open_skips_a_flaky_repo(tmp_path):
    q, cp = _setup(tmp_path)
    good, bad = "github.com/acme/good", "github.com/acme/bad"

    def _l(repo, cursor):
        if repo == bad:
            raise RuntimeError("git-host 500")
        return [ChangedPR(1, "sha1", "c1")], "c1"

    out = reconcile_once(repos=[bad, good], lister=_l, checkpoints=cp, queue=q)
    assert out["skipped"] == 1 and out["enqueued"] == 1 and q.pending_count() == 1


def test_empty_lister_is_a_noop(tmp_path):
    q, cp = _setup(tmp_path)
    out = reconcile_once(repos=["github.com/a/b"], lister=empty_lister, checkpoints=cp, queue=q)
    assert out == {"enqueued": 0, "duplicate": 0, "dropped": 0, "skipped": 0, "failed": 0}
    assert q.pending_count() == 0


def test_malformed_pr_row_is_dropped_not_fatal(tmp_path):
    q, cp = _setup(tmp_path)
    repo = "github.com/acme/widget"
    bad_pr = ChangedPR("not-an-int", "sha", "c")       # pr_number not int → normalize raises → dropped
    lister = _lister({repo: ([bad_pr, ChangedPR(9, "good", "c9")], "c9")})
    out = reconcile_once(repos=[repo], lister=lister, checkpoints=cp, queue=q)
    assert out["enqueued"] == 1 and out["dropped"] == 1 and out["skipped"] == 0  # bad row counted+dropped, repo NOT skipped
    assert q.pending_count() == 1


def test_trigger_poll_produces_jobs(tmp_path):
    repo = "github.com/acme/widget"
    trig = ReconciliationTrigger(repos=[repo], lister=_lister({repo: ([ChangedPR(7, "aaa", "c7")], "c7")}))
    jobs = trig.poll()
    assert len(jobs) == 1 and jobs[0].source == "reconciliation" and jobs[0].pr_number == 7
    assert jobs[0].repo == repo and jobs[0].delivery_id.startswith("recon-")


def test_reconciler_once_via_queue_root_builds_the_queue(tmp_path):
    repo = "github.com/acme/widget"
    rec = Reconciler(repos=[repo], queue_root=tmp_path / "queue", checkpoint_root=tmp_path / "cp",
                     lister=_lister({repo: ([ChangedPR(7, "aaa", "c7")], "c7")}))
    assert rec.once()["enqueued"] == 1
    assert SecurityJobQueue(tmp_path / "queue").pending_count() == 1


def test_checkpoint_roundtrip_and_fail_open(tmp_path):
    cp = ReconciliationCheckpoints(tmp_path / "cp")
    assert cp.load("repo-x") == ""                     # absent ⇒ "" (full re-list)
    cp.advance("repo-x", "github.com/a/b", "cursor-123")
    assert cp.load("repo-x") == "cursor-123"
    # a torn/invalid cursor file fails open to "" (full re-list), never raises
    (tmp_path / "cp" / "reconciliation_cursors" / "repo-x.json").write_text("{not json", encoding="utf-8")
    assert cp.load("repo-x") == ""


# ---- red-pen hardening regressions (Slice-2b) ---------------------------------------------------------

def test_non_finite_pr_number_is_dropped_not_whole_repo_skipped(tmp_path):
    # a non-finite pr_number → _job_for → int(inf) OverflowError must be caught as a per-ROW drop (counted),
    # NOT propagate to the per-repo handler and starve the repo's good PRs (the 2a-style regression).
    q, cp = _setup(tmp_path)
    repo = "github.com/acme/widget"
    lister = _lister({repo: ([ChangedPR(float("inf"), "bad", "c1"), ChangedPR(9, "good", "c2")], "c2")})
    out = reconcile_once(repos=[repo], lister=lister, checkpoints=cp, queue=q)
    assert out["dropped"] == 1 and out["enqueued"] == 1 and out["skipped"] == 0 and q.pending_count() == 1


def test_non_changedpr_row_is_dropped_not_fatal(tmp_path):
    q, cp = _setup(tmp_path)
    repo = "github.com/acme/widget"
    lister = _lister({repo: ([None, {"pr": 1}, ChangedPR(9, "good", "c")], "c")})  # junk rows + one good
    out = reconcile_once(repos=[repo], lister=lister, checkpoints=cp, queue=q)
    assert out["dropped"] == 2 and out["enqueued"] == 1 and out["skipped"] == 0 and q.pending_count() == 1


def test_poll_guards_each_row_so_a_poison_row_cannot_blank_all_repos(tmp_path):
    repo = "github.com/acme/widget"
    trig = ReconciliationTrigger(repos=[repo],
                                 lister=_lister({repo: ([None, ChangedPR(7, "aaa", "c7")], "c7")}))
    jobs = trig.poll()                                 # must NOT raise; the poison row is dropped
    assert len(jobs) == 1 and jobs[0].pr_number == 7


def test_malformed_drop_does_not_wedge_cursor_advances_past(tmp_path):
    q, cp = _setup(tmp_path)
    repo = "github.com/acme/widget"
    slug = SecurityJob(repo=repo).slug
    lister = _lister({repo: ([ChangedPR("bad", "x", "c1"), ChangedPR(9, "good", "c9")], "c9")})
    reconcile_once(repos=[repo], lister=lister, checkpoints=cp, queue=q)
    assert cp.load(slug) == "c9"                       # a permanently-malformed row does NOT wedge progress


def test_durable_failure_stops_cursor_at_last_clean_pr(tmp_path):
    # PR1 enqueues, PR2's enqueue fails (OSError) → cursor stops at PR1's per-PR cursor, batch high-water NOT used
    cp = ReconciliationCheckpoints(tmp_path / "cp")
    repo = "github.com/acme/widget"
    slug = SecurityJob(repo=repo).slug

    class _OneThenBoom:
        def __init__(self):
            self.n = 0

        def enqueue(self, job):
            self.n += 1
            if self.n >= 2:
                raise OSError("durable insert failed")
            return type("R", (), {"enqueued": True})()

    lister = _lister({repo: ([ChangedPR(1, "a", "c1"), ChangedPR(2, "b", "c2")], "cHIGH")})
    out = reconcile_once(repos=[repo], lister=lister, checkpoints=cp, queue=_OneThenBoom())
    assert out["enqueued"] == 1 and out["failed"] == 1
    assert cp.load(slug) == "c1"                       # stopped at PR1, NOT advanced to the batch high-water


def test_reconciler_requires_a_checkpoint_source_clear_error():
    class _Q:
        def enqueue(self, job):
            return None
    with pytest.raises(ValueError):                    # a clear ValueError, not a raw pathlib TypeError
        Reconciler(repos=["github.com/a/b"], queue=_Q())


def test_checkpoint_coerces_non_str_cursor_to_empty(tmp_path):
    cp = ReconciliationCheckpoints(tmp_path / "cp")
    cp.advance("repo-y", "github.com/a/b", None)        # a None high-water must NOT persist as "None"
    assert cp.load("repo-y") == ""
    cp.advance("repo-z", "github.com/a/b", 123)         # a non-str must NOT persist as "123"
    assert cp.load("repo-z") == ""


def test_checkpoint_oversized_file_fails_open(tmp_path):
    cp = ReconciliationCheckpoints(tmp_path / "cp")
    d = tmp_path / "cp" / "reconciliation_cursors"
    d.mkdir(parents=True, exist_ok=True)
    (d / "repo-big.json").write_text("x" * (128 * 1024), encoding="utf-8")   # > the 64KiB cap
    assert cp.load("repo-big") == ""                    # oversized ⇒ fail-open, never hangs/OOMs


def test_recon_delivery_id_is_injective_no_delimiter_collision():
    from vigil_integration.jobs.reconciliation import _recon_delivery_id
    # the classic '|'-join collision: ("a|b","c","d") vs ("a","b|c","d") would collapse to one string — the
    # JSON encoding keeps them distinct.
    assert _recon_delivery_id("a|b", "c", "d") != _recon_delivery_id("a", "b|c", "d")
    # a changed head correctly yields a NEW delivery id (so a new commit re-scans)
    assert _recon_delivery_id("r", 1, "head1") != _recon_delivery_id("r", 1, "head2")
    assert _recon_delivery_id("r", 1, "h").startswith("recon-")


def test_watch_surfaces_a_stuck_repo_tally(tmp_path, capsys):
    q, cp = _setup(tmp_path)

    def _always_raises(repo, cursor):
        raise RuntimeError("git-host down")

    rec = Reconciler(repos=["github.com/a/b"], queue=q, checkpoint_root=tmp_path / "cp", lister=_always_raises)
    rec.watch(interval=0, sleep=lambda _s: None, max_cycles=1)
    err = capsys.readouterr().err
    assert "reconcile" in err and "skipped=1" in err    # a non-reconciling repo is OBSERVABLE, not silent
