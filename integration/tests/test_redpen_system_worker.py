"""Red-Pen R4 — the whole-repository System-review WORKER (``jobs/redpen_system.py``).

Pinned: the System review threat-models the WHOLE TREE of the checkout (every reviewable file, NO ``include_paths``
/ diff restriction) — through the real engine, every lens sees it; only REPRODUCED FACTs are reported (Critical/High
fail the check, Medium/Low are neutral, none is success) and LEADs never cross; an empty tree fails CLOSED (a failed
clone is never a silent clean); the engine off is inert and posts nothing; a refused check-run post is recorded, not
fatal; and the worker runs ONLY through ``JobRunner.run_one`` behind the gate and the tenant reconciliation — a
refused or cross-tenant job never reaches it. Framework-free (no candidate reaches the certify seam here).
"""
from __future__ import annotations

import functools
from types import SimpleNamespace

import pytest

from vigil_integration.jobs import redpen_system as rs
from vigil_integration.jobs import runner as runner_mod
from vigil_integration.jobs.model import SecurityJob
from vigil_integration.redpen import LensResponse, RedPenFact, RedPenLead, RedPenReport

ORG, REPO, SLUG = "org_a", "github.com/acme/widgets", "cust_" + "c" * 24
WHOLE_TREE = ["README.md", "app.py", "pkg/mod.py", "pkg/sub/deep.txt"]


def _repo(tmp_path) -> str:
    root = tmp_path / "checkout"
    for rel in WHOLE_TREE:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(f"# {rel}\n", encoding="utf-8")
    for skipped in (".git/config", "node_modules/left-pad/index.js", "pkg/__pycache__/mod.cpython-313.pyc"):
        p = root / skipped
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x", encoding="utf-8")
    return str(root)


def _job(**over) -> SecurityJob:
    kw = dict(source="scheduled", repo=REPO, engagement_slug=SLUG, tenant_id=ORG, commit="sch-2026-W47",
              profile="full", delivery_id="work-x")
    kw.update(over)
    return SecurityJob.normalize(**kw)


def _fact(sev, ref="f1"):
    return RedPenFact(bug_class="sql_injection", confirmed_by="sql_breakout", severity=sev, finding_ref=ref,
                      reason="reproduced twice", lens="injection", file="app.py", line=7)


def _lead(ref="l1"):
    return RedPenLead(bug_class="idor", severity="high", finding_ref=ref, reason="SECRET-LEAD-BODY not reproduced",
                      lens="authn_authz", file="pkg/mod.py", line=3, outcome="no_fire")


class _Capture:
    def __init__(self, report):
        self.report, self.kw = report, None

    def __call__(self, **kw):
        self.kw = kw
        return self.report


# ---- whole-tree scope ---------------------------------------------------------------------------------------
def test_the_system_review_covers_the_whole_tree_not_a_diff(tmp_path):
    root = _repo(tmp_path)
    run = _Capture(RedPenReport(enabled=True))
    rs.make_redpen_system_worker(checkout=lambda j: root, reviewer=object(), signers=[("k", "s")], _run=run)(_job())
    assert run.kw["changed_paths"] == WHOLE_TREE                       # EVERY reviewable file, VCS/build dirs skipped
    assert "include_paths" not in run.kw                               # no diff restriction of any kind
    assert run.kw["checkout_path"] == root and run.kw["engagement_slug"] == SLUG


def test_through_the_real_engine_every_lens_sees_the_whole_tree(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_REDPEN_ENABLED", "1")
    root = _repo(tmp_path)
    seen: list = []

    def reviewer(req):
        seen.append((req.lens, tuple(req.changed_paths)))
        return LensResponse(candidates=())
    out = rs.make_redpen_system_worker(checkout=lambda j: root, reviewer=reviewer, signers=[("k", "s")])(_job())
    assert out["enabled"] is True and out["conclusion"] == "success" and out["facts"] == []
    assert seen and all(paths == tuple(WHOLE_TREE) for _lens, paths in seen)
    assert len({lens for lens, _p in seen}) == len(seen)               # one request per lens


def test_the_enumeration_is_bounded(tmp_path):
    assert rs.enumerate_tree(_repo(tmp_path), max_paths=2) == WHOLE_TREE[:2]


@pytest.mark.parametrize("enum", [None, (lambda job, root: [])])
def test_an_empty_whole_tree_fails_closed_never_a_silent_clean(tmp_path, enum):
    empty = tmp_path / "empty"
    empty.mkdir()
    run = _Capture(RedPenReport(enabled=True))
    worker = rs.make_redpen_system_worker(checkout=lambda j: str(empty), reviewer=object(), signers=[("k", "s")],
                                          enumerate_paths=enum, _run=run)
    with pytest.raises(ValueError, match="empty"):
        worker(_job())
    assert run.kw is None                                              # the engine never ran on an unknown scope


# ---- FACTs only ---------------------------------------------------------------------------------------------
def test_only_reproduced_facts_are_reported_and_leads_never_cross(tmp_path):
    report = RedPenReport(enabled=True, facts=(_fact("high"), _fact("low", "f2")), leads=(_lead(), _lead("l2")))
    posted: list = []
    out = rs.make_redpen_system_worker(checkout=lambda j: _repo(tmp_path), reviewer=object(), signers=[("k", "s")],
                                       post_outcome=lambda job, o: posted.append(o) or "check-run-1",
                                       _run=_Capture(report))(_job())
    assert [f["finding_ref"] for f in out["facts"]] == ["f1", "f2"] and out["leads_count"] == 2
    assert out["posted"] == "check-run-1" and len(posted) == 1
    assert "SECRET-LEAD-BODY" not in repr(posted) and "l1" not in repr(posted)    # no LEAD crosses to the post


@pytest.mark.parametrize("severities,conclusion,blocking", [
    ((), "success", False),
    (("low",), "neutral", False),
    (("medium", "low"), "neutral", False),
    (("high",), "failure", True),
    (("medium", "critical"), "failure", True),
])
def test_critical_and_high_facts_fail_the_check_and_others_are_neutral(severities, conclusion, blocking):
    out = rs.redpen_system_outcome(RedPenReport(enabled=True,
                                                facts=tuple(_fact(s, f"f{i}") for i, s in enumerate(severities))))
    assert out["conclusion"] == conclusion and out["blocking"] is blocking


def test_the_engine_off_is_inert_and_posts_nothing(tmp_path):
    posted: list = []
    out = rs.make_redpen_system_worker(checkout=lambda j: _repo(tmp_path), reviewer=object(), signers=[("k", "s")],
                                       post_outcome=lambda job, o: posted.append(o),
                                       _run=_Capture(RedPenReport(enabled=False)))(_job())
    assert out["enabled"] is False and out["conclusion"] == "skipped" and posted == []


def test_a_refused_check_run_post_is_recorded_not_fatal(tmp_path):
    def refuse(job, outcome):
        raise RuntimeError("App credential not provisioned")
    out = rs.make_redpen_system_worker(checkout=lambda j: _repo(tmp_path), reviewer=object(), signers=[("k", "s")],
                                       post_outcome=refuse,
                                       _run=_Capture(RedPenReport(enabled=True, facts=(_fact("high"),))))(_job())
    assert out["facts_count"] == 1 and out["posted"] is None
    assert out["post_refused"].startswith("RuntimeError: App credential")


# ---- execution stays behind JobRunner.run_one + the gate ----------------------------------------------------
class _OneJobQueue:
    def __init__(self, job):
        self._job, self.completed, self.released = job, [], []

    def claim_next(self):
        job, self._job = self._job, None
        return None if job is None else SimpleNamespace(job=job, job_id="j1")

    def try_lease(self, slug, *, run_id=""):
        return "tok"

    def release_lease(self, slug, token):
        pass

    def requeue(self, claimed):
        pass

    def complete(self, claimed):
        self.completed.append(claimed.job)

    def release_delivery(self, claimed):
        self.released.append(claimed.job)

    def requeue_stale(self):
        return 0


def _gate(allowed):
    return lambda job: SimpleNamespace(allowed=allowed, reason="ok" if allowed else "no verified lease",
                                       denial_code="" if allowed else "no_lease")


@pytest.mark.parametrize("allowed,process_tenant,state,ran", [
    (False, ORG, "refused", False),        # the gate refuses (e.g. the ticket's lease does not verify)
    (True, "org_other", "refused", False),  # a worker sharded for ANOTHER org: refused even though the gate allows
    (True, ORG, "done", True),             # the org's own process + an allowing gate: the worker runs
])
def test_the_system_worker_runs_only_through_the_job_runner_gate(tmp_path, monkeypatch, allowed, process_tenant,
                                                                  state, ran):
    monkeypatch.setattr(runner_mod, "authorize_job",
                        functools.partial(runner_mod.authorize_job, active_tenant=lambda: process_tenant))
    calls: list = []
    worker = rs.make_redpen_system_worker(checkout=lambda j: _repo(tmp_path), reviewer=object(),
                                          signers=[("k", "s")],
                                          _run=lambda **kw: calls.append(kw) or RedPenReport(enabled=True))
    queue = _OneJobQueue(_job())
    outcome = runner_mod.JobRunner(queue=queue, gate=_gate(allowed), worker=worker,
                                   assert_tenant=lambda: None).run_one()
    assert outcome.state == state and bool(calls) is ran
    assert queue.completed == [outcome.job]                            # claimed → decided → completed, either way
