"""repo-connect 3-live-b2b: make_pr_bot_runner wires the queue + the hard gate + the PR-bot worker.

It assembles a real ``SecurityJobQueue`` + the per-job authorization gate + the worker into a ``JobRunner`` whose
``drain()`` runs each queued job through ``run_one`` — so the gate stays the SOLE executor: an AUTHORIZED job
runs the worker, an UNAUTHORIZED one is refused WITHOUT ever running it. Offline — a real (file-backed) queue, an
injected gate verdict, and an injected worker double (the worker itself is covered by test_pr_bot_worker).
"""
from __future__ import annotations

import pytest

# make_pr_bot_runner builds a REAL SecurityJobQueue, which wraps the framework EngagementScheduler — so this
# exercises the genuine queue/claim/lease/complete path and runs in the offense leg (skips on the sovereign leg).
pytest.importorskip("framework.v2.engagement_scheduler",
                    reason="SecurityJobQueue wraps the framework EngagementScheduler (offense leg)")

from vigil_integration.jobs.authorize import GateOutcome  # noqa: E402
from vigil_integration.jobs.model import SecurityJob  # noqa: E402
from vigil_integration.jobs.pr_bot import make_pr_bot_runner  # noqa: E402


def _job():
    return SecurityJob(repo="github.com/acme/widget", pr_number=7, commit="c", source="manual", delivery_id="d1")


def _allow(job):
    return GateOutcome(True, "in envelope", "")


def _deny(job):
    return GateOutcome(False, "out of scope", "out_of_scope")


def test_runner_runs_the_worker_on_an_authorized_job(tmp_path):
    ran: list = []

    def _worker(job):
        ran.append(job.repo)
        return {"findings": [], "comments_posted": [], "comments_refused": []}

    runner = make_pr_bot_runner(queue_root=str(tmp_path / "q"), base_dir=str(tmp_path), trust_root=object(),
                                _gate=_allow, _worker=_worker)
    runner.queue.enqueue(_job())
    outcomes = runner.drain()
    assert [o.state for o in outcomes] == ["done"]
    assert ran == ["github.com/acme/widget"]                 # the worker ran UNDER the authorized gate


def test_runner_refuses_an_unauthorized_job_without_running_the_worker(tmp_path):
    ran: list = []

    def _worker(job):
        ran.append(job.repo)
        return {}

    runner = make_pr_bot_runner(queue_root=str(tmp_path / "q"), base_dir=str(tmp_path), trust_root=object(),
                                _gate=_deny, _worker=_worker)
    runner.queue.enqueue(_job())
    outcomes = runner.drain()
    assert [o.state for o in outcomes] == ["refused"]
    assert [o.denial_code for o in outcomes] == ["out_of_scope"]
    assert ran == []                                         # the gate refused BEFORE the worker ran (sole executor)


def test_runner_drains_empty_queue_to_nothing(tmp_path):
    runner = make_pr_bot_runner(queue_root=str(tmp_path / "q"), base_dir=str(tmp_path), trust_root=object(),
                                _gate=_allow, _worker=lambda job: {})
    assert runner.drain() == []                              # empty queue ⇒ no outcomes
