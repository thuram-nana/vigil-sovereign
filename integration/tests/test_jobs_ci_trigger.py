"""
jobs.ci_trigger — the CI trigger adapter (W4).

Pins the adapter invariants:
  * It PRODUCES a validated SecurityJob(source="ci") and nothing more — no execution, no queue method, no
    network (the enqueue + the authorized worker are elsewhere).
  * The delivery_id is the SHARED content-addressed work key work_delivery_id(repo, pr, commit) — NOT the
    CI run id — so a CI re-run and a webhook-handled commit of the same (repo, pr, commit) coalesce in the
    queue's permanent seen-set (exactly-once ACROSS paths). The CI run id is audit-only telemetry.
  * The repo identity matches the webhook path's `github.com/<full_name>` spelling (cross-path dedup).
  * GitHub-Actions env parsing is TOTAL + bounded: the PR HEAD sha is preferred over the merge SHA; a
    missing/garbage event file degrades safely; no repo => nothing to scan (CiTrigger.poll() -> []).
"""

from __future__ import annotations

import json

from vigil_integration.jobs.ci_trigger import (
    CiTrigger,
    ci_job_from_github_env,
    ci_job_from_inputs,
)
from vigil_integration.jobs.model import SecurityJob, work_delivery_id


def test_ci_job_from_inputs_is_source_ci_with_the_shared_work_delivery_key() -> None:
    job = ci_job_from_inputs(repo="github.com/org/repo", commit="headsha", pr_number=7, ci_run_id="999")
    assert job.source == "ci"
    assert job.repo == "github.com/org/repo"
    assert job.commit == "headsha"
    assert job.pr_number == 7
    # delivery_id is the SHARED work key over (repo, pr, commit) — never the CI run id
    assert job.delivery_id == work_delivery_id("github.com/org/repo", 7, "headsha")
    assert job.delivery_id != "999"
    assert job.extra.get("ci_run") == "999"            # the run id is audit telemetry only


def test_ci_delivery_id_coalesces_with_the_webhook_path() -> None:
    """A CI job and a webhook job for the SAME (repo, pr, commit) carry the IDENTICAL delivery_id, so the
    queue's permanent delivery seen-set coalesces them — a CI re-run never double-scans a webhook commit."""
    repo, pr, commit = "github.com/org/repo", 11, "deadbeef"
    ci = ci_job_from_inputs(repo=repo, commit=commit, pr_number=pr, ci_run_id="run-abc")
    webhook = SecurityJob.normalize(
        source="webhook", repo=repo, commit=commit, pr_number=pr,
        delivery_id=work_delivery_id(repo, pr, commit))
    assert ci.delivery_id == webhook.delivery_id
    # a changed commit yields a NEW key (new code re-scans)
    ci2 = ci_job_from_inputs(repo=repo, commit="cafef00d", pr_number=pr)
    assert ci2.delivery_id != ci.delivery_id


def test_ci_job_from_github_env_parses_repo_host_pr_and_prefers_head_sha(tmp_path) -> None:
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"pull_request": {"number": 42, "head": {"sha": "headsha42"}}}),
                     encoding="utf-8")
    env = {
        "GITHUB_REPOSITORY": "Org/Repo",
        "GITHUB_SERVER_URL": "https://github.com",
        "GITHUB_EVENT_PATH": str(event),
        "GITHUB_SHA": "mergesha",          # the merge sha — must NOT win over the PR head sha
        "GITHUB_RUN_ID": "run-77",
    }
    job = ci_job_from_github_env(env)
    assert job.source == "ci"
    assert job.repo == "github.com/Org/Repo"           # host prefixed; matches the webhook spelling
    assert job.pr_number == 42
    assert job.commit == "headsha42"                   # PR HEAD sha preferred over GITHUB_SHA merge sha
    assert job.extra.get("ci_run") == "run-77"
    # cross-path: same key the webhook path would compute for this (repo, pr, head)
    assert job.delivery_id == work_delivery_id("github.com/Org/Repo", 42, "headsha42")


def test_ci_job_from_github_env_falls_back_to_ref_and_sha_without_an_event(tmp_path) -> None:
    env = {
        "GITHUB_REPOSITORY": "org/repo",
        "GITHUB_REF": "refs/pull/13/merge",
        "GITHUB_SHA": "fallbacksha",
        "GITHUB_EVENT_PATH": str(tmp_path / "does-not-exist.json"),
    }
    job = ci_job_from_github_env(env)
    assert job.pr_number == 13                          # recovered from refs/pull/<n>/merge
    assert job.commit == "fallbacksha"                  # no event head sha -> GITHUB_SHA fallback
    assert job.repo == "github.com/org/repo"            # default host when GITHUB_SERVER_URL unset


def test_ci_trigger_poll_is_empty_when_no_repo_named() -> None:
    # no GITHUB_REPOSITORY -> normalize raises -> the one-shot trigger yields [] (nothing to scan), never raises
    assert CiTrigger(env={}).poll() == []
    # a named repo -> exactly one job
    jobs = CiTrigger(env={"GITHUB_REPOSITORY": "o/r", "GITHUB_SHA": "s"}).poll()
    assert len(jobs) == 1 and jobs[0].source == "ci" and jobs[0].repo == "github.com/o/r"


def test_ci_job_from_github_env_tolerates_a_garbage_event_file(tmp_path) -> None:
    bad = tmp_path / "event.json"
    bad.write_text("}{ not json", encoding="utf-8")
    env = {"GITHUB_REPOSITORY": "o/r", "GITHUB_EVENT_PATH": str(bad), "GITHUB_SHA": "s"}
    job = ci_job_from_github_env(env)                   # must not raise
    assert job.pr_number is None and job.commit == "s"
