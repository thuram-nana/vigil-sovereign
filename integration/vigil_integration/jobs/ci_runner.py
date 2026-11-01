"""jobs.ci_runner — assemble + drive the W4 CI scan.

One call enqueues the CI job and drains it through the ONE authorized runner (``JobRunner.run_one`` →
``authorize_job``), so the hard authorization gate stays the SOLE executor: a repo with no cryptographically
-verified ``EngagementAuthority`` is REFUSED, not scanned, regardless of being "from CI". This is the
sibling of ``make_pr_bot_runner``, with the CI-local checkout/changed-files seams (``live.ci_checkout``)
and a diff-scoped codescan worker.

``framework``-lazy (``build_repo_gate`` / the queue defer it); ``_queue`` / ``_gate`` / ``_worker`` /
``_git_runner`` are the offline injection seams. FATAL-2: no ``sigil`` import; registered in
``integration/tests/test_two_env_boundary.py``.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from .model import SecurityJob

#: severity ordering for the ``--fail-on`` gate (unknown sorts lowest so it never trips a threshold)
_SEVERITY_RANK: dict[str, int] = {"critical": 4, "high": 3, "medium": 2, "moderate": 2, "low": 1, "info": 0}


def make_ci_scan_runner(*, queue_root: str, base_dir: str, trust_root: Any, workspace: str,
                        base_ref: str, head_ref: str, max_files: int = 5000, now: Any = None,
                        assert_tenant: Any = None, _queue: Any = None, _gate: Any = None,
                        _worker: Any = None, _git_runner: Optional[Callable[..., Any]] = None):
    """Assemble ``(queue, JobRunner)`` for a CI scan: the durable SecurityJob queue + the hard per-job
    authorization gate (``build_repo_gate`` over the pinned authority root — fail-closed) + a DIFF-SCOPED
    codescan worker over the CI-local checkout. ``_queue``/``_gate``/``_worker`` are offline seams."""
    from ..live.ci_checkout import make_ci_changed_files, make_ci_checkout
    from .authorize import build_repo_gate
    from .queue import SecurityJobQueue
    from .runner import JobRunner, make_diff_codescan_worker

    queue = _queue if _queue is not None else SecurityJobQueue(queue_root)
    gate = _gate if _gate is not None else build_repo_gate(trust_root, now=now)
    worker = _worker if _worker is not None else make_diff_codescan_worker(
        base_dir=base_dir, checkout=make_ci_checkout(workspace),
        changed_files=make_ci_changed_files(base_ref=base_ref, head_ref=head_ref,
                                            workspace=workspace, _runner=_git_runner),
        max_files=max_files)
    return queue, JobRunner(queue=queue, gate=gate, worker=worker, assert_tenant=assert_tenant)


def run_ci_scan(job: SecurityJob, **kw: Any) -> "list":
    """Enqueue ``job`` and drain exactly one unit of work through the authorized runner; return the
    outcomes. A duplicate delivery (a CI re-run of an already-scanned (repo, pr, commit)) simply enqueues
    as a duplicate and drains to ``[]`` (idempotent). All keyword args pass through to
    :func:`make_ci_scan_runner`."""
    queue, runner = make_ci_scan_runner(**kw)
    queue.enqueue(job)
    return runner.drain(max_jobs=1)


def findings_of(outcomes: "list") -> "list[dict]":
    """Every finding dict from the ``done`` outcomes' ``run_codescan`` results, in order. Total/defensive —
    a non-dict result or a missing ``findings`` key contributes nothing."""
    out: list[dict] = []
    for o in outcomes or []:
        if getattr(o, "state", "") != "done":
            continue
        res = getattr(o, "result", None)
        items = res.get("findings") if isinstance(res, dict) else None
        if isinstance(items, list):
            out.extend(f for f in items if isinstance(f, dict))
    return out


def exit_code(outcomes: "list", findings: "list[dict]", *, fail_on: str = "") -> int:
    """The CI process exit code: ``1`` if any job FAILED (a worker/gate error a CI driver must notice), or
    if ``--fail-on <severity>`` is set and an ORACLE-CONFIRMED FACT is at or above that severity (LEADs are
    warnings, never build-breakers — prove-don't-guess: an unconfirmed lead must not gate a build). Else
    ``0``. A ``refused``/``busy``/``empty`` outcome is NOT a failure (it is a normal authorization/queue
    state)."""
    from ..live.ci_annotate import is_fact

    if any(getattr(o, "state", "") == "failed" for o in (outcomes or [])):
        return 1
    threshold = _SEVERITY_RANK.get(str(fail_on or "").strip().lower(), -1)
    if threshold < 0:
        return 0
    for f in findings or []:
        if not is_fact(f):
            continue  # gate only on confirmed FACTs
        rank = _SEVERITY_RANK.get(str(f.get("severity") or "").strip().lower(), 0)
        if rank >= threshold:
            return 1
    return 0


__all__ = ["make_ci_scan_runner", "run_ci_scan", "findings_of", "exit_code"]
