"""
jobs.runner — the SOLE execution path for a ``SecurityJob``.

``run_one`` claims the head job, passes it through the hard authorization gate (``authorize_job``), and
runs the worker ONLY if the gate allows. A refused job is recorded and completed WITHOUT running; a
worker error is caught (never crashes the loop). This is the one place the engine is invoked for a job —
no trigger adapter, webhook handler, or queue method ever runs a worker itself. Crash recovery is the
scheduler's ``requeue_stale`` (a claimer that dies leaves its job reclaimable).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from .authorize import JobAuthorization, authorize_job
from .model import SecurityJob
from .queue import ClaimedJob, SecurityJobQueue

#: A worker runs an AUTHORIZED job and returns its (opaque) result. It is called ONLY after the gate
#: allows — it must never be invoked directly by a trigger. ``(SecurityJob) -> Any``.
Worker = Callable[[SecurityJob], Any]


@dataclass
class JobOutcome:
    """The terminal outcome of one ``run_one``: what happened to the claimed job (or ``empty``)."""

    state: str                       # "empty" | "busy" | "refused" | "done" | "failed"
    job: "SecurityJob | None" = None
    reason: str = ""
    denial_code: str = ""
    result: Any = None


@dataclass
class JobRunner:
    """Drives jobs off the queue through the gate into the worker — the single execution authority."""

    queue: SecurityJobQueue
    gate: Callable[[SecurityJob], Any]          # the authorization decision (build_repo_gate / conjunctive)
    worker: Worker
    assert_tenant: "Callable[[], None] | None" = None   # None ⇒ authorize_job's default tenant boundary

    def run_one(self) -> JobOutcome:
        """Claim one job and either run it (authorized) or refuse it (never run). The per-slug run lease is
        held for the job's whole lifetime, so two jobs for the SAME repo never run the slug's spine at once:
          * queue empty         → ``empty``.
          * slug already leased  → the job is RE-QUEUED (NOT completed) and ``busy`` is returned; the caller
                                   retries after the holder frees it (``drain`` stops on busy), so same-repo
                                   jobs run serially rather than racing the live one.
          * refused              → recorded ``refused`` and completed WITHOUT running the worker.
          * authorized           → the worker runs UNDER the lease; the lease is released and the job
                                   completed in ``finally`` (``done``/``failed``).
        Crash recovery for a DIED claimer is ``requeue_stale`` + the lease's own staleness reclaim."""
        claimed: "ClaimedJob | None" = self.queue.claim_next()
        if claimed is None:
            return JobOutcome(state="empty")
        job = claimed.job
        token = self.queue.try_lease(job.slug, run_id=claimed.job_id)
        if token is None:
            # Another worker holds this repo's slug — return it to the queue (do NOT complete) and report
            # busy, so the same-repo job runs later, serially, instead of racing the live run.
            self.queue.requeue(claimed)
            return JobOutcome(state="busy", job=job, reason=f"slug {job.slug!r} busy (held by a live run)")
        try:
            authz: JobAuthorization = (
                authorize_job(job, gate=self.gate, assert_tenant=self.assert_tenant)
                if self.assert_tenant is not None
                else authorize_job(job, gate=self.gate))
            if authz.refused:
                return JobOutcome(state="refused", job=job, reason=authz.reason,
                                  denial_code=authz.denial_code)
            # AUTHORIZED — and only now, holding the slug lease, is the worker invoked.
            try:
                result = self.worker(job)
                return JobOutcome(state="done", job=job, result=result)
            except Exception as e:  # noqa: BLE001 — a worker error is a job outcome, never a loop crash
                return JobOutcome(state="failed", job=job,
                                  reason=f"worker error: {type(e).__name__}: {e}")
        finally:
            self.queue.release_lease(job.slug, token)   # release BEFORE complete (mirror the scheduler)
            self.queue.complete(claimed)

    def drain(self, *, max_jobs: int = 0) -> "list[JobOutcome]":
        """Run queued jobs in order until the queue is empty (or ``max_jobs`` ran). Re-queues crashed claims
        first. A job whose slug is momentarily busy is left queued (outcome ``busy``) and draining STOPS so
        the caller retries after the busy slug frees — avoids spinning on a head-of-line busy slug (mirrors
        :meth:`EngagementScheduler.drain`)."""
        self.queue.requeue_stale()
        out: list[JobOutcome] = []
        while max_jobs <= 0 or len(out) < max_jobs:
            outcome = self.run_one()
            if outcome.state == "empty":
                break
            out.append(outcome)
            if outcome.state == "busy":
                break
        return out


def make_codescan_worker(*, base_dir: str, checkout: Callable[[SecurityJob], str],
                         max_files: int = 5000) -> Worker:
    """A worker that runs the existing ``codescan`` engine over a LOCAL checkout of the job's repo.

    ``checkout(job) -> local_root`` resolves the repo to an on-disk tree (a gated git checkout — the
    git-host client is a later slice; tests inject a fixture path). The worker then calls
    :func:`vigil_integration.codescan.run_codescan` (which needs a local root and writes findings to the
    slug's signed spine) — the discover→prove half of the lifecycle. It is invoked ONLY by
    :meth:`JobRunner.run_one`, i.e. only after the authorization gate allowed the job."""
    def _worker(job: SecurityJob) -> dict:
        from ..codescan import run_codescan
        root = checkout(job)
        return run_codescan(root=root, slug=job.slug, base_dir=base_dir, max_files=max_files)
    return _worker
