"""
jobs.redpen_system_trigger — the RED-PEN SYSTEM-REVIEW trigger + seam drain (R4).

The System sibling of :mod:`jobs.launch_trigger` / :mod:`launch_drain`. The sovereign plane reserves + mints an
owner-signed ``CreditLaunchLease`` for a whole-repository review and drops a TICKET on the redpen-system seam
(``live.redpen_system_seam``). :class:`RedPenSystemTrigger` reads each ticket and PRODUCES one
``SecurityJob(source="scheduled", profile="full")`` carrying the ticket's owner-signed lease in ``extra["lease"]``;
:class:`RedPenSystemDrain` ENQUEUES each onto the durable idempotent :class:`SecurityJobQueue`.

Like every trigger it ONLY PRODUCES jobs; it NEVER runs one. Execution stays SOLELY behind
``jobs.runner.JobRunner.run_one`` → ``authorize_job`` + the job gate — which re-verifies the carried owner-signed
lease against its OWN pinned owner key before any work runs, so a produced System job grants NO bypass (a ticket with
no cryptographically-verified lease is REFUSED at the gate, not run). This keeps the sovereign edge offense-free: the
sovereign plane only writes a ticket to the seam; this integration-plane drain turns it into queued work.

Idempotency: the ``delivery_id`` is the content-addressed :func:`system_delivery_id(slug, nonce)` (the shared
``work_delivery_id`` over ``(slug, None, nonce)``), so a re-poll of the same ticket coalesces in the queue's
PERMANENT delivery seen-set (exactly-once across polls), while a new period's ticket (new nonce) is a distinct key
and re-enqueues. The sovereign scheduler's per-period high-water already bounds how often a ticket is written, so a
single enqueue per period is enforced on BOTH sides.

FATAL-2: module scope imports only stdlib + :mod:`jobs.model` (pure) + :mod:`live.redpen_system_seam` (sovereign-safe:
``vigil_core`` + stdlib). ``framework.v2`` enters only when the queue is CONSTRUCTED (deferred inside
:class:`SecurityJobQueue`) — never at import. No ``sigil`` import. Registered in
``integration/tests/test_two_env_boundary.py``.
"""

from __future__ import annotations

import sys as _sys
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional

from .model import SecurityJob, work_delivery_id


def system_delivery_id(slug: str, nonce: str) -> str:
    """The content-addressed exactly-once key for one System review, ``(engagement_slug, nonce)`` — the shared
    :func:`work_delivery_id` over ``(repo=slug, pr_number=None, commit=nonce)``. A re-poll of the SAME ticket
    yields the SAME key (coalesces in the queue's permanent seen-set); a NEW period's ticket (new nonce) yields a
    new key, so it re-enqueues. Injective (JSON-encoded components, never joined)."""
    return work_delivery_id(slug, None, nonce)


def system_jobs_from_seam(base_dir: Any, *, now: Optional[float] = None) -> "list[SecurityJob]":
    """Read every System-review ticket on the seam under ``base_dir`` and return one
    ``SecurityJob(source="scheduled", profile="full")`` per readable ticket whose lease window is still OPEN at
    ``now`` (default: the clock). The owner-signed lease rides in ``extra["lease"]`` (+ its trust_root) so the job
    gate can verify it owner-pinned; ``profile="full"`` routes the job to the whole-tree System worker. The window
    check is HYGIENE, not authority (the gate re-verifies signature + window): it keeps a lapsed or already-settled
    ticket — the seam keeps one per repo until the next period overwrites it — from being re-enqueued only to be
    refused. TOTAL + fail-closed: a malformed ticket skips that ticket, never raises."""
    from ..live.redpen_system_seam import list_system_tickets    # same plane (sovereign-safe: vigil_core + stdlib)
    t = time.time() if now is None else float(now)
    out: "list[SecurityJob]" = []
    for ticket in list_system_tickets(base_dir):
        try:
            doc = ticket.signed_lease.document
            slug = str(doc.engagement_slug)
            nonce = str(doc.nonce)
            repo = str(ticket.repo)
            org_id = str(ticket.org_id)
            not_after = doc.not_after.timestamp()
            lease = ticket.signed_lease.model_dump(mode="json")
            trust_root = ticket.trust_root.model_dump(mode="json")
        except Exception:  # noqa: BLE001 — a malformed ticket is 'no job', never a crash / never a job
            continue
        if not (t < not_after):
            continue                    # the lease window has closed: nothing could run under it — no job
        if org_id != str(doc.org_id) or repo != str(doc.scope_host):
            continue                    # the ticket's labels must be the lease's own (signed) org + repo — no job
        try:
            job = SecurityJob.normalize(
                source="scheduled", repo=repo, engagement_slug=slug, tenant_id=org_id,
                # commit carries the lease NONCE so the work-fingerprint (tenant, repo, commit, profile, policy)
                # is per-PERIOD, not per-repo: a later period's ticket (new nonce) is distinct work and re-enqueues
                # even while an earlier System review of the same repo is in flight. A System review has no git
                # commit, so this overload is inert to the worker (it reviews the default-branch HEAD checkout).
                commit=nonce,
                profile="full",
                delivery_id=system_delivery_id(slug, nonce),
                extra={"lease": lease, "trust_root": trust_root, "repo": repo, "org_id": org_id,
                       "nonce": nonce, "profile": "full"})
        except ValueError:  # an empty repo or other invalid field — fail-closed, no job
            continue
        out.append(job)
    return out


@dataclass
class RedPenSystemTrigger:
    """A ``TriggerSource`` polling the redpen-system ticket seam: ``poll()`` returns one
    ``SecurityJob(profile="full")`` per readable open-window ticket, or ``[]``. Mirrors ``LaunchTrigger`` — it
    PRODUCES, it never executes (the queue + ``jobs.runner`` are the sole executors). ``now=None`` re-reads the clock
    at each poll (a long-lived poller); a fixed ``now`` is for tests."""

    base_dir: Any
    now: Optional[float] = None

    def poll(self) -> "list[SecurityJob]":
        try:
            return system_jobs_from_seam(self.base_dir, now=self.now)
        except Exception:  # noqa: BLE001 — a flaky seam read never sinks the drain (model.drain also guards)
            return []


class RedPenSystemDrain:
    """Polls the redpen-system ticket seam and ENQUEUES one ``SecurityJob(profile="full")`` per readable ticket
    onto the durable idempotent queue. Enqueue-only (the authorized runner is the sole executor). Idempotent by
    the queue's permanent content-addressed ``delivery_id`` — re-polls coalesce, a new period's ticket re-enqueues.
    The one-for-one twin of :class:`vigil_integration.launch_drain.LaunchSeamDrain`."""

    def __init__(self, *, base_dir: Any, queue_root: "str | Any | None" = None, queue: Any = None,
                 now: Optional[float] = None, trigger: Any = None) -> None:
        if queue is None and queue_root is None:
            raise ValueError("RedPenSystemDrain needs a queue (injected) or a queue_root to build one")
        self._base_dir = base_dir
        self._queue_root = queue_root
        self._q = queue                 # an injected SecurityJobQueue (tests), else built lazily
        self._now = now                 # None ⇒ the trigger re-reads the clock at each poll (a long-lived poller)
        self._trig = trigger            # an injected TriggerSource (tests), else a real RedPenSystemTrigger

    def _queue(self) -> Any:
        """The SecurityJobQueue, built LAZILY so this module/class stay sovereign-importable (the queue's
        framework import is deferred to construction, which only happens in the offense/integration run)."""
        if self._q is None:
            from .queue import SecurityJobQueue   # lazy (two-env: framework deferred inside the queue)
            self._q = SecurityJobQueue(self._queue_root)
        return self._q

    def _trigger(self) -> Any:
        if self._trig is None:
            self._trig = RedPenSystemTrigger(base_dir=self._base_dir, now=self._now)
        return self._trig

    def drain(self) -> dict:
        """Poll the seam once and enqueue each System-review job. Returns ``{enqueued, duplicate, deferred}``.
        ENQUEUE-ONLY — never runs a job. A ``duplicate`` is the terminal coalesce of a re-polled ticket; a
        ``deferred`` is a transient enqueue failure the next drain retries off the untouched seam (the ticket is
        not claimed/moved, so there is nothing to un-claim)."""
        enqueued = duplicate = deferred = 0
        queue = self._queue()   # built once; surfaces a misconfig (e.g. framework unavailable) BEFORE polling
        for job in self._trigger().poll():
            try:
                res = queue.enqueue(job)
            except OSError:   # transient durable-insert failure — enqueue rolled back its OWN markers; the ticket
                deferred += 1  # is untouched on the seam, so the next drain re-polls and retries cleanly
                continue
            if getattr(res, "enqueued", False):
                enqueued += 1
            else:             # duplicate_delivery / duplicate_fingerprint — TERMINAL: the queue has coalesced it
                duplicate += 1
        return {"enqueued": enqueued, "duplicate": duplicate, "deferred": deferred}

    def watch(self, *, interval: float = 2.0, sleep: Optional[Callable[[float], None]] = None) -> None:
        """Drain in a loop forever (Ctrl-C / SIGTERM to stop). A single bad drain NEVER kills the daemon: an
        unexpected error is reported to stderr and the loop continues. ``sleep`` is injectable for tests."""
        import time
        _sleep = sleep or time.sleep
        while True:
            try:
                self.drain()
            except Exception as exc:  # noqa: BLE001 — the watch loop must survive any single-drain failure
                _sys.stderr.write("vigil redpen-schedule: WARNING drain error (continuing): "
                                  f"{type(exc).__name__}: {exc}\n")
            _sleep(interval)
