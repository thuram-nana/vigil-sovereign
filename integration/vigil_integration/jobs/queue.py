"""
jobs.queue — the DURABLE, IDEMPOTENT, DEDUPLICATED queue a ``SecurityJob`` flows through.

The spine alone cannot enforce idempotency or a single-winner claim, so this REUSES the primitives built
for exactly that (confirmed driver-less today): :class:`framework.v2.engagement_scheduler.EngagementScheduler`
(durable file-FIFO; atomic ``claim_next`` via an ``O_EXCL``/rename single-winner; ``requeue_stale`` crash
recovery; the ``claim → slug-lease → run → complete`` control-flow in ``run_next``, reused WHOLESALE) and
:class:`framework.v2.slug_lease.SlugLease` (the per-slug run lease the scheduler already holds).

On top of the scheduler this adds the two dedup keys the architecture requires, each an ATOMIC ``O_EXCL``
marker so concurrent enqueuers coalesce:
  * ``delivery_id`` → the EXACTLY-ONCE idempotency key (a re-delivered webhook enqueues at most once).
    Permanent (a seen-set), so a replay is dropped forever.
  * the canonical ``fingerprint`` → the WORK dedup key (same tenant+repo+commit+profile+policy already
    in flight ⇒ don't enqueue a second identical scan). Cleared on completion so a later commit re-scans.

Integration-layer code: imports ``framework.v2`` (the offense engine it federates) + stdlib only — NO
``sigil`` import.
"""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .model import SecurityJob

if TYPE_CHECKING:  # annotations only — framework is imported LAZILY at runtime (two-env: stay sovereign-importable)
    from framework.v2.engagement_scheduler import EngagementJob, EngagementScheduler


@dataclass(frozen=True)
class EnqueueResult:
    """Outcome of an enqueue: ``enqueued`` is False (with a ``reason``) when a dedup key coalesced it."""

    enqueued: bool
    reason: str
    job_id: str = ""
    seq: int = -1


@dataclass
class ClaimedJob:
    """A job claimed for execution — the ``SecurityJob`` plus the underlying scheduler row to complete."""

    job: SecurityJob
    _ej: EngagementJob

    @property
    def job_id(self) -> str:
        """The underlying scheduler row id — passed as the run-lease ``run_id`` for crash-recovery/audit."""
        return getattr(self._ej, "job_id", "")


def _safe_key(value: str) -> str:
    """A filesystem-safe, collision-resistant marker name for an untrusted key (hash it — never trust a
    remote delivery_id to be a safe path component)."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class SecurityJobQueue:
    """The durable, idempotent, deduplicated ``SecurityJob`` queue (wraps ``EngagementScheduler``)."""

    def __init__(self, root: "str | os.PathLike", *, scheduler: "EngagementScheduler | None" = None) -> None:
        self._root = Path(root)
        if scheduler is None:
            from framework.v2.engagement_scheduler import EngagementScheduler  # lazy (two-env)
            scheduler = EngagementScheduler(self._root)
        self._sched = scheduler
        self._delivery_dir = self._root / "delivery"     # permanent idempotency seen-set
        self._fingerprint_dir = self._root / "fingerprint"  # in-flight work dedup (cleared on complete)
        self._lease_dir = self._root / "leases"          # per-slug run lease (same dir the scheduler uses)
        self._lease: Any = None                          # SlugLease, lazily built (framework import is two-env)
        for d in (self._delivery_dir, self._fingerprint_dir, self._lease_dir):
            d.mkdir(parents=True, exist_ok=True)
            try:
                d.chmod(0o700)
            except OSError:
                pass

    # -- dedup markers (atomic O_EXCL: True iff THIS caller created it) ---------------------------------

    @staticmethod
    def _claim_marker(path: Path) -> bool:
        """Create ``path`` atomically; True iff newly created, False iff it already existed. Any other
        error propagates (fail LOUD on a broken dedup store rather than silently duplicating/dropping)."""
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
            return True
        except FileExistsError:
            return False

    def _clear_fingerprint(self, fingerprint: str) -> None:
        try:
            (self._fingerprint_dir / fingerprint).unlink(missing_ok=True)
        except OSError:
            pass

    @staticmethod
    def _rollback(markers: "list[Path]") -> None:
        """Compensating rollback: unlink markers THIS enqueue created, so none outlives the job it guards
        when the durable insert fails (an orphaned delivery marker would drop the retried job forever; an
        orphaned fingerprint marker would wedge re-enqueue until a completion that can never come)."""
        for marker in markers:
            try:
                marker.unlink(missing_ok=True)
            except OSError:
                pass

    # -- enqueue (idempotent + deduplicated) -----------------------------------------------------------

    def enqueue(self, job: SecurityJob) -> EnqueueResult:
        """Enqueue a job unless a dedup key coalesces it. Order: delivery_id idempotency FIRST (a replay is
        dropped permanently), then the work fingerprint (a same-work scan already in flight is dropped,
        re-allowed after the first completes). ATOMIC: the markers this call creates are rolled back if the
        durable scheduler insert raises, so a transient failure never permanently loses a job or wedges a
        fingerprint — the caller may safely retry the same job."""
        created: "list[Path]" = []
        if job.delivery_id:
            delivery_marker = self._delivery_dir / _safe_key(job.delivery_id)
            if not self._claim_marker(delivery_marker):
                return EnqueueResult(enqueued=False, reason="duplicate_delivery")
            created.append(delivery_marker)
        fingerprint_marker = self._fingerprint_dir / job.fingerprint
        if not self._claim_marker(fingerprint_marker):
            # The delivery marker (if any) is intentionally KEPT: this delivery has been decided — coalesced
            # into the in-flight same-work run — so a later replay of it must stay a no-op, not spawn a dup.
            return EnqueueResult(enqueued=False, reason="duplicate_fingerprint")
        created.append(fingerprint_marker)
        try:
            ej = self._sched.enqueue(job.slug, params=job.to_params())
        except Exception:                        # noqa: BLE001 — any insert failure must leave NO orphaned marker
            self._rollback(created)
            raise
        return EnqueueResult(enqueued=True, reason="enqueued", job_id=ej.job_id, seq=ej.seq)

    # -- claim / complete (lower level; single-winner via the scheduler's atomic rename) ---------------

    def claim_next(self) -> "ClaimedJob | None":
        ej = self._sched.claim_next()
        if ej is None:
            return None
        return ClaimedJob(job=SecurityJob.from_params(ej.params), _ej=ej)

    def complete(self, claimed: ClaimedJob) -> None:
        """Mark the job done and clear its work-fingerprint (so a later commit of the same repo re-scans).
        The delivery_id marker is kept — idempotency is permanent."""
        self._sched.complete(claimed._ej)
        self._clear_fingerprint(claimed.job.fingerprint)

    def requeue(self, claimed: ClaimedJob) -> None:
        """Return a claimed job to the queue (markers kept — it is the SAME job, still in flight)."""
        self._sched.requeue(claimed._ej)

    def requeue_stale(self) -> int:
        """Crash recovery: re-queue jobs whose claimer died (delegates to the scheduler)."""
        return self._sched.requeue_stale()

    def pending_count(self) -> int:
        return self._sched.pending_count()

    # -- per-slug run lease (the runner holds it so two same-repo jobs never race the spine) ------------

    def _leases(self) -> Any:
        """The per-slug run lease, lazily built against the same dir the scheduler uses (framework import
        is two-env-gated, so it is deferred until first use rather than taken at construction)."""
        if self._lease is None:
            from framework.v2.slug_lease import SlugLease  # lazy (two-env)
            self._lease = SlugLease(self._lease_dir)
        return self._lease

    def try_lease(self, slug: str, *, run_id: str = "") -> "str | None":
        """Acquire the EXCLUSIVE per-slug run lease; return its token, or None if another worker holds it.
        The runner MUST hold this for a job's whole lifetime so two jobs for the same repo can never run
        the slug's spine concurrently (a corrupt interleave). Atomic + cross-process (key = sha256(slug))."""
        result = self._leases().acquire(slug, run_id=run_id)
        return getattr(result, "token", None) if getattr(result, "ok", False) else None

    def release_lease(self, slug: str, token: str) -> None:
        """Release a lease taken by :meth:`try_lease`. Best-effort — a crashed holder is recovered by the
        lease's own staleness reclaim, so a failed release never wedges the slug permanently."""
        try:
            self._leases().release(slug, token)
        except Exception:                        # noqa: BLE001 — staleness reclaim is the backstop
            pass

    def prune_delivery(self, *, older_than_seconds: float) -> int:
        """Retention for the PERMANENT delivery seen-set (idempotency markers accumulate forever otherwise).
        Removes delivery markers older than ``older_than_seconds`` by mtime and returns the count removed.
        Operator-driven (a delivery's exactly-once window is finite); NEVER called on the enqueue path."""
        cutoff = time.time() - max(0.0, float(older_than_seconds))
        removed = 0
        try:
            entries = list(self._delivery_dir.iterdir())
        except OSError:
            return 0
        for marker in entries:
            try:
                if marker.is_file() and marker.stat().st_mtime < cutoff:
                    marker.unlink(missing_ok=True)
                    removed += 1
            except OSError:
                continue
        return removed

    # NOTE: the queue deliberately exposes NO "run a callback" method. Execution happens SOLELY through
    # jobs.runner.JobRunner.run_one, which claims → AUTHORIZES → runs → completes. A raw run-a-callback
    # helper here would be a gate bypass (a caller could run a worker without the authorization gate), so
    # it is omitted by design — the queue only enqueues/claims/completes; the runner is the sole executor.
