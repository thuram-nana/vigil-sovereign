"""engagement_scheduler — a durable, ordered, crash-safe queue/scheduler ABOVE the run boundary (Wave D / D1).

``engage.run_engagement`` is a clean per-engagement job boundary: one call runs one authorized engagement
end to end. Before this module there was no layer that decided WHICH engagement runs next, or that enforced
"at most one live engagement per slug" across the whole system — the launch guard was per-launch only.

This is that layer. It is a small file-backed FIFO with three states — ``queue/`` (pending), ``running/``
(claimed), ``done/`` (finished) — where every transition is a single atomic filesystem operation, so it is
durable across a crash and safe under concurrent workers:

* ENQUEUE allocates a strictly monotonic sequence and creates ``queue/<seq>.json`` with ``O_EXCL`` — a
  sequence collision (two enqueuers) is resolved by retrying the next free sequence, so ordering is total
  and no job is dropped.
* CLAIM (dequeue) takes the lowest pending sequence and ``os.rename``s it ``queue/ → running/``. Rename is
  atomic, so of N workers racing for the head exactly one claims it; the losers move to the next sequence.
  Order is FIFO: jobs run in enqueue order.
* Running a claimed job first acquires that slug's :class:`~framework.v2.slug_lease.SlugLease`. If the slug
  is already leased (a live engagement of it), the job is re-queued at its ORIGINAL sequence (FIFO preserved)
  and the caller is told the slug is busy — two engagements of one slug never run concurrently.
* COMPLETE renames ``running/ → done/`` (audit trail) atomically.
* CRASH recovery: a worker that dies mid-run leaves its job in ``running/`` recording the worker's pid+boot;
  :meth:`requeue_stale` renames any such job whose worker is gone back to ``queue/`` — a crashed worker never
  strands a job, and the slug's own lease is independently reclaimable (see slug_lease).

Import-clean: stdlib only plus :mod:`framework.v2.slug_lease` (also stdlib-only). ``run_engagement`` is
imported lazily by :func:`default_engagement_runner` so scheduling a job never drags the heavy engine into
processes that only enqueue.
"""
from __future__ import annotations

import json
import os
import secrets
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .slug_lease import SlugLease, _boot_id, _pid_alive

#: Zero-padded width for the sequence filename, so lexical order == numeric order for the lifetime of a
#: queue (10^15 enqueues is unreachable; ordering degrades gracefully past it because claim_next also sorts
#: numerically).
_SEQ_WIDTH = 15
_MAX_SEQ_PROBE = 4096   # bounded search for the next free sequence under concurrent enqueue


@dataclass
class EngagementJob:
    """One queued engagement. ``slug`` + ``seed_url`` + ``params`` are exactly what a runner forwards to
    ``run_engagement``; ``job_id`` and ``seq`` are assigned at enqueue (``seq`` fixes FIFO order)."""

    slug: str
    seed_url: str = ""
    params: dict = field(default_factory=dict)
    job_id: str = ""
    seq: int = -1

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)

    @staticmethod
    def from_dict(d: dict) -> "EngagementJob":
        return EngagementJob(
            slug=str(d.get("slug") or ""),
            seed_url=str(d.get("seed_url") or ""),
            params=dict(d.get("params") or {}),
            job_id=str(d.get("job_id") or ""),
            seq=int(d.get("seq", -1)),
        )


@dataclass
class ScheduleOutcome:
    """The result of :meth:`EngagementScheduler.run_next`. Exactly one of ``ran`` / ``busy`` / ``empty``."""

    status: str                 # "ran" | "busy" | "empty"
    job: "EngagementJob | None" = None
    result: object = None       # the runner's return value when status == "ran"
    error: str = ""


class EngagementScheduler:
    """A durable FIFO scheduler of engagements with per-slug exclusivity. ``root`` holds the queue state;
    ``lease`` is the :class:`SlugLease` that enforces one live engagement per slug (defaults to
    ``root/leases``)."""

    def __init__(self, root: "str | os.PathLike", *, lease: "SlugLease | None" = None) -> None:
        self.root = Path(root)
        self.q = self.root / "queue"
        self.running = self.root / "running"
        self.done = self.root / "done"
        for d in (self.q, self.running, self.done):
            d.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lease = lease or SlugLease(self.root / "leases")

    # -- helpers -------------------------------------------------------------------------------------
    def _name(self, seq: int) -> str:
        return f"{seq:0{_SEQ_WIDTH}d}.json"

    def _seq_of(self, name: str) -> int:
        try:
            return int(name.split(".", 1)[0])
        except (ValueError, IndexError):
            return -1

    def _max_seq(self) -> int:
        hi = -1
        for d in (self.q, self.running, self.done):
            try:
                for f in d.iterdir():
                    hi = max(hi, self._seq_of(f.name))
            except OSError:
                continue
        return hi

    def _fsync_dir(self, d: Path) -> None:
        try:
            dfd = os.open(str(d), os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(dfd)
        except OSError:
            pass
        finally:
            os.close(dfd)

    def _read_job(self, path: Path) -> "EngagementJob | None":
        try:
            obj = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return EngagementJob.from_dict(obj) if isinstance(obj, dict) else None

    # -- enqueue -------------------------------------------------------------------------------------
    def enqueue(self, slug: str, seed_url: str = "", *, params: "dict | None" = None) -> EngagementJob:
        """Append an engagement to the queue and return it with its assigned ``seq``/``job_id``. Atomic: the
        sequence is claimed by an ``O_EXCL`` create, so two concurrent enqueues get distinct, ordered slots
        and neither is lost. Raises ValueError on an empty slug."""
        s = str(slug or "").strip()
        if not s:
            raise ValueError("refusing to enqueue an engagement with an empty slug")
        job = EngagementJob(slug=s, seed_url=str(seed_url or ""), params=dict(params or {}),
                            job_id=secrets.token_hex(8))
        start = self._max_seq() + 1
        for cand in range(start, start + _MAX_SEQ_PROBE):
            path = self.q / self._name(cand)
            try:
                fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                continue                        # another enqueuer took this seq — try the next
            except OSError as e:
                raise OSError(f"could not enqueue engagement ({type(e).__name__})") from e
            job.seq = cand
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(job.to_json())
                fh.flush()
                os.fsync(fh.fileno())
            self._fsync_dir(self.q)
            return job
        raise RuntimeError("could not allocate a queue sequence (too much concurrent enqueue contention)")

    # -- inspection ----------------------------------------------------------------------------------
    def pending(self) -> "list[EngagementJob]":
        """All queued jobs, in FIFO (enqueue) order. Total; a torn file is skipped."""
        out: list[EngagementJob] = []
        try:
            names = sorted((f.name for f in self.q.iterdir() if f.name.endswith(".json")),
                           key=self._seq_of)
        except OSError:
            return out
        for name in names:
            job = self._read_job(self.q / name)
            if job is not None:
                out.append(job)
        return out

    def pending_count(self) -> int:
        return len(self.pending())

    # -- claim / requeue / complete ------------------------------------------------------------------
    def claim_next(self) -> "EngagementJob | None":
        """Atomically claim the head (lowest ``seq``) pending job for execution, moving it ``queue/ →
        running/`` and stamping the claiming worker's pid+boot for crash recovery. Returns the job, or None
        if the queue is empty. Of N workers racing for the head exactly one wins (rename is atomic); a loser
        transparently tries the next job."""
        try:
            names = sorted((f.name for f in self.q.iterdir() if f.name.endswith(".json")),
                           key=self._seq_of)
        except OSError:
            return None
        for name in names:
            src = self.q / name
            dst = self.running / name
            try:
                os.rename(str(src), str(dst))   # atomic single-claim; a lost race raises below
            except FileNotFoundError:
                continue                        # another worker claimed this one — try the next
            except OSError:
                continue
            job = self._read_job(dst)
            if job is None:
                self._safe_unlink(dst)          # torn job file — drop it and move on
                continue
            self._stamp_claimer(dst, job)
            return job
        return None

    def _stamp_claimer(self, path: Path, job: EngagementJob) -> None:
        """Record the claiming worker's pid+boot on the running job, so :meth:`requeue_stale` can tell a live
        run from a crashed one. Best-effort — a stamp failure leaves the plain job (requeue_stale then treats
        an unstamped running job conservatively as live)."""
        doc = asdict(job)
        doc["_claimer"] = {"pid": os.getpid(), "boot_id": _boot_id(), "ts": time.time()}
        try:
            path.write_text(json.dumps(doc, sort_keys=True), encoding="utf-8")
        except OSError:
            pass

    def _claimer_alive(self, path: Path) -> bool:
        """True iff the running job's claimer is still alive. An unstamped or torn running file is treated as
        LIVE (conservative — never yank a job from under a run we cannot prove dead)."""
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return True
        c = doc.get("_claimer") if isinstance(doc, dict) else None
        if not isinstance(c, dict):
            return True
        pid = c.get("pid")
        boot = str(c.get("boot_id") or "")
        cur = _boot_id()
        if cur and boot and cur != boot:
            return False                        # a reboot killed the claimer
        return _pid_alive(pid)

    def requeue(self, job: EngagementJob) -> bool:
        """Return a claimed job to the queue at its ORIGINAL sequence (FIFO preserved). Atomic rename
        ``running/ → queue/``; used when a slug is busy or by :meth:`requeue_stale`."""
        name = self._name(job.seq)
        src = self.running / name
        dst = self.q / name
        # rewrite the plain job (drop the _claimer stamp) so a re-claim re-stamps cleanly
        try:
            src.write_text(job.to_json(), encoding="utf-8")
        except OSError:
            pass
        try:
            os.rename(str(src), str(dst))
            self._fsync_dir(self.q)
            return True
        except OSError:
            return False

    def requeue_stale(self) -> int:
        """Crash recovery: move every ``running/`` job whose claiming worker is GONE back to ``queue/``.
        Returns the count requeued. Total; safe to call at startup and idempotent under concurrent callers
        (a rename that loses simply counts nothing)."""
        n = 0
        try:
            names = sorted((f.name for f in self.running.iterdir() if f.name.endswith(".json")),
                           key=self._seq_of)
        except OSError:
            return 0
        for name in names:
            path = self.running / name
            if self._claimer_alive(path):
                continue
            job = self._read_job(path)
            if job is None:
                continue
            if self.requeue(job):
                n += 1
        return n

    def complete(self, job: EngagementJob) -> None:
        """Mark a claimed job finished: move ``running/ → done/`` (kept as an audit trail). Best-effort."""
        name = self._name(job.seq)
        src = self.running / name
        dst = self.done / name
        try:
            os.rename(str(src), str(dst))
            self._fsync_dir(self.done)
        except OSError:
            self._safe_unlink(src)

    def _safe_unlink(self, path: Path) -> None:
        try:
            path.unlink()
        except OSError:
            pass

    # -- run -----------------------------------------------------------------------------------------
    def run_next(self, runner) -> ScheduleOutcome:
        """Claim the head job, acquire its slug lease, run it via ``runner(job)``, then release the lease and
        mark the job done. If the queue is empty → ``status='empty'``. If the head's slug is already leased
        (a live engagement of it) the job is re-queued in place and ``status='busy'`` is returned — the
        caller retries later; two engagements of one slug never run at once. The lease is ALWAYS released and
        the job ALWAYS moved out of ``running/`` (even if the runner raises)."""
        job = self.claim_next()
        if job is None:
            return ScheduleOutcome(status="empty")
        acq = self.lease.acquire(job.slug, run_id=job.job_id)
        if not acq.ok:
            self.requeue(job)                   # slug busy → back to the queue, FIFO order preserved
            return ScheduleOutcome(status="busy", job=job, error=acq.reason)
        try:
            result = runner(job)
            return ScheduleOutcome(status="ran", job=job, result=result)
        except Exception as e:  # noqa: BLE001 — surface the failure; teardown still runs in finally
            return ScheduleOutcome(status="ran", job=job, error=f"{type(e).__name__}: {e}")
        finally:
            self.lease.release(job.slug, acq.token)
            self.complete(job)

    def drain(self, runner, *, max_jobs: int = 0) -> "list[ScheduleOutcome]":
        """Run queued jobs in order until the queue is empty or ``max_jobs`` (0 = no cap) have run. A job
        whose slug is momentarily busy is left queued (its outcome is recorded 'busy') and draining stops so
        the caller can retry after the busy slug frees — this avoids spinning on a head-of-line busy slug."""
        outcomes: list[ScheduleOutcome] = []
        while True:
            out = self.run_next(runner)
            if out.status == "empty":
                break
            outcomes.append(out)
            if out.status == "busy":
                break                           # head is busy — stop; caller retries later
            if max_jobs and len(outcomes) >= max_jobs:
                break
        return outcomes


def default_engagement_runner(job: EngagementJob):
    """A runner that calls :func:`framework.v2.engage.run_engagement` with the job's slug/seed/params —
    the concrete tie between this scheduler layer and the run boundary. ``run_engagement`` is imported
    lazily so merely scheduling a job never imports the heavy engine."""
    from .engage import run_engagement
    return run_engagement(job.slug, job.seed_url, **dict(job.params or {}))
