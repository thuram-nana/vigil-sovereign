"""launch_drain — the CUSTOMER-LAUNCH seam poller: a published owner-signed lease → an enqueued SecurityJob.

The customer-launch sibling of :mod:`webhook_drain` (K4-5c). The sovereign plane RESERVES credits and mints +
PUBLISHES an owner-signed ``CreditLaunchLease`` to the cross-plane credit-lease seam
(``LaunchGate.publish_lease`` → ``live.credit_lease_broker``). This poller reads that seam through the K4-2
:class:`~vigil_integration.jobs.launch_trigger.LaunchTrigger` — which runs the KEYLESS
``verify_customer_launch_lease(consume=False)`` pre-check (owner-PIN verify + bind slug/host/tenant/window +
the K4-1 settlement re-check, floor NOT burned) and yields one verified ``SecurityJob(source="api")`` per
currently-valid lease — and ENQUEUES each onto the durable idempotent :class:`SecurityJobQueue`.

It is ENQUEUE-ONLY, exactly like ``webhook_drain``: it NEVER runs a job. Execution stays SOLELY behind
``jobs.runner.JobRunner.run_one`` → ``authorize_job`` + the K4-3 customer-launch gate (verified customer
authority ∧ owner-signed lease ∧ the production-disable flag), so a produced launch job grants NO bypass — a
customer engagement with no cryptographically-verified authority + lease is REFUSED at the gate, not run.
This keeps the sovereign edge offense-free: the sovereign plane only ``publish_lease``s to the seam; this
integration-plane poller is what turns a published lease into queued work.

Idempotency — ONE layer, and it is enough (the design distinction from ``webhook_drain``): the credit-lease
seam IS the source of truth (there is no inbound spool of inert files to byte-dedup), and the queue's
PERMANENT ``delivery_id`` seen-set is the single exactly-once gate. ``LaunchTrigger`` keys every job's
``delivery_id`` to the content-addressed ``(engagement_slug, nonce)`` (:func:`launch_delivery_id`), so:
  * a RE-POLL of the same published lease yields the SAME delivery_id → ``duplicate_delivery`` (coalesced,
    counted as ``duplicate``, never re-enqueued) — exactly-once across the poll loop;
  * once a run SETTLES (K4-5b tombstones the lease + marks ``(slug, nonce)``), the ``consume=False``
    settlement re-check inside ``poll()`` stops producing a job for it — the settled lease drains to nothing;
  * a genuine RE-LEASE (new ``nonce``) is a DISTINCT delivery_id AND work-fingerprint, so it re-enqueues even
    while an earlier launch of the same engagement is still in flight (a separately-paid launch is never
    silently dropped — the K4-2 red-pen fix).
Because nothing is claimed/moved off the seam (unlike a spool file), a transient enqueue ``OSError`` needs no
un-claim: ``queue.enqueue`` rolls back its OWN markers and the next drain re-polls the untouched lease and
retries cleanly. So a failed enqueue is simply DEFERRED to the next tick, never a lost or double job.

FATAL-2: module scope imports only stdlib + :mod:`jobs.launch_trigger` (itself framework-free at module scope
— the keyless ``verify`` is lazy inside ``poll()``) + :mod:`jobs.model` (pure). ``framework.v2`` enters only
when the queue is CONSTRUCTED (deferred inside :class:`SecurityJobQueue`) and when ``poll()`` runs the verify
— never at import. No ``sigil`` import. Registered in ``integration/tests/test_two_env_boundary.py``.
"""

from __future__ import annotations

import sys as _sys
from typing import Any, Callable, Optional

from .jobs.launch_trigger import LaunchTrigger   # framework-free at module scope (the keyless verify is lazy in poll())


class LaunchSeamDrain:
    """Polls the credit-launch-lease seam and ENQUEUES one SecurityJob per currently-valid published lease
    onto the durable idempotent queue. Enqueue-only (the authorized runner is the sole executor). Idempotent
    by the queue's permanent content-addressed ``delivery_id``, so re-polls coalesce and a settled lease
    drains to nothing."""

    def __init__(self, *, base_dir: Any, queue_root: "str | Any | None" = None, queue: Any = None,
                 now: Optional[float] = None, trigger: Any = None) -> None:
        if queue is None and queue_root is None:
            raise ValueError("LaunchSeamDrain needs a queue (injected) or a queue_root to build one")
        self._base_dir = base_dir
        self._queue_root = queue_root
        self._q = queue                 # an injected SecurityJobQueue (tests), else built lazily
        self._now = now                 # None ⇒ LaunchTrigger re-reads the clock at each poll (a long-lived poller)
        self._trig = trigger            # an injected TriggerSource (tests), else a real LaunchTrigger

    def _queue(self) -> Any:
        """The SecurityJobQueue, built LAZILY so this module/class stay sovereign-importable (the queue's
        framework import is deferred to construction, which only happens in the offense/integration run)."""
        if self._q is None:
            from .jobs.queue import SecurityJobQueue   # lazy (two-env: framework deferred inside the queue)
            self._q = SecurityJobQueue(self._queue_root)
        return self._q

    def _trigger(self) -> Any:
        """The LaunchTrigger over the seam (cached). ``poll()`` re-reads the seam AND (when ``now is None``)
        the clock on every call, so one cached trigger drives every tick of a ``watch()`` loop correctly."""
        if self._trig is None:
            self._trig = LaunchTrigger(base_dir=self._base_dir, now=self._now)
        return self._trig

    def drain(self) -> dict:
        """Poll the seam once and enqueue each verified launch job. Returns ``{enqueued, duplicate, deferred}``.
        ENQUEUE-ONLY — never runs a job. ``poll()`` is total + fail-closed (a malformed/forged/settled lease
        yields NO job, never raises — so there is nothing to 'reject' at this layer; the keyless ``consume``
        floor is left for the engine arm). A ``duplicate`` is the terminal coalesce of a re-polled or in-flight
        launch; a ``deferred`` is a transient enqueue failure that the next drain retries off the untouched
        seam."""
        enqueued = duplicate = deferred = 0
        queue = self._queue()   # built once; surfaces a misconfig (e.g. framework unavailable) BEFORE polling
        for job in self._trigger().poll():
            try:
                res = queue.enqueue(job)
            except OSError:   # transient durable-insert failure — enqueue rolled back its OWN markers; the lease
                deferred += 1  # is untouched on the seam, so the next drain re-polls and retries cleanly (no un-claim)
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
                _sys.stderr.write("vigil launch-drain: WARNING drain error (continuing): "
                                  f"{type(exc).__name__}: {exc}\n")
            _sleep(interval)
