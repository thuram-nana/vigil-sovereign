"""
jobs.launch_trigger — the CUSTOMER-LAUNCH trigger adapter (slice K4-2).

A customer reserves credits and the sovereign plane mints + PUBLISHES an owner-signed ``CreditLaunchLease``
to the cross-plane seam (``LaunchGate.publish_lease``). This adapter — the sibling of :mod:`jobs.ci_trigger`
— reads the published lease(s) and PRODUCES one :class:`SecurityJob` (``source="api"``) per lease that
passes the KEYLESS enqueue PRE-CHECK ``verify_customer_launch_lease(consume=False)``:

  * owner-PINNED signature verify (never the seam-carried trust_root),
  * BIND (the lease's own engagement_slug / scope_host / org_id / ``[not_before, not_after)`` window), and
  * the K4-1 SETTLEMENT re-check (a settled/canceled lease is refused),

all WITHOUT burning the single-use ``issued_at`` floor — the engine ARM (``consume=True``, inside
``run_engagement``) is the ONE authoritative consume, so the pre-check neither charges nor burns.
A lease that is absent / expired / settled / forged / malformed yields NO job (fail-closed).

Like every trigger it ONLY PRODUCES jobs; it NEVER runs one. Execution stays solely behind the queue + the
authorized worker (``jobs.runner.JobRunner.run_one`` → ``authorize_job``), so a produced launch job grants
NO bypass — a customer engagement with no cryptographically-verified authority + lease is REFUSED at the
gate, not run.

The ``delivery_id`` is the content-addressed :func:`work_delivery_id(slug, nonce)` (NOT a wall-clock tick),
so a re-poll of the same ``(slug, nonce)`` coalesces in the queue's permanent delivery seen-set
(exactly-once across polls); a genuine re-lease (new ``nonce``) is a new delivery key, so it re-enqueues.
The job's ``engagement_slug`` is the owner-signed ``cust_<hash>`` slug, so the queue's scheduler slug and
per-slug run lease key to THAT exact engagement (the authority + lease are keyed by it), never a
repo-derived mangle.

Integration-layer code: imports ``.model`` (pure) + ``vigil_integration.live`` seam (sovereign-safe) at
module scope; ``framework.v2.launch_lease`` (the keyless offense verify) is imported LAZILY inside the
function — NO ``framework`` at module scope, NO ``sigil`` import, NO execution (two-env boundary; registered
in ``integration/tests/test_two_env_boundary.py``).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Optional

from .model import SecurityJob, work_delivery_id


def launch_delivery_id(slug: str, nonce: str) -> str:
    """The content-addressed exactly-once key for one customer launch, ``(engagement_slug, nonce)`` — the
    shared :func:`work_delivery_id` over ``(repo=slug, pr_number=None, commit=nonce)``. A re-poll of the SAME
    published lease yields the SAME key (coalesces in the queue's permanent seen-set); a genuine re-lease
    (new ``nonce``) yields a NEW key, so it re-enqueues. Injective (JSON-encoded components, never joined)."""
    return work_delivery_id(slug, None, nonce)


def _seed_url_for(host: str) -> str:
    """The engagement seed for a verified host — ``https://<host>``. A convenience carrier only: the ARM
    RE-BINDS the host AUTHORITATIVELY from the verified lease (K4-3 gate + the engine arm), so a tampered
    seed never widens scope — it just fails the bind and refuses."""
    h = str(host or "").strip()
    return f"https://{h}" if h else ""


def launch_jobs_from_seam(base_dir: Any, *, now: Optional[float] = None) -> "list[SecurityJob]":
    """Read every published credit-launch lease on the seam under ``base_dir`` and return one
    ``SecurityJob(source="api")`` per lease that PASSES the keyless ``consume=False`` pre-check (owner-pin +
    bind + K4-1 settlement re-check, floor NOT burned). Absent/expired/settled/forged/malformed → no job.
    TOTAL + fail-closed: a malformed bundle or a pre-check failure skips that lease, never raises."""
    t = time.time() if now is None else float(now)
    from vigil_integration.live.credit_lease_broker import list_credit_leases     # same plane (sovereign-safe)
    from framework.v2.launch_lease import verify_customer_launch_lease            # framework LAZY (two-env)
    out: "list[SecurityJob]" = []
    for bundle in list_credit_leases(base_dir):
        try:
            doc = bundle.signed_lease.document
            slug = str(doc.engagement_slug)
            host = str(doc.scope_host)
            tenant = str(doc.org_id)
            nonce = str(doc.nonce)
        except Exception:  # noqa: BLE001 — a malformed bundle is 'no lease', never a crash / never a job
            continue
        # Enqueue PRE-CHECK: verify owner-pinned, bind the lease to its OWN slug/host/tenant/window, and
        # refuse a settled lease — but consume=False so the single-use floor is left for the engine arm.
        ok, _reason = verify_customer_launch_lease(slug, host, tenant, base_dir=base_dir, now=t, consume=False)
        if not ok:
            continue
        try:
            job = SecurityJob.normalize(
                source="api", repo=host, engagement_slug=slug, tenant_id=tenant,
                # commit carries the lease NONCE so the work-fingerprint (tenant, repo, commit, profile,
                # policy) is per-LAUNCH, not per-engagement. Without it every launch of the same (org, host)
                # hashes identically (commit=""), so a genuine re-lease (new nonce) racing an in-flight launch
                # would collide on `duplicate_fingerprint`, be dropped, and — its delivery marker kept — never
                # re-enqueue: a separately-paid launch stranded forever. A launch has no git commit, so this
                # overload is inert to the worker (it seeds from the verified authority scope, never job.commit).
                commit=nonce,
                delivery_id=launch_delivery_id(slug, nonce),
                extra={"seed_url": _seed_url_for(host), "host": host, "nonce": nonce, "org_id": tenant})
        except ValueError:  # an empty host (no target) or other invalid field — fail-closed, no job
            continue
        out.append(job)
    return out


@dataclass
class LaunchTrigger:
    """A ``TriggerSource`` polling the credit-launch-lease seam: ``poll()`` returns one ``SecurityJob`` per
    currently-valid published lease (owner-pinned + bound + not-settled, floor NOT burned), or ``[]``.
    Mirrors ``CiTrigger`` — it PRODUCES, it never executes (the queue + ``jobs.runner`` are the sole
    executors). ``now=None`` re-reads the clock at each poll (a long-lived poller); a fixed ``now`` is for
    tests."""

    base_dir: Any
    now: Optional[float] = None

    def poll(self) -> "list[SecurityJob]":
        try:
            return launch_jobs_from_seam(self.base_dir, now=self.now)
        except Exception:  # noqa: BLE001 — a flaky seam read never sinks the drain (model.drain also guards)
            return []
