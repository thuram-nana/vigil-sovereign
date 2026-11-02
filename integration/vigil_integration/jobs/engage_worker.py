"""
jobs.engage_worker — the customer-launch WORKER (slice K4-3), invoked ONLY by ``JobRunner.run_one``.

A worker runs an AUTHORIZED ``SecurityJob`` and returns its result; it is called ONLY after the hard
authorization gate (``authorize_job`` + ``build_customer_launch_gate``) allows the job, never by a trigger.
:func:`make_engage_worker` builds the worker that drives CRUCIBLE's EXISTING governed execution — it
lazy-imports ``framework.v2.engage.run_engagement`` (no duplicate engine) and runs it under the job's
owner-signed ``cust_<hash>`` engagement slug. The engine's own gate chain (``_run_gates``: authority +
kill-switch → scope → destructive-confirm → budget → rate-limit → egress floor) AND the single-use arm
(``_engage_launch_lease_precondition`` → ``verify_customer_launch_lease(consume=True)``, the ONE
authoritative consume) re-enforce everything at execution; the worker adds no bypass.

Defence-in-depth at the EXECUTION boundary (beyond the scheduling-time gate):
  * the engagement HOST is bound AUTHORITATIVELY from the VERIFIED customer ``EngagementAuthority``'s
    exact-host scope — NOT from the (advisory) ``job.extra`` seed — so a tampered carrier cannot steer the
    scan off the verified asset; and
  * the K4 production-disable flag is RE-CHECKED here: a ``LIVE`` customer target is refused while
    ``customer_prod_execution_enabled()`` is False (TWIN / STAGING / loopback proceed), so even a mis-wired
    gate cannot run a live customer engagement with the flag off.

Integration-layer code: ``.model`` (pure) at module scope; ``framework`` (engage + authority) and
``vigil_core`` (posture + TargetEnvironment) are imported LAZILY inside the worker — NO ``framework`` at
module scope, NO ``sigil`` import, NO execution at import (two-env boundary).
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any, Callable, Optional

from .model import SecurityJob

_ATTEMPTS_DIRNAME = ".engage-attempts"


def _mark_attempt_and_is_redrive(base_dir: Any, slug: str, nonce: str) -> bool:
    """Record a durable per-``(slug, nonce)`` arm-attempt marker and return whether an attempt was ALREADY
    recorded (a RE-DRIVE). Atomic ``O_EXCL`` create: the FIRST attempt creates it and returns ``False`` (a
    fresh arm — ``run_engagement`` consumes the single-use floor); any later attempt finds it and returns
    ``True`` (resume — the arm re-validates WITHOUT re-burning the floor, so a crash-after-consume re-delivery
    is not stranded as a 'replay'). FAIL-SAFE: if the marker store is unusable, returns ``False`` (a fresh arm
    — it never silently resumes an un-attempted lease, preserving single-use; the degenerate case falls back
    to today's fail-closed behaviour). The marker name is ``sha256(slug\\x00nonce)`` so it is path-safe for any
    slug/nonce, and a genuine re-lease (new nonce) gets a NEW marker ⇒ a fresh arm."""
    base = base_dir if base_dir is not None else (os.environ.get("VIGIL_BASE_DIR") or ".vigil-live")
    key = hashlib.sha256((str(slug) + "\x00" + str(nonce)).encode("utf-8")).hexdigest()
    try:
        d = Path(base) / _ATTEMPTS_DIRNAME
        d.mkdir(parents=True, exist_ok=True)
        fd = os.open(d / f"{key}.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        return False                                   # THIS call created it → first attempt → fresh arm
    except FileExistsError:
        return True                                    # already recorded → re-drive → resume
    except OSError:
        return False                                   # fail-safe: cannot record → fresh arm (never auto-resume)

#: The low-impact self-serve engage profile. Customer authorities are minted ``allow_destructive=False``
#: (``add_customer_target``), so the engine's destructive-confirm gate already refuses destructive tools; the
#: run therefore stays read-only/non-destructive without a special flag. Left empty = run_engagement's
#: defaults (its finite request/page budgets are a fail-safe OPSEC cap, and the owner-signed authority
#: ``max_actions`` caps it further); a deployment may inject a tighter profile via ``profile_kwargs``.
_LOW_IMPACT_PROFILE: "dict[str, Any]" = {}


def _default_run_engagement(*, slug: str, seed_url: str, **kw: Any) -> Any:
    """Invoke CRUCIBLE's existing governed engage path. Lazy (two-env): ``framework`` is imported only here,
    at run time, never at module scope."""
    from framework.v2.engage import run_engagement
    return run_engagement(slug, seed_url, **kw)


def make_engage_worker(
    *,
    base_dir: Any = None,
    trust_root: Any = None,
    run: "Optional[Callable[..., Any]]" = None,
    profile_kwargs: "Optional[dict[str, Any]]" = None,
    prod_execution_enabled: "Optional[Callable[[], bool]]" = None,
    now: Any = None,
) -> "Callable[[SecurityJob], Any]":
    """Build the customer-launch worker: ``(SecurityJob) -> result``. Invoked ONLY by ``JobRunner.run_one``,
    i.e. only after ``build_customer_launch_gate`` allowed the job. It loads the VERIFIED customer authority
    for the job's slug, binds the seed host authoritatively from its exact-host scope, re-checks the K4
    production-disable flag (a ``LIVE`` target needs the explicit opt-in), then drives ``run_engagement`` —
    whose arm consumes the single-use lease and whose gate chain re-enforces scope + egress. Any precondition
    failure RAISES (``JobRunner`` turns a worker error into a ``failed`` outcome + ``release_delivery``, so
    the work is re-driveable, never a silent false-clean).

    ``run`` / ``prod_execution_enabled`` / ``trust_root`` are injectable for tests (a mock engine + a mock
    flag + an explicit owner root) so the full wiring is exercised deterministically without a live scan."""
    def _worker(job: SecurityJob) -> Any:
        from framework.v2.authority.store import load_authority_root, load_verified_authority
        from vigil_core.authority import TargetEnvironment
        from vigil_core.posture import customer_prod_execution_enabled

        root = trust_root if trust_root is not None else load_authority_root()
        if root is None:
            raise RuntimeError("engage worker: no authority trust root pinned (fail-closed)")
        authority = load_verified_authority(job.slug, root)        # raises on an unverifiable / absent authority
        if authority is None:
            raise RuntimeError(f"engage worker: no verified authority for {job.slug!r}")
        if not str(getattr(authority, "issued_by", "")).startswith("customer:"):
            raise RuntimeError("engage worker: not a customer engagement authority (issued_by != 'customer:')")
        scope = list(getattr(authority, "scope", None) or [])
        host = scope[0] if scope else ""
        if not host:
            raise RuntimeError("engage worker: customer authority has no scope host (fail-closed)")
        # K4 production-disable RE-CHECK at the execution boundary (defence-in-depth over the gate).
        enabled = prod_execution_enabled or customer_prod_execution_enabled
        if authority.environment == TargetEnvironment.LIVE and not enabled():
            raise RuntimeError(
                "engage worker: production-target customer execution is disabled (K4 flag off) — refusing a "
                "LIVE customer-target arm until VIGIL_CUSTOMER_PROD_EXECUTION is explicitly enabled")
        seed_url = f"https://{host}"                               # AUTHORITATIVE seed (authority scope, not extra)
        # K4-5a crash-after-arm fix: a FRESH arm consumes the single-use floor; a RE-DRIVE must RESUME (the
        # arm re-validates + re-binds the lease WITHOUT re-burning the floor), else a worker crash AFTER the
        # arm consumed but before completion strands the paid reservation as a 'replay' on re-delivery. The
        # durable per-(slug,nonce) attempt marker distinguishes the two: the FIRST attempt arms fresh, any
        # later attempt resumes. Single-use integrity is preserved — resume still re-validates owner-pin /
        # bind / settlement, and two concurrent arms of one slug are serialized by the per-slug run lease; the
        # marker only governs whether THIS (slug,nonce) re-burns its own floor. No nonce ⇒ fresh arm (safe).
        nonce = str((job.extra or {}).get("nonce") or "")
        resume = _mark_attempt_and_is_redrive(base_dir, job.slug, nonce) if nonce else False
        runner = run if run is not None else _default_run_engagement
        kwargs = dict(_LOW_IMPACT_PROFILE if profile_kwargs is None else profile_kwargs)
        kwargs.pop("resume", None)                                 # resume is a worker concern, never a profile key
        return runner(slug=job.slug, seed_url=seed_url, resume=resume, **kwargs)
    return _worker