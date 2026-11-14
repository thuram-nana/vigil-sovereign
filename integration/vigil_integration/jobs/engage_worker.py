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

import contextlib
import hashlib
import os
from pathlib import Path
from typing import Any, Callable, Iterator, Optional

from vigil_core.seam_base import resolve_seam_base

from .model import SecurityJob

_ATTEMPTS_DIRNAME = ".engage-attempts"


#: A customer launch re-drives (resume) on a transient worker failure up to this many arm attempts; the LAST
#: attempt is TERMINAL — only its failure emits a refunding FAILED completion. This bounds the FAILED emit to
#: a terminal abandonment so a transient-fail-then-succeed (re-drive) never spools a FAILED that would RACE
#: the eventual COMPLETED into a free run, AND a permanently-failing launch still terminates (the terminal
#: FAILED settles + tombstones the lease, so the launch poller stops re-enqueuing it).
_MAX_ARM_ATTEMPTS = 3


def _mark_attempt(base_dir: Any, slug: str, nonce: str) -> "tuple[int, bool]":
    """Record a durable per-``(slug, nonce)`` arm attempt and return ``(ATTEMPT COUNT, slot_created)``. Numbered
    ``O_EXCL`` markers under ``.engage-attempts``: the Nth distinct call creates ``<key>.<N>`` and returns N.
    Count 1 is a FRESH arm (``run_engagement`` consumes the single-use floor); count > 1 is a RE-DRIVE (resume —
    the arm re-validates WITHOUT re-burning the floor, so a crash-after-consume re-delivery is not stranded as a
    'replay'); count >= ``_MAX_ARM_ATTEMPTS`` is the TERMINAL attempt (its failure is a real abandonment, not a
    transient retry). FAIL-SAFE: an unusable marker store returns ``(1, False)`` (a FRESH, NON-terminal arm — it
    never silently resumes an un-attempted lease, and never reports TERMINAL off a broken store, so a transient
    failure is never mis-refunded). The key is ``sha256(slug\\x00nonce)``; a genuine re-lease (new nonce) gets a
    NEW key ⇒ a fresh count.

    ``slot_created`` is True ONLY when THIS call actually minted a new numbered slot. It is False on the two
    paths that mint NO slot — the FAIL-SAFE OSError (``(1, False)``) and SATURATED (``(MAX+1, False)``) returns —
    so a later in-flight-pause rollback (:func:`_release_attempt`) can be gated on it and never unlink a slot
    THIS attempt did not create (which would be a PRIOR attempt's, silently eroding crash budget)."""
    base = base_dir if base_dir is not None else resolve_seam_base()
    key = hashlib.sha256((str(slug) + "\x00" + str(nonce)).encode("utf-8")).hexdigest()
    try:
        d = Path(base) / _ATTEMPTS_DIRNAME
        d.mkdir(parents=True, exist_ok=True)
        for n in range(1, _MAX_ARM_ATTEMPTS + 2):      # 1..MAX+1; the first free slot is THIS attempt's number
            try:
                fd = os.open(d / f"{key}.{n}.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.close(fd)
                return n, True
            except FileExistsError:
                continue
        return _MAX_ARM_ATTEMPTS + 1, False            # all slots taken ⇒ beyond max (terminal); minted NO slot
    except OSError:
        return 1, False                                # fail-safe: fresh, NON-terminal arm; minted NO slot


#: pause/resume PR-3 — the suffix of the durable per-(slug,nonce) "the floor was burned; the next arm must
#: RESUME" marker, written when an in-flight PAUSE rolls back its attempt slot (so the rollback does not reset
#: the resume decision to a floor-RE-burning fresh arm). Lives beside the numbered attempt markers.
_RESUME_MARK_SUFFIX = "resume"


def _attempt_key(slug: str, nonce: str) -> str:
    """The shared ``.engage-attempts`` key for ``(slug, nonce)`` — the SAME hash :func:`_mark_attempt` uses, so
    the rollback and resume-required markers address the same slot family."""
    return hashlib.sha256((str(slug) + "\x00" + str(nonce)).encode("utf-8")).hexdigest()


def _release_attempt(base_dir: Any, slug: str, nonce: str, attempt: int) -> None:
    """pause/resume PR-3 — roll back THIS attempt's numbered marker so an in-flight PAUSE never consumes
    crash-attempt budget (``_MAX_ARM_ATTEMPTS``). ``_mark_attempt`` always hands out the LOWEST free slot, so the
    slot just taken is the current maximum; deleting exactly it keeps the slots contiguous and a genuine CRASH
    still advances toward the terminal attempt. Best-effort: a failed unlink leaves the slot (the pause then
    counts as one crash attempt — fail-SAFE toward eventual termination, NEVER toward a never-terminating launch
    or a lost refund). No nonce / bad attempt ⇒ no-op."""
    if not nonce or attempt < 1:
        return
    base = base_dir if base_dir is not None else resolve_seam_base()
    with contextlib.suppress(OSError):
        (Path(base) / _ATTEMPTS_DIRNAME / f"{_attempt_key(slug, nonce)}.{attempt}.json").unlink()


def _record_resume_required(base_dir: Any, slug: str, nonce: str) -> None:
    """pause/resume PR-3 — durably record that THIS (slug,nonce)'s single-use floor WAS burned and the next arm
    MUST resume (verify + re-bind, NOT re-consume), so an in-flight pause whose attempt slot was rolled back
    re-drives WITHOUT a replay refusal. Idempotent ``O_CREAT``; keyed per (slug,nonce) so a genuine re-lease
    (new nonce) is unaffected. Best-effort: a failed write degrades to a one-cycle replay refusal that self-heals
    on the next re-drive (``attempt > 1`` then holds) — money-safe (never a double-charge)."""
    if not nonce:
        return
    base = base_dir if base_dir is not None else resolve_seam_base()
    with contextlib.suppress(OSError):
        d = Path(base) / _ATTEMPTS_DIRNAME
        d.mkdir(parents=True, exist_ok=True)
        fd = os.open(d / f"{_attempt_key(slug, nonce)}.{_RESUME_MARK_SUFFIX}.json", os.O_WRONLY | os.O_CREAT, 0o600)
        os.close(fd)


def _resume_required(base_dir: Any, slug: str, nonce: str) -> bool:
    """pause/resume PR-3 — True iff a prior in-flight pause POSITIVELY recorded that THIS (slug,nonce)'s floor
    was burned (so the arm must RESUME, not re-consume). FAIL-CLOSED toward FRESH: any read error ⇒ False. This
    direction is the money-safe one — a false False causes at worst a one-cycle replay refusal that self-heals
    (``attempt > 1`` on the next re-drive), whereas a false True would make a FRESH arm SKIP the single-use
    consume and leave the floor un-burned (a replayable lease). No nonce ⇒ False."""
    if not nonce:
        return False
    base = base_dir if base_dir is not None else resolve_seam_base()
    try:
        return (Path(base) / _ATTEMPTS_DIRNAME / f"{_attempt_key(slug, nonce)}.{_RESUME_MARK_SUFFIX}.json").is_file()
    except OSError:
        return False


def _is_engagement_paused(exc: BaseException) -> bool:
    """pause/resume PR-3 — True iff ``exc`` is the engine's re-driveable in-flight pause halt
    (``framework.v2.engage.EngagementPaused``). Lazy + guarded (FATAL-2: no ``framework`` at module scope). By
    the time a run has raised, the runner has already imported ``framework.v2.engage``, so this is a cheap
    ``sys.modules`` lookup. SAFE DEFAULT = False: if the type cannot be resolved the exception is treated as a
    NORMAL failure (the transient/terminal FAILED path), never silently converted into a held, infinitely
    re-driven launch — the money-dangerous direction is a false POSITIVE, which ``isinstance`` cannot produce."""
    try:
        from framework.v2.engage import EngagementPaused
    except Exception:  # noqa: BLE001 — cannot classify ⇒ treat as a normal failure (safe default)
        return False
    return isinstance(exc, EngagementPaused)


def _lease_currently_paused(base_dir: Any, slug: str, nonce: str) -> bool:
    """pause/resume PR-4 (HARD #2) — True iff THIS (slug, nonce) lease is paused RIGHT NOW. Used to classify a
    NON-``EngagementPaused`` run failure as a gate→arm-window pause (the PRECONDITION raised ``EngagementRefused``
    because the lease was paused AFTER the pickup gate passed but BEFORE the arm) vs a genuine failure.
    ``is_lease_paused`` is total + fail-closed (a corrupt marker ⇒ True/held — correct, the pickup gate refuses
    it too). FAIL toward False (the genuine-failure/terminal path) ONLY when the seam import is unavailable, so a
    REAL failure with NO pause marker is never wrongly held — a false POSITIVE here would re-drive forever. No
    nonce ⇒ False."""
    if not nonce:
        return False
    try:
        from vigil_integration.live.credit_lease_pause import is_lease_paused
        return bool(is_lease_paused(base_dir, slug, nonce))
    except Exception:  # noqa: BLE001 — cannot read the pause store ⇒ treat as a genuine failure (terminates)
        return False


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


def _default_run_tier_enabled() -> bool:
    """The default EC-7 gate: the SHARED ``vigil_core`` reader of ``VIGIL_TIERED_PRODUCTS`` (NO ``sigil``
    import — FATAL-2; the sovereign ``config.tiered_products_enabled`` mirrors the same leaf). Lazy: vigil_core
    is imported at call time, never at module scope. OFF ⇒ the worker derives/applies no run tier."""
    from vigil_core import run_tier
    return run_tier.tiered_products_enabled()


def _default_read_units(slug: str, host: str, tenant: Optional[str], *, base_dir: Any, now: Any) -> Optional[int]:
    """Read the launch's OWNER-SIGNED ``units_reserved`` via the SAME verified+bound lease EC-3 reads for its
    ceiling (authoritative, verify-ONLY — never consumes the single-use floor, never trusts ``job.extra``).
    Lazy (two-env): ``framework`` is imported only here. Fail-closed: any missing / forged / wrong-host /
    wrong-tenant / expired / settled lease ⇒ ``None`` (the caller then classifies the SMALLER 'quick' tier)."""
    from framework.v2.launch_lease import read_verified_launch_units
    return read_verified_launch_units(slug, host, tenant, base_dir=base_dir, now=now)


@contextlib.contextmanager
def _model_routing_scope(enabled: Optional[bool]) -> "Iterator[None]":
    """Scope the EC-2a model-routing lever (``CRUCIBLE_MODEL_ROUTING``) to the EC-7 run tier for the duration
    of ONE run, restoring the prior value EXACTLY on exit (including unset). ``enabled is None`` ⇒ a NO-OP
    (byte-identical: EC-7 off, so the deployment's own routing setting stands untouched). ``True`` turns the
    cheaper per-binding tiers ON for a 'quick' run; ``False`` forces every binding to its capable model for a
    'deep' run (fail-toward-capable). Scoping the WHOLE ``run_engagement`` call is correct even though the run
    spawns parallel self-consistency samples — the worker runs one job at a time (``JobRunner.run_one``), so
    ``os.environ`` is stable for the run and every in-process sample reads the same value."""
    if enabled is None:
        yield
        return
    key = "CRUCIBLE_MODEL_ROUTING"
    prev = os.environ.get(key)
    os.environ[key] = "1" if enabled else "0"
    try:
        yield
    finally:
        if prev is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = prev


def _launch_governance_signers(base_dir: Any) -> "list[tuple[str, str]]":
    """Load the STABLE offense-governance signer for this ``base_dir`` as ``[(key_id, priv_b64)]`` — the same
    key the sovereign launch step (``ui.launch_governance``) owner-DELEGATED at launch, so the crossing + the
    completion signal this worker emits verify under that delegation. vigil_core-only (no framework); the key
    is loaded-or-created under the engagement base (sealed under the vault when provisioned)."""
    from vigil_integration.live.governance_identity import (
        DEFAULT_GOVERNANCE_KEY_FILE, GOVERNANCE_KEY_ID, load_or_create_governance_keypair,
    )
    base = base_dir if base_dir is not None else resolve_seam_base()
    kp = load_or_create_governance_keypair(path=str(Path(base) / DEFAULT_GOVERNANCE_KEY_FILE))
    return [(GOVERNANCE_KEY_ID, kp.private_key_b64)]


def _completion_spool(base_dir: Any, completion_spool_dir: Any, slug: str) -> str:
    """The completion settle-spool this worker emits to. An explicit ``completion_spool_dir`` is used as-is
    (the caller controls it). The DEFAULT is PER-SLUG — ``base/completion-spool/<slug>/`` — so each tenant's
    completions land in their OWN spool (K4-5 red-pen MED): a per-slug-scoped settle-drain then reads only its
    own tenant's completions and can never atomically-claim + quarantine (destroy) another tenant's valid
    completion out of a shared incoming/ dir."""
    if completion_spool_dir is not None:
        return str(completion_spool_dir)
    base = base_dir if base_dir is not None else resolve_seam_base()
    return str(Path(base) / "completion-spool" / str(slug))


def _finding_spool(base_dir: Any, finding_spool_dir: Any, slug: str) -> str:
    """The FACT finding-spool this worker crosses to. Explicit path used as-is; the DEFAULT is PER-SLUG
    (``base/finding-spool/<slug>/``) for the same per-tenant isolation as the completion spool."""
    if finding_spool_dir is not None:
        return str(finding_spool_dir)
    base = base_dir if base_dir is not None else resolve_seam_base()
    return str(Path(base) / "finding-spool" / str(slug))


def make_engage_worker(
    *,
    base_dir: Any = None,
    trust_root: Any = None,
    run: "Optional[Callable[..., Any]]" = None,
    profile_kwargs: "Optional[dict[str, Any]]" = None,
    prod_execution_enabled: "Optional[Callable[[], bool]]" = None,
    run_tier_enabled: "Optional[Callable[[], bool]]" = None,
    read_units: "Optional[Callable[..., Optional[int]]]" = None,
    now: Any = None,
    finding_spool_dir: Any = None,
    completion_spool_dir: Any = None,
    signers: "Optional[list]" = None,
    emit_completion: bool = True,
) -> "Callable[[SecurityJob], Any]":
    """Build the customer-launch worker: ``(SecurityJob) -> result``. Invoked ONLY by ``JobRunner.run_one``,
    i.e. only after ``build_customer_launch_gate`` allowed the job. It loads the VERIFIED customer authority
    for the job's slug, binds the seed host authoritatively from its exact-host scope, re-checks the K4
    production-disable flag (a ``LIVE`` target needs the explicit opt-in), then drives ``run_engagement`` —
    whose arm consumes the single-use lease and whose gate chain re-enforces scope + egress. Any precondition
    failure RAISES (``JobRunner`` turns a worker error into a ``failed`` outcome + ``release_delivery``, so
    the work is re-driveable, never a silent false-clean).

    EC-7 (tiered Quick/Deep products): when ``run_tier_enabled()`` is True the worker DERIVES the run tier
    from the launch's OWNER-SIGNED ``units_reserved`` (``read_units`` — the SAME verified+bound lease EC-3
    reads, authoritative, never the tamperable ``job.extra``) and overlays the tier's engagement roster
    (``engage.profile_kwargs`` — a 'deep' launch runs the full browser/SSO/GraphQL/access-control roster, a
    'quick' launch the lean default) + sets the EC-2a model-routing lever for the run (quick ⇒ cheaper tiers
    on; deep ⇒ capable models). OFF by default ⇒ byte-identical: no derivation, run_engagement's own default
    roster, ``CRUCIBLE_MODEL_ROUTING`` untouched. A bad/absent/unverifiable lease fails SAFE to the smaller
    'quick' tier (never silently escalates a run to the fuller, more expensive 'deep').

    ``run`` / ``prod_execution_enabled`` / ``run_tier_enabled`` / ``read_units`` / ``trust_root`` are
    injectable for tests (a mock engine + mock flags + a stub units reader + an explicit owner root) so the
    full wiring is exercised deterministically without a live scan."""
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
        attempt, _slot_created = _mark_attempt(base_dir, job.slug, nonce) if nonce else (1, False)
        # a re-drive resumes (K4-5a), never re-burns the floor. pause/resume PR-3: an in-flight PAUSE rolls its
        # attempt slot back (so pauses never consume crash-attempt budget), so ``attempt`` alone can read 1 on a
        # post-pause re-drive even though the floor WAS burned on the original arm — the resume-required marker
        # makes RESUME hold regardless, so the re-drive re-validates/re-binds WITHOUT re-burning the floor into a
        # replay refusal.
        resume = (attempt > 1) or _resume_required(base_dir, job.slug, nonce)
        terminal = attempt >= _MAX_ARM_ATTEMPTS                    # the LAST attempt: its failure is a real abandonment
        runner = run if run is not None else _default_run_engagement
        kwargs = dict(_LOW_IMPACT_PROFILE if profile_kwargs is None else profile_kwargs)
        kwargs.pop("resume", None)                                 # resume is a worker concern, never a profile key
        kwargs.pop("launch_nonce", None)                           # ...and so is the launch identity
        # Bind the run to THIS job's launch. The seam holds ONE lease per slug and a customer slug is reused by
        # every launch of the same (org, host), so the lease on the seam can be a LATER launch's: the engine then
        # refuses before its arm (so this job never burns that launch's single-use floor) and binds its pause
        # halt + resume state to this nonce, never to whichever lease is on the seam. No nonce ⇒ not passed
        # (the engine keeps its seam read, as before).
        if nonce:
            kwargs["launch_nonce"] = nonce
        # EC-7 — tiered Quick/Deep run profile (default-OFF ⇒ byte-identical). When the owner has enabled
        # tiered products, DERIVE the run tier from the launch's OWNER-SIGNED units_reserved (the SAME
        # verified+bound lease EC-3 reads for its token ceiling — authoritative, never the tamperable
        # job.extra), then OVERLAY the tier's engagement roster (additively — the profile system only ever
        # UNIONS flags on) and HOLD the EC-2a routing lever for the run. A bad / absent / unverifiable lease ⇒
        # units=None ⇒ "quick" (fail-SAFE: the smaller-impact, cheaper tier — never a silent escalation to the
        # fuller, costlier "deep").
        tier_enabled = run_tier_enabled if run_tier_enabled is not None else _default_run_tier_enabled
        read_u = read_units if read_units is not None else _default_read_units
        routing_override: Optional[bool] = None
        if tier_enabled():
            from framework.v2.engage import profile_kwargs as _engage_profile_kwargs
            from vigil_core import run_tier
            units = read_u(job.slug, host, (job.tenant_id or None), base_dir=base_dir, now=now)
            tier = run_tier.run_tier_for_units(units)              # None/bad ⇒ "quick" (fail-safe)
            kwargs["profile"] = run_tier.engage_profile_for(tier)  # surface|full — the roster NAME (manifest-recorded)
            kwargs.update(_engage_profile_kwargs(kwargs["profile"]))   # the enable_* passes that roster turns ON
            routing_override = run_tier.routing_enabled_for(tier)  # quick ⇒ cheaper tiers on; deep ⇒ capable models
        # K4-5d(B): the completion SEAM. Load the owner-delegated offense-governance signers BEFORE the arm
        # (fail-closed — a run that could never settle must not consume the lease), then:
        #   run succeeds → cross the confirmed FACTs (best-effort) + emit a COMPLETED settle signal (REQUIRED —
        #                  the billing trigger: the sovereign settle-drain reads it and settles to consumption);
        #   run raises   → emit a FAILED settle signal (consumed=0, full refund) then RE-RAISE, so JobRunner
        #                  still marks the job failed + release_delivery (re-driveable), and the paid reservation
        #                  is refunded rather than stranded as consumed.
        # Both signals are governance-SIGNED and verified sovereign-side against the launch's owner delegation
        # (ui.launch_governance). No nonce ⇒ no settle binding ⇒ no emit (defensive; launch jobs always carry one).
        do_settle = bool(emit_completion and nonce)
        sgnrs = (signers if signers is not None else _launch_governance_signers(base_dir)) if do_settle else None
        try:
            with _model_routing_scope(routing_override):          # EC-7: scope CRUCIBLE_MODEL_ROUTING to the tier (no-op when off)
                result = runner(slug=job.slug, seed_url=seed_url, resume=resume, **kwargs)
        except Exception as _run_exc:  # noqa: BLE001 — a run failure re-raises (JobRunner -> failed + release_delivery -> re-drive)
            # pause/resume PR-3 — a COOPERATIVE in-flight PAUSE halt is NOT a failure; it is a re-driveable
            # transient. Classify it by TYPE (not by message) BEFORE the FAILED-settle path so a paused launch:
            #   * NEVER emits the terminal refunding FAILED settle (the lease is HELD for resume, not refunded or
            #     tombstoned — no premature refund, and the launch poller keeps re-driving), and
            #   * rolls its attempt slot back + records resume-required, so repeat pause/resume can NEVER exhaust
            #     ``_MAX_ARM_ATTEMPTS`` into a spurious terminal abandonment, and the eventual resume re-drive
            #     re-validates/re-binds WITHOUT re-burning the single-use floor into a replay refusal.
            # Then re-raise unchanged, so JobRunner still marks the job failed + release_delivery → re-enqueue.
            if _is_engagement_paused(_run_exc):
                if nonce:
                    # Roll back ONLY a slot THIS attempt actually minted — on the _mark_attempt fail-safe /
                    # saturated paths no slot was created, and unlinking ``<key>.<attempt>`` there would delete a
                    # PRIOR attempt's slot and silently erode crash budget. resume-required is recorded
                    # regardless (the floor burn it reflects is independent of whether a slot was minted).
                    if _slot_created:
                        _release_attempt(base_dir, job.slug, nonce, attempt)
                    _record_resume_required(base_dir, job.slug, nonce)
                raise
            # pause/resume PR-4 (HARD #2) — a NON-EngagementPaused failure whose lease is NOW paused is the
            # gate→arm-window pause: the precondition raised EngagementRefused because the lease was paused AFTER
            # the pickup gate passed but BEFORE _advance_floor, so the single-use floor was NOT burned. Treat it
            # as a REVERSIBLE halt: emit NO FAILED settle (no premature refund/tombstone — the seam poller holds a
            # paused lease and re-produces on resume; PR-A's pickup gate catches any racing re-pickup), roll back
            # the do-nothing attempt slot, and record NO resume-required (the floor was NOT burned, so the re-arm
            # MUST consume — recording it would skip the burn = a replayable lease / free run). Re-raise ⇒
            # JobRunner release_delivery + the launch re-drives. FAIL-SAFE: a genuine failure with no pause marker
            # is NOT held (it terminates normally) — see _lease_currently_paused.
            if nonce and _lease_currently_paused(base_dir, job.slug, nonce):
                if _slot_created:
                    _release_attempt(base_dir, job.slug, nonce, attempt)
                raise
            # Emit a refunding FAILED completion ONLY on the TERMINAL attempt. A transient failure (attempt <
            # _MAX_ARM_ATTEMPTS) re-drives WITHOUT a premature refund, so it can never spool a FAILED that RACES
            # the eventual COMPLETED into a free run (the K4-5 red-pen HIGH). The terminal FAILED settles +
            # tombstones the lease, so a permanently-failing launch still terminates (the poller stops re-driving).
            if do_settle and terminal:
                try:
                    from .completion_signal import emit_completion_signal
                    emit_completion_signal(engagement_slug=job.slug, nonce=nonce, outcome="failed",
                                           signers=sgnrs, spool_dir=_completion_spool(base_dir, completion_spool_dir, job.slug))
                except Exception:  # noqa: BLE001 — a failed-settle emit is best-effort; never mask the run error
                    pass
            raise
        if do_settle:
            # FDX-2: a COMPLETED run's settle DEPENDS on its confirmed FACTs being durably crossed to the
            # sovereign finding spool FIRST — the COMPLETED signal's very existence must prove the FACTs
            # crossed, so a paid run can never settle with its FACTs lost. CAUTION: cross_confirmed_findings
            # is TOTAL — it COUNTS a per-finding durability/sign/serialize failure (e.g. an unwritable finding
            # spool) and RETURNS a CrossingResult WITHOUT raising (findings_crossing.py). So merely CALLING it
            # is not a gate; we must INSPECT the result and raise on `errors`, else a swallowed spool-write
            # failure falls through to the COMPLETED emit — the exact FACT-loss-while-charging hole this slice
            # closes. On a raise, JobRunner marks the job failed + release_delivery, so the launch RE-DRIVES
            # (resume re-reaches completion and the crossing retries; the finding spool's content-addressed
            # dedup + the receiver's two-anchor ingest make the retry idempotent, so an already-crossed FACT
            # lands exactly once). Money-safe: a crossing that keeps erroring HOLDS the reservation (never
            # charges) rather than recognising revenue on a run whose FACTs were lost; a FACT that does not
            # re-fire legitimately degrades to a LEAD (counted in `leads`, NOT crossed, NOT an error) and does
            # not block. The terminal FAILED path (above) still refunds a genuine run failure.
            from .findings_crossing import cross_confirmed_findings, findings_from_report
            found = findings_from_report(getattr(result, "report", None))
            if found:
                crossing = cross_confirmed_findings(
                    found, engagement_slug=job.slug, signers=sgnrs,
                    spool_dir=_finding_spool(base_dir, finding_spool_dir, job.slug))
                if crossing.errors:
                    raise RuntimeError(
                        f"findings crossing incomplete for {job.slug}: {crossing.errors} of {len(found)} "
                        f"confirmed FACT(s) failed to cross durably (crossed={crossing.crossed}, "
                        f"leads={crossing.leads}) — refusing to emit the COMPLETED settle signal so the launch "
                        f"re-drives rather than settle with its FACTs lost")
            from .completion_signal import emit_completion_signal
            emit_completion_signal(engagement_slug=job.slug, nonce=nonce, outcome="completed",
                                   signers=sgnrs, spool_dir=_completion_spool(base_dir, completion_spool_dir, job.slug))
        return result
    return _worker
