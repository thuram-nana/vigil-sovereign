"""
jobs.authorize — the HARD pre-execution gate every ``SecurityJob`` passes before ANY worker runs.

This is the architecture's load-bearing rule: a trigger only PRODUCES a job; the worker runs it ONLY
after this gate says yes. Fail-closed — any refusal / error / missing authority means the job is NOT
run. The decision REUSES VIGIL's existing "is this EXACT asset authorized?" primitive
(:func:`framework.v2.authority.gate.authorize_action` over a CRYPTOGRAPHICALLY-VERIFIED
:class:`EngagementAuthority`) plus the per-tenant structural boundary
(:func:`framework.v2.common.tenant.assert_tenant_fleet_isolated`).

``authorize_job`` is a pure composition (tenant boundary → authorization gate); the real authorization
wiring is factored into :func:`build_repo_gate` (injectable), so a caller swaps in the full conjunctive
gate (CRUCIBLE ∧ WARDEN ∧ m-of-n) in production and a fake in tests, without this module hiding a
governance dependency. v1 authorizes a repo HOST-BROAD (``scope=["github.com"]``, one slug per repo);
the EXACT per-repo + PR-write conjuncts land in a later slice.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime as _datetime, timezone as _timezone
from typing import Any, Callable, Optional

from .model import SecurityJob


@dataclass(frozen=True)
class GateOutcome:
    """A single authorization decision for a job (decoupled from which gate produced it)."""

    allowed: bool
    reason: str = ""
    denial_code: str = ""


@dataclass(frozen=True)
class JobAuthorization:
    """The gate's verdict for a job: allowed, or refused with a stable code + human reason (audit)."""

    allowed: bool
    state: str                       # "allowed" | "refused"
    reason: str = ""
    denial_code: str = ""

    @property
    def refused(self) -> bool:
        return not self.allowed


def _repo_host(repo: str) -> str:
    """The bare host of a connected-repo identity — ``github.com/org/repo`` → ``github.com``. v1 scope is
    host-only (the exact-repo conjunct is a later slice), so this is what the scope check matches."""
    r = str(repo or "").strip()
    for sep in ("://",):             # tolerate a full URL form too
        if sep in r:
            r = r.split(sep, 1)[1]
    return r.split("/", 1)[0]


def _default_assert_tenant() -> None:
    """Enforce the per-tenant structural boundary when the process is sharded (``CRUCIBLE_TENANT`` set):
    a worker must be running in a dedicated, isolated root. Unsharded (the historical single-tenant
    default) is a no-op — isolation is vacuous with one tenant. Re-raises ``TenantIsolationError``."""
    from framework.v2.common.tenant import assert_tenant_fleet_isolated, tenant_id
    if tenant_id() is not None:
        assert_tenant_fleet_isolated()


def _active_tenant() -> Optional[str]:
    """The tenant this process is sharded for (``CRUCIBLE_TENANT``), or ``None`` when unsharded (the
    single-tenant default). Reads the validated primitive; a set-but-malformed id fails closed upstream."""
    from framework.v2.common.tenant import tenant_id
    return tenant_id()


def _reconcile_tenant(job: SecurityJob, active_tenant: Callable[[], Optional[str]]) -> Optional[JobAuthorization]:
    """Fail-closed cross-tenant check: a job TAGGED for an org (``job.tenant_id``) MUST run in THAT org's
    sharded process. Returns a refusal ``JobAuthorization`` on a mismatch, else ``None`` (ok to proceed).

    The per-tenant root boundary (``assert_tenant_fleet_isolated``) proves the PROCESS is in a dedicated,
    isolated root; it does NOT prove that root belongs to the tenant THIS job is for — a worker sharded for
    org B draining a job tagged for org A would pass the boundary yet write A's findings into B's root. This
    closes that gap: org == ``tenant_id`` (CRUCIBLE_TENANT), so a non-empty ``job.tenant_id`` must equal the
    process's active tenant. An UNtagged job is left to the boundary check (backward-compatible: today's
    single-tenant jobs are untagged and run unsharded); the guard engages only once jobs carry a tenant."""
    jt = str(getattr(job, "tenant_id", "") or "").strip()   # str() so a non-str tag refuses, never crashes
    if not jt:
        return None                       # untagged ⇒ no cross-tenant claim to reconcile (boundary still applies)
    try:
        active = active_tenant()
    except Exception as e:  # noqa: BLE001 — cannot resolve the process tenant ⇒ refuse (never assume a match)
        return JobAuthorization(allowed=False, state="refused",
                                reason=f"tenant resolution error (fail-closed): {type(e).__name__}: {e}",
                                denial_code="tenant_mismatch")
    if active is None:
        return JobAuthorization(
            allowed=False, state="refused",
            reason=f"job is tagged for tenant {jt!r} but this process is not sharded for any tenant — "
                   "refusing (a tenant-scoped job must run in that tenant's dedicated root, never the "
                   "shared default store)",
            denial_code="tenant_mismatch")
    if str(active) != jt:
        return JobAuthorization(
            allowed=False, state="refused",
            reason=f"job is tagged for tenant {jt!r} but this process is sharded for {str(active)!r} — "
                   "refusing (cross-tenant)",
            denial_code="tenant_mismatch")
    return None


def authorize_job(
    job: SecurityJob,
    *,
    gate: Callable[[SecurityJob], GateOutcome],
    assert_tenant: Callable[[], None] = _default_assert_tenant,
    active_tenant: Callable[[], Optional[str]] = _active_tenant,
) -> JobAuthorization:
    """Decide whether ``job`` may run. Order (first failure wins, fail-closed):
      0. tenant reconciliation — a job TAGGED for an org must run in THAT org's sharded process
         (``_reconcile_tenant``; org == ``tenant_id``), else it is a cross-tenant leak and is refused;
      1. tenant boundary — a sharded worker must be isolated (``assert_tenant``);
      2. authorization — the injected ``gate`` (the verified-authority / conjunctive decision).
    ANY exception in any step is a REFUSAL, never a pass (a gate that errors must not run the job).
    ``active_tenant`` is injectable so offline tests exercise the reconciliation without sharding a process."""
    try:
        mismatch = _reconcile_tenant(job, active_tenant)
    except Exception as e:  # noqa: BLE001 — ANY reconciliation error ⇒ refuse (fail-closed; honors the contract)
        return JobAuthorization(allowed=False, state="refused",
                                reason=f"tenant reconciliation error (fail-closed): {type(e).__name__}: {e}",
                                denial_code="tenant_mismatch")
    if mismatch is not None:
        return mismatch
    try:
        assert_tenant()
    except Exception as e:  # noqa: BLE001 — TenantIsolationError (or any boundary failure) ⇒ refuse
        return JobAuthorization(allowed=False, state="refused",
                                reason=f"tenant boundary not satisfied: {type(e).__name__}: {e}",
                                denial_code="tenant_isolation")
    try:
        outcome = gate(job)
    except Exception as e:  # noqa: BLE001 — a gate that raises is fail-closed, not a pass
        return JobAuthorization(allowed=False, state="refused",
                                reason=f"authorization gate error (fail-closed): {type(e).__name__}: {e}",
                                denial_code="gate_error")
    if not getattr(outcome, "allowed", False):
        return JobAuthorization(allowed=False, state="refused",
                                reason=getattr(outcome, "reason", "") or "not authorized",
                                denial_code=getattr(outcome, "denial_code", "") or "authorization")
    return JobAuthorization(allowed=True, state="allowed",
                            reason=getattr(outcome, "reason", "") or "authorized")


def build_repo_gate(
    trust_root: Any = None,
    *,
    killswitch: Any = None,
    now: Any = None,
) -> Callable[[SecurityJob], GateOutcome]:
    """Wire the REAL authorization decision: load the CRYPTOGRAPHICALLY-VERIFIED ``EngagementAuthority`` for
    the job's slug (fail-closed — a None/absent trust root or an unverifiable authority REFUSES) and run
    :func:`authorize_action` over an ``ActionRequest`` for the repo host. This is the minimal sound gate
    for Slice 1 (verified-authority + scope + window + kill-switch); a caller can inject the full
    conjunctive gate (``build_offense_gate`` → WARDEN ∧ m-of-n) in its place without changing
    :func:`authorize_job`. Pure wiring — it reaches no network and mints nothing."""
    def _gate(job: SecurityJob) -> GateOutcome:
        from framework.v2.authority.gate import authorize_action
        from framework.v2.authority.killswitch import KillSwitch
        from framework.v2.authority.models import ActionRequest
        from framework.v2.authority.store import load_authority_root, load_verified_authority

        root = trust_root if trust_root is not None else load_authority_root()
        if root is None:
            return GateOutcome(False, "no authority trust root pinned — refusing (fail-closed)", "no_trust_root")
        try:
            authority = load_verified_authority(job.slug, root)
        except Exception as e:  # noqa: BLE001 — unverifiable / absent authority ⇒ refuse
            return GateOutcome(False, f"no verified authority for {job.slug!r}: {type(e).__name__}: {e}",
                               "unverified_authority")
        if authority is None:
            return GateOutcome(False, f"no verified authority for {job.slug!r}", "unverified_authority")
        req = ActionRequest(target=_repo_host(job.repo), action_kind="offense", destructive=False,
                            description=f"security scan of {job.repo} (job {job.fingerprint[:12]})")
        # Default the kill-switch to the per-slug one: authorize_action SKIPS the halt check when it is
        # None (fail-open), so a tripped switch would not stop a repo job unless we supply one here.
        ks = killswitch if killswitch is not None else KillSwitch(job.slug)
        decision = authorize_action(authority, req, killswitch=ks, now=now)
        return GateOutcome(bool(decision.allowed), decision.reason or "",
                           getattr(decision, "denial_code", "") or "")
    return _gate


def build_customer_launch_gate(
    trust_root: Any = None,
    *,
    killswitch: Any = None,
    now: Any = None,
    base_dir: Any = None,
    prod_execution_enabled: Optional[Callable[[], bool]] = None,
) -> Callable[[SecurityJob], GateOutcome]:
    """The CUSTOMER-LAUNCH authorization gate (slice K4-3) — the scheduling-boundary decision for a paying
    customer's self-serve engagement. A CONJUNCTION, fail-closed on the first failure:

      1. a CRYPTOGRAPHICALLY-VERIFIED **customer** ``EngagementAuthority`` for the job's slug (the
         ``cust_<hash>`` slug): ``issued_by`` MUST start ``"customer:"`` — this gate refuses an operator
         authority, so the customer-launch path can never run an operator engagement;
      2. the owner-signed ``CreditLaunchLease`` (billing≠testing): ``verify_customer_launch_lease(
         consume=False)`` — owner-PINNED verify + bind (slug / host / tenant / window) + the K4-1 SETTLEMENT
         re-check — at the scheduling boundary, WITHOUT burning the single-use floor (the engine arm inside
         ``run_engagement`` is the ONE authoritative consume);
      3. the K4 production-disable flag: a ``LIVE`` customer target is REFUSED while
         ``customer_prod_execution_enabled()`` is False (TWIN / STAGING / loopback proceed); and
      4. ``authorize_action`` over the verified authority (scope + window + kill-switch) for the authority's
         EXACT-host scope.

    The target HOST is bound AUTHORITATIVELY from the verified authority's scope (``scope[0]``), NEVER from
    the advisory ``job.extra`` carrier, so a tampered seam value cannot widen scope. The tenant is bound by
    ``authorize_job``'s ``_reconcile_tenant`` (``job.tenant_id`` == ``CRUCIBLE_TENANT``) BEFORE this gate, and
    here again via the lease's ``org_id`` == ``job.tenant_id`` — so lease.org == job.tenant == process tenant.
    Keyless, mints nothing; a None/absent trust root, an unverifiable / non-customer authority, a failed lease
    pre-check, or a flag-off LIVE target all REFUSE. Mirrors ``build_repo_gate`` so a caller swaps it into
    ``authorize_job`` unchanged."""
    def _gate(job: SecurityJob) -> GateOutcome:
        from framework.v2.authority.gate import authorize_action
        from framework.v2.authority.killswitch import KillSwitch
        from framework.v2.authority.models import ActionRequest
        from framework.v2.authority.store import load_authority_root, load_verified_authority
        from framework.v2.launch_lease import verify_customer_launch_lease
        from vigil_core.authority import TargetEnvironment
        from vigil_core.posture import customer_prod_execution_enabled

        root = trust_root if trust_root is not None else load_authority_root()
        if root is None:
            return GateOutcome(False, "no authority trust root pinned — refusing (fail-closed)", "no_trust_root")
        try:
            authority = load_verified_authority(job.slug, root)
        except Exception as e:  # noqa: BLE001 — unverifiable / absent authority ⇒ refuse
            return GateOutcome(False, f"no verified authority for {job.slug!r}: {type(e).__name__}: {e}",
                               "unverified_authority")
        if authority is None:
            return GateOutcome(False, f"no verified authority for {job.slug!r}", "unverified_authority")
        # (1) STRUCTURAL customer gate: this path authorizes ONLY a customer engagement, never an operator one.
        if not str(getattr(authority, "issued_by", "")).startswith("customer:"):
            return GateOutcome(False, "not a customer engagement authority (issued_by != 'customer:') — the "
                               "customer-launch gate refuses an operator authority", "not_customer")
        scope = list(getattr(authority, "scope", None) or [])
        host = scope[0] if scope else ""
        if not host:
            return GateOutcome(False, "customer authority has no scope host (fail-closed)", "no_scope_host")
        # (3) K4 production-disable: a LIVE customer target needs the explicit owner opt-in.
        enabled = prod_execution_enabled or customer_prod_execution_enabled
        if authority.environment == TargetEnvironment.LIVE and not enabled():
            return GateOutcome(False, "production-target customer execution is disabled (K4 flag off) — a LIVE "
                               "customer engagement is refused until the acceptance matrix is green and the "
                               "owner enables VIGIL_CUSTOMER_PROD_EXECUTION", "customer_prod_disabled")
        # (2) the owner-signed CreditLaunchLease (consume=False — scheduling pre-check, single-use floor NOT burned)
        ok, reason = verify_customer_launch_lease(job.slug, host, (job.tenant_id or None),
                                                  base_dir=base_dir, now=now, consume=False)
        if not ok:
            return GateOutcome(False, f"credit-launch lease refused: {reason}", "no_lease")
        # (4) authority scope + window + kill-switch over the EXACT-host target. ``now`` is the POSIX-float
        # lease convention (what verify_customer_launch_lease takes); authorize_action wants a datetime, so
        # convert here — None flows through unchanged to mean "the real current time" in both.
        req = ActionRequest(target=host, action_kind="offense", destructive=False,
                            description=f"customer launch of {host} (job {job.fingerprint[:12]})")
        ks = killswitch if killswitch is not None else KillSwitch(job.slug)
        now_dt = _datetime.fromtimestamp(float(now), tz=_timezone.utc) if now is not None else None
        decision = authorize_action(authority, req, killswitch=ks, now=now_dt)
        return GateOutcome(bool(decision.allowed), decision.reason or "",
                           getattr(decision, "denial_code", "") or "")
    return _gate
