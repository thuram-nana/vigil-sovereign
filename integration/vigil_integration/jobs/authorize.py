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
from typing import Any, Callable

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


def authorize_job(
    job: SecurityJob,
    *,
    gate: Callable[[SecurityJob], GateOutcome],
    assert_tenant: Callable[[], None] = _default_assert_tenant,
) -> JobAuthorization:
    """Decide whether ``job`` may run. Order (first failure wins, fail-closed):
      1. tenant boundary — a sharded worker must be isolated (``assert_tenant``);
      2. authorization — the injected ``gate`` (the verified-authority / conjunctive decision).
    ANY exception in either step is a REFUSAL, never a pass (a gate that errors must not run the job)."""
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
