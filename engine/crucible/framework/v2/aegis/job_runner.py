"""aegis.job_runner — AS-30 (D17, #1202): the PER-TENANT job-substrate runner (defense plane).

The EXECUTION end of the AEGIS fleet's ``jobs`` worker-kind (AS-6a wires the placement contract:
``aegis-jobs@.service``, ONE systemd instance per tenant, health on ``/run/aegis-jobs/%i/jobs.sock``).
AS-6a *routes* the worker; this slice is what runs INSIDE it. One :class:`PerTenantRunner` drives exactly
ONE tenant's job substrate and holds ONLY that tenant's state, so the fault domain is a single tenant.

DOCTRINE (enforced here and tested):
  * DEFENSIVE + ENGINE-PLANE ONLY. This runs the operator's OWN managed defensive jobs (rule compiles,
    heartbeat probes, relocations); it never attacks and never reaches a tenant's live traffic. It
    imports only ``vigil_core`` (plane-neutral) + stdlib + ``..common`` — NEVER ``sigil`` (FATAL-2).
  * PER-TENANT FAULT ISOLATION — the plan AS-30 acceptance, *"killed job degrades TT-A only"*. A runner
    executes ONLY its tenant's jobs and has NO handle on another tenant's runner or substrate. A job
    that is killed (OOM, a ``manage_defense`` relocate, a crash-loop cap) or that raises is CONTAINED:
    the fault degrades THIS tenant's substrate and propagates to no other. Isolation is process-per-
    tenant at deploy time (the systemd instance) and state-partition at the logic level — the vigil_core
    primitive's :func:`~vigil_core.job_substrate.isolation_witness` proves no other tenant's projection
    bytes move.
  * DETERMINISM. No wall-clock, no RNG. Job ids are content hashes of canonical fields + a per-runner
    monotonic sequence, so the same calls yield byte-identical ids and projections.
  * DEFAULT-OFF. The whole runner is gated behind ``VIGIL_AEGIS_JOBS`` (strict, fail-closed, DEFAULT OFF
    — the ``_saas_enforce_flag`` pattern). With the flag off the runner is INERT: it accepts and runs
    nothing and every call returns a FIXED ``disabled`` outcome over the empty substrate (flag-off golden
    byte-identical).

Nothing under ``aegis/__init__`` or ``framework.v2.__main__`` imports this module (it is off the gate
path, like ``aegis_fleet`` and ``tt_rig``), so ``make gate`` stays byte-identical. Its tests import it
directly.

VIGIL-LIMIT:LIMIT-aegis-jobs-runtime-isolation — the per-tenant OS process / cgroup isolation (the
systemd ``aegis-jobs@<tenant>.service`` instance, its own uid and MemoryMax) is deploy-gated runtime
infra and is not exercised by these offline tests; the fault-isolation PROVEN here is the substrate-
logic partition (one tenant's kill never perturbs another tenant's projection). The OS-level guarantee
rests on the deployed unit, recorded in docs/limitations/inventory.json.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable, Optional

from vigil_core.job_substrate import (
    Job,
    JobState,
    SubstrateState,
    TenantHealth,
    content_id,
    kill_job,
    submit,
    transition,
)

from ..common.logging import get_logger

_log = get_logger("aegis.job_runner")

__all__ = [
    "JOBS_ENV",
    "jobs_enabled",
    "RunnerError",
    "KilledJob",
    "JobSpec",
    "RunOutcome",
    "PerTenantRunner",
]


# ==================================================================================================
# Default-OFF flag (the _saas_enforce_flag pattern — strict, fail-closed, DEFAULT OFF).
# ==================================================================================================
JOBS_ENV = "VIGIL_AEGIS_JOBS"


def jobs_enabled() -> bool:
    """The AS-30 per-tenant job-substrate flag — strict, fail-closed, DEFAULT OFF. Only an explicit
    affirmative token turns a runner on; anything else (unset, typo, empty) keeps it INERT."""
    return (os.environ.get(JOBS_ENV) or "").strip().lower() in ("1", "true", "yes", "on")


class RunnerError(ValueError):
    """A fail-closed refusal by the runner (wrong-tenant job, operating a disabled runner's live path)."""


class KilledJob(Exception):
    """Raised by an injected job body to signal an OUT-OF-BAND terminate (OOM / relocate / crash-loop
    cap) rather than an ordinary failure. The runner maps it to the substrate ``killed`` state; any other
    exception maps to ``failed``. Both degrade ONLY this tenant."""


# The empty-substrate projection digest for a tenant — the FIXED value a disabled (flag-off) runner
# reports, computed from the primitive so the golden tracks the primitive's canonicalization.
def _empty_projection_digest(tenant: str) -> str:
    return SubstrateState().tenant_projection_digest(tenant)


@dataclass(frozen=True, slots=True)
class JobSpec:
    """A unit of defensive work to run for one tenant. ``payload`` is opaque to the runner (it hashes it
    into ``payload_digest`` and hands the whole spec to the injected executor)."""

    tenant: str
    kind: str
    payload: dict


@dataclass(frozen=True, slots=True)
class RunOutcome:
    """The immutable result of one run-attempt. ``enabled`` is False only for a flag-off runner, whose
    outcome is otherwise FIXED (inert). ``health`` is the tenant's substrate health AFTER the attempt;
    ``projection_digest`` is the deterministic digest of that tenant's rendered projection."""

    enabled: bool
    tenant: str
    job_id: str
    state: Optional[JobState]
    health: TenantHealth
    projection_digest: str
    detail: str = ""


class PerTenantRunner:
    """Runs one tenant's defensive jobs over an in-memory, immutable job substrate. Bound to a single
    tenant for its whole life — the fault domain. A fault in one job is caught and recorded; it never
    escapes the runner and never touches another tenant (there is no cross-tenant handle to touch)."""

    def __init__(self, tenant: str, *, enabled: Optional[bool] = None) -> None:
        if not (isinstance(tenant, str) and tenant):
            raise RunnerError("tenant must be a non-empty str")
        self.tenant = tenant
        # Read the flag ONCE at construction unless the caller pins it (tests pin both legs). A disabled
        # runner is inert for its whole life — it never holds substrate state.
        self.enabled = jobs_enabled() if enabled is None else bool(enabled)
        self._state = SubstrateState()
        self._seq = 0

    # --- read-side -------------------------------------------------------------------------------
    @property
    def state(self) -> SubstrateState:
        return self._state

    def health(self) -> TenantHealth:
        """This tenant's substrate health. A disabled runner is ``nominal`` over the empty substrate
        (inert, nothing ran), never a false ``down`` and never another tenant's state."""
        return self._state.tenant_health(self.tenant)

    def projection(self) -> dict:
        return self._state.tenant_projection(self.tenant)

    def projection_digest(self) -> str:
        return self._state.tenant_projection_digest(self.tenant)

    def _next_job_id(self, payload_digest: str) -> str:
        jid = content_id("aegis-job", self.tenant, payload_digest, self._seq)
        self._seq += 1
        return jid

    def _disabled_outcome(self) -> RunOutcome:
        # FIXED, input-independent outcome for the flag-off leg (flag-off byte-identical golden).
        return RunOutcome(
            enabled=False,
            tenant=self.tenant,
            job_id="",
            state=None,
            health=TenantHealth.NOMINAL,
            projection_digest=_empty_projection_digest(self.tenant),
            detail="VIGIL_AEGIS_JOBS off: runner inert",
        )

    # --- the sole execution path -----------------------------------------------------------------
    def run_job(self, spec: JobSpec, execute: Callable[[Job], object]) -> RunOutcome:
        """Admit ``spec`` onto this tenant's substrate and drive it through the injected ``execute``.
        FAULT-CONTAINED: a job that raises :class:`KilledJob` -> ``killed``; any other exception ->
        ``failed``; a clean return -> ``succeeded``. The exception NEVER escapes — a crashing job must not
        crash the runner, and whichever terminal it reaches degrades ONLY this tenant.

        With the flag off the runner is inert: no state changes, a FIXED disabled outcome is returned."""
        if not self.enabled:
            return self._disabled_outcome()
        if spec.tenant != self.tenant:
            # Fail closed: a runner never touches another tenant's work. This is the single-tenant fault
            # domain made explicit — a mis-routed job is refused, never silently cross-run.
            raise RunnerError(
                f"runner for {self.tenant!r} refuses a job for {spec.tenant!r} (one tenant per runner)"
            )

        # ``payload`` is JSON-canonical (opaque to the runner); content_id hashes it deterministically.
        payload_digest = content_id(spec.kind, spec.payload)
        job_id = self._next_job_id(payload_digest)
        job = Job(job_id=job_id, tenant=self.tenant, kind=spec.kind, payload_digest=payload_digest)
        self._state = submit(self._state, job)
        self._state = transition(self._state, job_id, JobState.RUNNING)

        try:
            execute(self._state.require(job_id))
        except KilledJob as k:
            reason = str(k) or "killed"
            self._state = kill_job(self._state, job_id, reason=reason)
            _log.warning("aegis job killed", extra={"tenant": self.tenant, "job_id": job_id, "reason": reason})
            return self._outcome(job_id)
        except Exception as e:  # noqa: BLE001 — fault containment: a failing body degrades ONE tenant, never crashes
            detail = f"{type(e).__name__}: {e}"
            self._state = transition(self._state, job_id, JobState.FAILED, detail=detail)
            _log.warning("aegis job failed", extra={"tenant": self.tenant, "job_id": job_id, "detail": detail})
            return self._outcome(job_id)

        self._state = transition(self._state, job_id, JobState.SUCCEEDED)
        return self._outcome(job_id)

    def kill(self, job_id: str, *, reason: str) -> RunOutcome:
        """Terminate a live job out of band (the control-plane ``manage_defense`` relocate / crash-loop
        cap path). Degrades this tenant only. A disabled runner has no jobs -> fixed disabled outcome."""
        if not self.enabled:
            return self._disabled_outcome()
        self._state = kill_job(self._state, job_id, reason=reason)
        return self._outcome(job_id)

    def _outcome(self, job_id: str) -> RunOutcome:
        job = self._state.require(job_id)
        return RunOutcome(
            enabled=True,
            tenant=self.tenant,
            job_id=job_id,
            state=job.state,
            health=self.health(),
            projection_digest=self.projection_digest(),
            detail=job.detail,
        )
