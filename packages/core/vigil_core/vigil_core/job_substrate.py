"""vigil_core.job_substrate — AS-30 (D17, #1202): the per-tenant job-substrate PRIMITIVE.

A pure, deterministic, stdlib-only model of a per-tenant defensive job substrate, promoted into the
plane-neutral ``vigil_core`` so BOTH planes load the SAME primitive. The offense/defense ENGINE plane
runs jobs through it (``framework.v2.aegis.job_runner``); the sovereign SIGIL plane RENDERS a tenant's
job-substrate health to that tenant through VIGIL WITHOUT importing the engine (FATAL-2). Promoting the
primitives into ``vigil_core`` is exactly D17 ("Executor env; primitives move").

The load-bearing property (plan AS-30 acceptance — *"killed job degrades TT-A only"*) is FAULT
ISOLATION: a tenant's health and its rendered projection are a PURE FUNCTION of that tenant's OWN jobs,
so a kill / fault on one tenant's job can change ONLY that tenant's projection. Every OTHER tenant's
projection bytes are BYTE-IDENTICAL across the event (:func:`isolation_witness` proves which tenants
moved), so a noisy neighbour degrades honestly and ALONE instead of degrading everyone silently (§8
isolation-and-fairness rule: a per-tenant bound, an over-limit state visible to that tenant, and the
other tenant unaffected).

Stdlib-closed (the re-execution closure stays stdlib-only, like ``vigil_core.gate`` and
``vigil_core.seam_base``): this leaf imports nothing but ``dataclasses`` / ``enum`` / ``hashlib`` /
``json`` / ``typing`` — no ``framework``, no ``sigil``, not even ``pydantic`` — so the standalone
sovereign leg and any re-execution kernel load it with no heavy dependency. Pinned by
``tests/test_job_substrate.py::test_the_leaf_is_stdlib_only`` (the ``make gate`` ported-primitive
closure guard).

DETERMINISM (no wall-clock, no RNG on any signed path): every id is a sha256 content hash of canonical
fields, so the same inputs yield byte-identical output. Immutable throughout — every operation returns
a NEW frozen state (append-only in spirit); nothing mutates in place.

This primitive carries NO runtime effect of its own — it is pure logic + data. The default-OFF
capability gate (inert when off; flag-off byte-identical) lives in the engine-plane runner that drives
it (``framework.v2.aegis.job_runner``), never here.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from enum import Enum
from typing import Iterable, Mapping, Optional

__all__ = [
    "JobSubstrateError",
    "JobState",
    "TenantHealth",
    "Job",
    "SubstrateState",
    "TENANT_HEALTH_DEGRADING_STATES",
    "canonical_bytes",
    "content_id",
    "submit",
    "transition",
    "kill_job",
    "isolation_witness",
]


class JobSubstrateError(ValueError):
    """A fail-closed refusal in the job-substrate primitive (unknown job, bad transition, bad input).

    A ``ValueError`` subclass so a caller that only catches ``ValueError`` still fails closed; the
    distinct type lets the runner tell a substrate refusal from an arbitrary error."""


# ==================================================================================================
# Closed vocabularies — jobs and per-tenant health.
# ==================================================================================================
class JobState(str, Enum):
    """The CLOSED lifecycle of one job on the substrate. ``str`` mixin so the value serializes directly
    into the canonical projection (determinism). The terminal set is {SUCCEEDED, FAILED, KILLED}.

      * ``queued``     — accepted onto the per-tenant substrate, not started.
      * ``running``    — the per-tenant runner is executing it.
      * ``succeeded``  — ran to completion (terminal, healthy).
      * ``failed``     — the job body raised / returned a failure (terminal, DEGRADING).
      * ``killed``     — the job was terminated out of band — OOM-kill, a ``manage_defense`` relocate,
                         a crash-loop cap (terminal, DEGRADING). This is the acceptance event.
    """

    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    KILLED = "killed"


#: Terminal states that degrade the owning tenant's health. A tenant whose substrate holds a KILLED or
#: FAILED job is ``degraded`` — honest, and SCOPED to that tenant (fault isolation).
TENANT_HEALTH_DEGRADING_STATES: frozenset[JobState] = frozenset({JobState.FAILED, JobState.KILLED})

_TERMINAL_STATES: frozenset[JobState] = frozenset(
    {JobState.SUCCEEDED, JobState.FAILED, JobState.KILLED}
)

# The permitted non-terminal forward transitions. A terminal state is final (fail-closed: no resurrection,
# which would let a killed job silently un-degrade a tenant). ``killed`` is reachable from any live state
# via :func:`kill_job` (an out-of-band terminate can land on a queued OR a running job).
_FORWARD: Mapping[JobState, frozenset[JobState]] = {
    JobState.QUEUED: frozenset({JobState.RUNNING, JobState.SUCCEEDED, JobState.FAILED, JobState.KILLED}),
    JobState.RUNNING: frozenset({JobState.SUCCEEDED, JobState.FAILED, JobState.KILLED}),
}


class TenantHealth(str, Enum):
    """A tenant's job-substrate health. The ``degraded`` / ``down`` tokens are the SAME honest headline
    vocabulary as ``vigil_core.protection_contract.Headline`` (``degraded``) and
    ``vigil_core.aegis_schemas.EngineHealthState`` (``down``) — reused, never re-coined, so the D13
    closed vocabulary is not forked. Value-parity with those enums is pinned by the tests. ``nominal`` is
    the healthy state (no degrading job); it is a job-substrate token, not an overclaim of enforcement."""

    NOMINAL = "nominal"       # no degrading job on this tenant's substrate
    DEGRADED = "degraded"     # ≥1 killed/failed job on THIS tenant's substrate (scoped, honest)
    DOWN = "down"             # the tenant's runner is absent — fail-closed floor (never reads NOMINAL)


# ==================================================================================================
# Canonicalization — the one deterministic serialization every id / projection is built from.
# ==================================================================================================
def canonical_bytes(obj: object) -> bytes:
    """Canonical JSON bytes (sorted keys, tight separators, UTF-8). The ONE serialization the substrate
    hashes and projects from, so two equal states produce byte-identical output on any machine."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def content_id(*parts: object) -> str:
    """A deterministic 64-bit (16 hex) sha256 content id over ``parts``. No RNG, no wall-clock — the same
    parts always yield the same id (enough to disambiguate a job within a tenant)."""
    return hashlib.sha256(canonical_bytes(list(parts))).hexdigest()[:16]


# ==================================================================================================
# Job — one immutable job record on the substrate.
# ==================================================================================================
@dataclass(frozen=True, slots=True)
class Job:
    """One job on a tenant's substrate. Immutable; a transition returns a NEW ``Job``. ``payload_digest``
    is the content id of whatever the runner will execute (the runner computes it; the substrate stores
    it opaquely). ``tenant`` is the partition key — a job belongs to exactly one tenant and is only ever
    visible in that tenant's projection."""

    job_id: str
    tenant: str
    kind: str
    payload_digest: str
    state: JobState = JobState.QUEUED
    detail: str = ""

    def __post_init__(self) -> None:
        if not (isinstance(self.job_id, str) and self.job_id):
            raise JobSubstrateError("job_id must be a non-empty str")
        if not (isinstance(self.tenant, str) and self.tenant):
            raise JobSubstrateError("tenant must be a non-empty str")
        if not isinstance(self.state, JobState):
            raise JobSubstrateError("state must be a JobState")

    def canonical(self) -> dict[str, str]:
        """The canonical, projection-stable mapping for this job (sorted-key JSON is applied on top)."""
        return {
            "job_id": self.job_id,
            "tenant": self.tenant,
            "kind": self.kind,
            "payload_digest": self.payload_digest,
            "state": self.state.value,
            "detail": self.detail,
        }


# ==================================================================================================
# SubstrateState — the shared, append-only-in-spirit substrate view, PARTITIONED per tenant.
# ==================================================================================================
@dataclass(frozen=True, slots=True)
class SubstrateState:
    """The whole substrate as the fleet/console sees it: every tenant's jobs in one immutable value,
    but PROJECTED strictly per tenant. ``jobs`` is kept sorted by ``(tenant, job_id)`` so equal states are
    byte-equal. Every mutator returns a NEW ``SubstrateState``.

    The fault-isolation contract: :meth:`tenant_projection` and :meth:`tenant_health` read ONLY the given
    tenant's own jobs, so one tenant's projection bytes cannot depend on another tenant's jobs."""

    jobs: tuple[Job, ...] = ()

    def __post_init__(self) -> None:
        keys = [(j.tenant, j.job_id) for j in self.jobs]
        if len(set(keys)) != len(keys):
            raise JobSubstrateError("duplicate (tenant, job_id) in substrate state")
        ordered = tuple(sorted(self.jobs, key=lambda j: (j.tenant, j.job_id)))
        if ordered != self.jobs:
            object.__setattr__(self, "jobs", ordered)

    # --- lookups ---------------------------------------------------------------------------------
    def by_id(self) -> dict[str, Job]:
        return {j.job_id: j for j in self.jobs}

    def get(self, job_id: str) -> Optional[Job]:
        for j in self.jobs:
            if j.job_id == job_id:
                return j
        return None

    def require(self, job_id: str) -> Job:
        j = self.get(job_id)
        if j is None:
            raise JobSubstrateError(f"no such job: {job_id!r}")
        return j

    def tenants(self) -> tuple[str, ...]:
        """The tenants present, in sorted order (deterministic)."""
        return tuple(sorted({j.tenant for j in self.jobs}))

    # --- per-tenant projection (the isolation boundary) ------------------------------------------
    def tenant_jobs(self, tenant: str) -> tuple[Job, ...]:
        """ONLY ``tenant``'s jobs, in job-id order. Another tenant's jobs are never returned — the read
        is partitioned, so a cross-tenant object answers like a nonexistent one (§8)."""
        return tuple(j for j in self.jobs if j.tenant == tenant)

    def tenant_health(self, tenant: str) -> TenantHealth:
        """``tenant``'s health computed PURELY from ``tenant``'s OWN jobs: ``degraded`` iff any of its
        jobs is in a degrading terminal state (killed / failed), else ``nominal``. No cross-tenant input,
        so another tenant's kill can never move this value."""
        own = self.tenant_jobs(tenant)
        if any(j.state in TENANT_HEALTH_DEGRADING_STATES for j in own):
            return TenantHealth.DEGRADED
        return TenantHealth.NOMINAL

    def tenant_projection(self, tenant: str) -> dict[str, object]:
        """The canonical per-tenant view the sovereign plane RENDERS to ``tenant`` through VIGIL: its
        health plus its own jobs, and NOTHING of any other tenant. This mapping (serialized by
        :func:`canonical_bytes`) is the byte-identity witness for fault isolation."""
        return {
            "tenant": tenant,
            "health": self.tenant_health(tenant).value,
            "jobs": [j.canonical() for j in self.tenant_jobs(tenant)],
        }

    def tenant_projection_digest(self, tenant: str) -> str:
        """A full sha256 of ``tenant``'s projection bytes. Two substrate states that render ``tenant``
        identically have the same digest — the deterministic equality the isolation test asserts."""
        return hashlib.sha256(canonical_bytes(self.tenant_projection(tenant))).hexdigest()

    def digest(self) -> str:
        """A content digest over the WHOLE substrate (all tenants). Determinism anchor for the state."""
        return hashlib.sha256(canonical_bytes([j.canonical() for j in self.jobs])).hexdigest()


# ==================================================================================================
# Operations — each returns a NEW SubstrateState (immutable; no in-place mutation).
# ==================================================================================================
def _with_jobs(state: SubstrateState, jobs: Iterable[Job]) -> SubstrateState:
    return SubstrateState(jobs=tuple(jobs))


def submit(state: SubstrateState, job: Job) -> SubstrateState:
    """Accept ``job`` onto the substrate (it must be ``queued`` and new). Fail-closed on a duplicate id
    or a non-queued initial state — a job is only ever admitted at the start of its lifecycle."""
    if not isinstance(job, Job):
        raise JobSubstrateError("submit requires a Job")
    if job.state is not JobState.QUEUED:
        raise JobSubstrateError(f"a submitted job must start queued, got {job.state.value!r}")
    if state.get(job.job_id) is not None:
        raise JobSubstrateError(f"duplicate job_id: {job.job_id!r}")
    return _with_jobs(state, (*state.jobs, job))


def transition(state: SubstrateState, job_id: str, new_state: JobState, *, detail: str = "") -> SubstrateState:
    """Move ``job_id`` to ``new_state`` along the permitted forward edges. A terminal state is final
    (fail-closed: no transition OUT of succeeded/failed/killed), so a tenant cannot silently un-degrade.
    Use :func:`kill_job` for the out-of-band KILLED path."""
    if not isinstance(new_state, JobState):
        raise JobSubstrateError("new_state must be a JobState")
    job = state.require(job_id)
    if job.state in _TERMINAL_STATES:
        raise JobSubstrateError(f"job {job_id!r} is terminal ({job.state.value}); no further transition")
    allowed = _FORWARD.get(job.state, frozenset())
    if new_state not in allowed:
        raise JobSubstrateError(
            f"illegal transition {job.state.value} -> {new_state.value} for job {job_id!r}"
        )
    moved = replace(job, state=new_state, detail=detail or job.detail)
    return _with_jobs(state, (moved if j.job_id == job_id else j for j in state.jobs))


def kill_job(state: SubstrateState, job_id: str, *, reason: str) -> SubstrateState:
    """Terminate ``job_id`` out of band -> ``killed``. The owning tenant degrades; by construction NO
    other tenant's projection can change (the acceptance: a killed job degrades that tenant ONLY).

    A kill lands on any LIVE job (queued or running); killing an already-terminal job is a fail-closed
    refusal (idempotence is the caller's business — a second, distinct kill is a bug to surface)."""
    if not reason:
        raise JobSubstrateError("kill_job requires a non-empty reason")
    job = state.require(job_id)
    if job.state in _TERMINAL_STATES:
        raise JobSubstrateError(f"job {job_id!r} already terminal ({job.state.value}); cannot kill")
    killed = replace(job, state=JobState.KILLED, detail=reason)
    return _with_jobs(state, (killed if j.job_id == job_id else j for j in state.jobs))


def isolation_witness(before: SubstrateState, after: SubstrateState) -> frozenset[str]:
    """The set of tenants whose RENDERED PROJECTION changed between two substrate states — the
    deterministic fault-isolation witness. For a single-tenant event (e.g. :func:`kill_job`) this must be
    a subset of {that tenant}: every other tenant's projection bytes are identical before and after.

    Computed over the UNION of tenants in either state, so a tenant that vanished or appeared counts as a
    projection change too (fail-closed: it never under-reports movement)."""
    tenants = set(before.tenants()) | set(after.tenants())
    moved: set[str] = set()
    for t in tenants:
        if before.tenant_projection_digest(t) != after.tenant_projection_digest(t):
            moved.add(t)
    return frozenset(moved)
