"""AEGIS AS-6d — the customer tenant ONBOARDING-JOURNEY evaluator (connected host -> monitored).

AS-6d is the tenant-onboarding increment, the final link in the customer-app UI chain
(4a->2f->2g->2k->21a->29->3d->4b->27b->6d). It composes the already-built monitoring-authority +
defense-control surfaces into a GUIDED FLOW: it walks a tenant from a connected (proven) host to a
monitored (observe) host, and then surfaces the AS-4b protection preview (:mod:`vigil_core.contract_eval`)
and the AS-27b defense-control view (:mod:`vigil_core.defense_control`) as the explore-next steps. This
module is the read-only EVALUATOR that GRADES where a tenant is on that journey; it COMPOSES the existing
surfaces, it does not re-implement ``preview_host`` / ``defense_control_host`` (nor the monitoring toggle).

Doctrine (inherited from :mod:`vigil_core.contract_eval` / :mod:`vigil_core.defense_control`):

  * READ-ONLY / NEVER AUTHORITY — every function here only READS and GRADES already-resolved facts. It
    signs nothing, mints nothing, arms nothing; a journey is a snapshot a renderer reads. Turning
    monitoring on stays behind the EXISTING gated ``monitoring/authorize`` write on the Monitoring screen.
  * FAIL-CLOSED / HONEST — a step is ``done`` only when its own grounded condition holds, and the journey
    is ``complete`` only when a host is actually monitored. A missing fact reads as "not done", never
    "done"; when the journey is complete no step is reported as the ``current`` one.
  * DETERMINISM — no wallclock, no RNG. The inputs are already-resolved booleans/counts (the caller
    applies "now" when it resolves the active grants and current ownership proofs), and the step order is
    a fixed tuple. Set-valued / ordered outputs are produced in that fixed order.

FATAL-2: imports only ``vigil_core`` siblings + stdlib + pydantic. No ``framework``, no ``sigil``.
"""
from __future__ import annotations

from typing import Final, Optional

from pydantic import ConfigDict, Field

from .aegis_schemas import CanonicalModel

# The ordered, closed set of onboarding steps a tenant walks from a connected host to a monitored one. The
# order is load-bearing: the journey is linear, so the ``current`` step is the FIRST not-done step and every
# step after it is ``todo``. A renderer maps each key to fixed copy and a deep-link; the evaluator names only
# the semantic key (honest by construction — the page invents nothing).
STEP_PROVE_HOST: Final[str] = "prove_host"       # the workspace has a host with a CURRENT ownership proof
STEP_PLAN: Final[str] = "plan"                    # the workspace has an active AEGIS monitoring plan
STEP_TURN_ON: Final[str] = "turn_on_observe"      # at least one host is actively monitored (observe/respond)
ONBOARDING_STEPS: Final[tuple[str, ...]] = (STEP_PROVE_HOST, STEP_PLAN, STEP_TURN_ON)

# The closed status vocabulary for a step. Fail-closed: a not-done step is ``current`` only when it is the
# first not-done step AND the journey is not already complete, else ``todo``.
STATUS_DONE: Final[str] = "done"
STATUS_CURRENT: Final[str] = "current"
STATUS_TODO: Final[str] = "todo"


class OnboardingStep(CanonicalModel):
    """A READ-ONLY projection of one onboarding step: its semantic ``key`` (a closed token), whether it is
    ``done`` (its grounded condition holds), and its ``status`` in the closed vocabulary. It is NEVER
    authority — it records only where the tenant already is, and performs nothing."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    key: str
    status: str = Field(default=STATUS_TODO)
    done: bool = Field(default=False)

    def customer_safe(self) -> dict:
        """The customer-plane projection: the step's semantic key, its status token and whether it is done —
        no secret, no internal id, nothing a manager does not already see on the Monitoring screens."""
        return {"key": self.key, "status": self.status, "done": self.done}


class OnboardingJourney(CanonicalModel):
    """A READ-ONLY projection of a tenant's AEGIS onboarding journey — where it is on the walk from a
    connected (proven) host to a monitored (observe) one, graded from already-resolved facts. It is NEVER
    authority: nothing here arms or releases a host. ``complete`` states, fail-closed, whether at least one
    host is actually monitored; ``next_step`` names the single step the tenant should do next (``None`` once
    complete); ``explore_available`` states whether the AS-4b preview + AS-27b defense-control read-only
    views are meaningful yet (they are once a host is monitored)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    proven_host_count: int = Field(default=0, ge=0)
    active_host_count: int = Field(default=0, ge=0)
    enforcing_host_count: int = Field(default=0, ge=0)
    has_plan: bool = Field(default=False)
    respond_entitled: bool = Field(default=False)
    steps: tuple[OnboardingStep, ...] = Field(default_factory=tuple)
    complete: bool = Field(default=False, description="At least one host is actively monitored.")
    next_step: Optional[str] = Field(default=None, description="The key of the current step, or None when complete.")
    explore_available: bool = Field(default=False, description="The read-only preview/control views are meaningful now.")

    def customer_safe(self) -> dict:
        """The customer-plane projection the edge returns over the hop: counts, booleans and closed tokens
        only — no secret, no internal id, no host name, nothing a manager does not already see on the
        Monitoring screens. The renderer maps each step key to fixed copy and a deep-link."""
        return {
            "proven_host_count": self.proven_host_count,
            "active_host_count": self.active_host_count,
            "enforcing_host_count": self.enforcing_host_count,
            "has_plan": self.has_plan,
            "respond_entitled": self.respond_entitled,
            "steps": [s.customer_safe() for s in self.steps],
            "complete": self.complete,
            "next_step": self.next_step,
            "explore_available": self.explore_available,
        }


def onboarding_journey(
    *,
    proven_host_count: int,
    active_host_count: int,
    has_plan: bool,
    respond_entitled: bool,
    enforcing_host_count: int = 0,
) -> OnboardingJourney:
    """Grade, read-only, a tenant's onboarding journey from already-resolved facts: how many hosts have a
    CURRENT ownership proof, how many are actively monitored (and of those, how many are enforcing), whether
    the workspace has an active AEGIS plan, and whether that plan entitles Respond.

    The journey is LINEAR (prove a host -> get an AEGIS plan -> turn monitoring on): each step is ``done``
    iff its grounded condition holds, the ``current`` step is the FIRST not-done step (and every step after
    it ``todo``), and ``complete`` is reached when at least one host is actually monitored — the destination
    of the walk. When the journey is complete no step is reported ``current`` (``next_step`` is ``None``).
    Fail-closed: a missing fact reads as "not done", never "done". The result is NEVER an action — turning
    monitoring on stays behind the existing gated monitoring/authorize write."""
    proven = max(0, int(proven_host_count))
    active = max(0, int(active_host_count))
    enforcing = max(0, int(enforcing_host_count))

    conditions: dict[str, bool] = {
        STEP_PROVE_HOST: proven > 0,
        STEP_PLAN: bool(has_plan),
        STEP_TURN_ON: active > 0,
    }
    complete = conditions[STEP_TURN_ON]

    steps: list[OnboardingStep] = []
    current_assigned = complete        # once complete, no step is the "current" one
    for key in ONBOARDING_STEPS:
        done = conditions[key]
        if done:
            status = STATUS_DONE
        elif not current_assigned:
            status = STATUS_CURRENT
            current_assigned = True
        else:
            status = STATUS_TODO
        steps.append(OnboardingStep(key=key, status=status, done=done))

    next_step = None if complete else next((s.key for s in steps if s.status == STATUS_CURRENT), None)

    return OnboardingJourney(
        proven_host_count=proven,
        active_host_count=active,
        enforcing_host_count=enforcing,
        has_plan=bool(has_plan),
        respond_entitled=bool(respond_entitled),
        steps=tuple(steps),
        complete=complete,
        next_step=next_step,
        explore_available=active > 0,
    )


__all__ = [
    "STEP_PROVE_HOST",
    "STEP_PLAN",
    "STEP_TURN_ON",
    "ONBOARDING_STEPS",
    "STATUS_DONE",
    "STATUS_CURRENT",
    "STATUS_TODO",
    "OnboardingStep",
    "OnboardingJourney",
    "onboarding_journey",
]
