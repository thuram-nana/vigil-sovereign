"""AEGIS AS-27b — the DEFENSE-CONTROL (``manage_defense``) read-only posture + stand-down preview.

AS-4b (:mod:`vigil_core.contract_eval`) previews the RELEASE gate — the DANGEROUS direction, a host moving
from the always-safe Observe base INTO enforce/Respond. AS-27b is its SAFE-direction mirror: it grades the
DEFENSE-CONTROL posture the ``manage_defense`` capability governs, and previews the authorized STAND-DOWN —
the safe-direction override that returns an enforcing host to Observe. Where AS-4b asks "could this host be
released to enforce, and why not", AS-27b asks "is this host enforcing right now, and would an authorized
stand-down have any effect". Together the customer sees the whole defense-control picture, each read-only.

The slice is named "override + ``manage_defense``": the OVERRIDE is this stand-down (the §4.5
``enforcement_terms.override_active`` downgrade-only signal, and the data plane's unsigned downgrade-only
``override.json`` — both only ever REDUCE authority), and ``manage_defense`` is the capability (vigil_core.rbac)
that may operate it. This module is the read-only EVALUATOR; it issues no stand-down.

Doctrine (inherited from :mod:`vigil_core.contract_eval` / :mod:`vigil_core.protection_contract`):

  * READ-ONLY / NEVER AUTHORITY — every function here only READS and GRADES already-verified state. It signs
    nothing, mints nothing, arms nothing, stands nothing down, and cannot raise OR lower anyone's live
    authority. A view is a snapshot a renderer reads; a real stand-down stays behind the owner-signed gate.
  * SAFE DIRECTION ONLY — the only control this slice describes is a stand-down (enforce -> observe), which
    REDUCES authority; it never widens scope, never releases a host into enforce (that is AS-29), and never
    grants a capability. A stand-down is meaningful ONLY on a host that is actively enforcing.
  * FAIL-CLOSED / HONEST — ``enforcing`` is the AND of every precondition and defaults ``False``; a
    stand-down is reported ``available`` only when there is live enforcement to stand down, and
    ``standdown_blockers`` names, in a closed honest vocabulary, why it would be a no-op otherwise. A missing
    input reads as "not enforcing", never "enforcing".
  * DETERMINISM — no wallclock, no RNG; set-valued outputs are sorted + de-duplicated.

FATAL-2: imports only ``vigil_core`` siblings + stdlib + pydantic. No ``framework``, no ``sigil``.
"""
from __future__ import annotations

from typing import Final

from pydantic import ConfigDict, Field, field_validator

from .aegis_schemas import CanonicalModel
from .authority_v2 import check_dns_host
from .monitoring_authority import MonitoringMode

# The closed, honest vocabulary a view names when a stand-down would have NO effect (the host is not
# enforcing). Fail-closed: a renderer maps each token to fixed copy and claims nothing beyond it.
STANDDOWN_NOT_ENFORCING: Final[str] = "not_enforcing"
STANDDOWN_ALREADY_STOOD_DOWN: Final[str] = "already_stood_down"


class HostDefenseControl(CanonicalModel):
    """A READ-ONLY, per-host projection of the DEFENSE-CONTROL posture ``manage_defense`` governs: whether the
    host is enforcing live blocking right now, and whether an authorized stand-down (the safe-direction
    override back to Observe) would have any effect. It is NEVER authority — nothing here stands a host down;
    ``standdown_available`` only states whether a stand-down WOULD reduce live enforcement, and
    ``standdown_blockers`` names, honestly, why it would be a no-op. Fail-closed: ``enforcing`` and
    ``standdown_available`` both default ``False``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    host: str
    mode: MonitoringMode = Field(default=MonitoringMode.OBSERVE)
    armed: bool = Field(default=False)
    proof_current: bool = Field(default=False)
    respond_entitled: bool = Field(default=False)
    enforcing: bool = Field(default=False, description="Live blocking (Respond) is in force right now.")
    override_active: bool = Field(default=False, description="A downgrade-only override already stands enforcement down.")
    standdown_available: bool = Field(default=False, description="An authorized stand-down would reduce live enforcement.")
    standdown_blockers: tuple[str, ...] = Field(default_factory=tuple)

    @field_validator("host")
    @classmethod
    def _host(cls, v: str) -> str:
        # A bare DNS host (the same shape the grant declares); IP literals refused.
        return check_dns_host(v, label="defense_control.host")

    def customer_safe(self) -> dict:
        """The customer-plane projection the edge returns over the hop: enum values, booleans and token lists
        only — no secret, no internal id, nothing a host does not already see on the Monitoring screen."""
        return {
            "host": self.host,
            "mode": self.mode.value,
            "armed": self.armed,
            "proof_current": self.proof_current,
            "respond_entitled": self.respond_entitled,
            "enforcing": self.enforcing,
            "override_active": self.override_active,
            "standdown_available": self.standdown_available,
            "standdown_blockers": list(self.standdown_blockers),
        }


def defense_control_host(
    host: str,
    *,
    mode: MonitoringMode,
    armed: bool,
    proof_current: bool,
    respond_entitled: bool,
    override_active: bool = False,
) -> HostDefenseControl:
    """Grade, read-only, the DEFENSE-CONTROL posture for ``host`` from already-verified inputs (its armed
    mode, whether its ownership proof is current, whether the plan entitles Respond, and whether a
    downgrade-only override already stands it down).

    ``enforcing`` is the fail-closed AND of every precondition for LIVE blocking: the host must be armed, in
    BLOCK mode, with a current ownership proof, on a Respond-entitled plan, and NOT already stood down by an
    override. A stand-down (the safe-direction override back to Observe) is ``available`` iff there is live
    enforcement to stand down — i.e. exactly when ``enforcing`` holds. ``standdown_blockers`` names, in a
    closed honest vocabulary, why a stand-down would be a NO-OP: ``already_stood_down`` when an override is
    already in force, else ``not_enforcing`` when the host is not blocking. The result is NEVER an action."""
    enforcing = bool(
        armed
        and proof_current
        and respond_entitled
        and mode is MonitoringMode.BLOCK
        and not override_active
    )

    blockers: list[str] = []
    if override_active:
        blockers.append(STANDDOWN_ALREADY_STOOD_DOWN)
    elif not enforcing:
        blockers.append(STANDDOWN_NOT_ENFORCING)
    standdown_available = not blockers

    return HostDefenseControl(
        host=host,
        mode=mode,
        armed=armed,
        proof_current=proof_current,
        respond_entitled=respond_entitled,
        enforcing=enforcing,
        override_active=override_active,
        standdown_available=standdown_available,
        standdown_blockers=tuple(sorted(blockers)),
    )


__all__ = [
    "STANDDOWN_NOT_ENFORCING",
    "STANDDOWN_ALREADY_STOOD_DOWN",
    "HostDefenseControl",
    "defense_control_host",
]
