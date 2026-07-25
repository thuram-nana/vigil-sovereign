"""The ONE authorization-gate composition of record (unification S6).

Every action-bearing edge in BOTH engines authorizes through the same pure, fail-closed conjunction: an
action ALLOWs only if the domain authority is in-envelope AND the WARDEN tool tier auto-approves AND (for a
destructive/high-blast action) an owner-inclusive m-of-n threshold authorization is present. First failure
wins; ANY error in ANY conjunct is a DENY (never caught-and-continued); only an explicit WARDEN ``"auto"``
may open the gate, so a new/unexpected outcome can never silently ALLOW.

This module hosts the PURE core (``conjunctive_decide`` + its result/verdict shapes) in the neutral shared
``vigil_core`` so BOTH processes import the SAME gate-of-record primitive without a reversed dependency
(before S6 it lived in the offense ``integration`` seam, unreachable to the sovereign side without importing
the offense engine). Each process supplies its OWN trust-domain-appropriate thunks — the offense wrapper
(``integration.conjunctive_gate.build_offense_gate``) wires the CRUCIBLE authority + kernel classifier +
destruction quorum; a sovereign composition supplies the Governor + the shared classifier. The core imports
nothing but stdlib, so it is a leaf both envs load and it can never drag ``framework``/``strix`` into the
owner-key process (the two-env boundary).

Fail-closed invariants that MUST hold (pinned by ``tests/test_gate.py``): a raised conjunct → DENY; the
strict ``authorized is True`` identity check on the destructive conjunct (a truthy-but-not-True value must
NOT open an irreversible action); an unrecognised WARDEN outcome → DENY; a missing destruction gate on a
destructive action → DENY.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional, Protocol


class WardenDecision(Protocol):
    """The minimal shape the composition needs from the WARDEN tool gate. Any object exposing these
    attributes (e.g. ``integration.warden_gate.ToolDecision``) satisfies it structurally, so this core stays
    a leaf with NO dependency on the integration seam (which would be a reversed, boundary-illegal import)."""
    outcome: str    # "auto" | "queue" | "deny"
    tool: str
    reason: str


@dataclass(frozen=True)
class GateVerdict:
    allowed: bool                       # may this action auto-run right now?
    outcome: str                        # "allow" | "queue" | "deny"
    reason: str
    crucible_allowed: Optional[bool]    # domain authority in-envelope? (None if it errored)
    warden: Optional[WardenDecision]    # the WARDEN tool decision (None if not reached/errored)


@dataclass(frozen=True)
class CrucibleResult:
    """The minimal shape the composition needs from the domain (CRUCIBLE / sovereign) authority half."""
    allowed: bool
    reason: str


@dataclass(frozen=True)
class DestructionOutcome:
    """The minimal shape the composition needs from the threshold-destruction half. The concrete
    ``destruction_gate.DestructionDecision`` (``.authorized`` + ``.reason``) satisfies this duck-type,
    so the composition stays decoupled from that module and is testable in isolation."""
    authorized: bool
    reason: str


def conjunctive_decide(
    *,
    crucible_authorize: Callable[[], CrucibleResult],
    warden_decide: Callable[[], WardenDecision],
    destructive: bool = False,
    destruction_authorize: Optional[Callable[[], Any]] = None,
) -> GateVerdict:
    """Compose the gates, first-failure-wins, fail-closed. Both core halves are thunks. For a
    DESTRUCTIVE action a THIRD conjunct is required — the m-of-n threshold-destruction authorization
    (``destruction_authorize`` returns an object with ``.authorized`` + ``.reason``); a destructive
    action with no destruction gate wired, an errored gate, or an unauthorized result is a DENY."""
    # 1. Domain authority first — its killswitch step is the absolute stop. Any deny OR error => DENY.
    try:
        cru = crucible_authorize()
    except Exception as exc:  # noqa: BLE001 — a raised refusal (halted/expired/out-of-scope/…) or any error
        return GateVerdict(False, "deny", f"CRUCIBLE gate error/refusal (fail-closed): {exc}", None, None)
    if not cru.allowed:
        return GateVerdict(False, "deny", f"CRUCIBLE denied: {cru.reason}", False, None)

    # 2. WARDEN tool gate.
    try:
        war = warden_decide()
    except Exception as exc:  # noqa: BLE001 — a classifier/gate error is a DENY, never a silent pass
        return GateVerdict(False, "deny", f"WARDEN gate error (fail-closed): {exc}", True, None)

    # 3. Threshold-destruction gate — a HARD extra conjunct for destructive/high-blast actions. It is
    #    orthogonal to WARDEN's tier approval: an autonomous worker must not perform an irreversible
    #    action without the owner-inclusive m-of-n quorum, even if WARDEN would auto-allow the class.
    if destructive:
        if destruction_authorize is None:
            return GateVerdict(
                False, "deny",
                "destructive action requires a threshold-destruction gate, but none was wired "
                "(fail-closed)", True, war,
            )
        try:
            dz = destruction_authorize()
        except Exception as exc:  # noqa: BLE001 — a destruction-gate error denies the irreversible action
            return GateVerdict(False, "deny", f"destruction gate error (fail-closed): {exc}", True, war)
        if getattr(dz, "authorized", False) is not True:
            # strict `is True` (not truthiness): a buggy/adversarial gate returning a truthy-but-not-
            # bool authorized (e.g. "no", 1, a non-empty list) must NOT open the irreversible-action gate.
            return GateVerdict(
                False, "deny",
                f"destructive action not threshold-authorized: {getattr(dz, 'reason', 'refused')}",
                True, war,
            )

    if war.outcome == "auto":
        note = "both gates allow: CRUCIBLE in-envelope AND WARDEN auto"
        if destructive:
            note += " AND destruction threshold-authorized"
        return GateVerdict(True, "allow", note, True, war)
    if war.outcome == "queue":
        return GateVerdict(False, "queue", f"in envelope, but WARDEN needs owner approval: {war.reason}", True, war)
    # "deny" OR any unrecognised WARDEN outcome → DENY. Only an explicit "auto" may ALLOW, so a
    # new/unexpected outcome string can never silently open the gate (fail-closed conjunction).
    return GateVerdict(False, "deny", f"WARDEN refused tool {war.tool!r} (outcome={war.outcome!r}): {war.reason}", True, war)
