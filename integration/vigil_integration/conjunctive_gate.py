"""
conjunctive_gate — every target-touching offense action must pass BOTH gates (VIGIL P7 Slice 3).

Two orthogonal, conjunctive checks over one signed spine, per the plan's governance doctrine:

  * CRUCIBLE authority — "is THIS target/action inside the signed engagement envelope RIGHT NOW?"
    (killswitch → validity window → scope → destructive → live-destructive → budget; fail-closed).
    Its killswitch step has absolute precedence, so it is checked FIRST.
  * WARDEN tool gate — "what TIER is this tool-class, and must the owner approve it?"
    (raise-only A2 floor → auto / queue / deny; see warden_gate.decide_tool).

First failure wins; ANY error in either half is a DENY (never caught-and-continued). The verdict
is the conjunction: ALLOW only if CRUCIBLE says in-envelope AND WARDEN says auto; QUEUE if
in-envelope but WARDEN needs owner approval; DENY otherwise.

The composition core (:func:`conjunctive_decide`) is pure — both halves are injected as thunks —
so it is fully testable without CRUCIBLE or the kernel. :func:`build_offense_gate` wires the real
CRUCIBLE ``authorize_action`` (loaded via the governance trust root — the seam map flagged a
``None`` trust root as the biggest fail-open) and the real WARDEN classifier; its ``framework``
import is LAZY so this module stays import-clean for the sovereign side (which never calls it).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .warden_gate import DEFAULT_CEILING, DEFAULT_FLOOR, ToolDecision, decide_tool


@dataclass(frozen=True)
class GateVerdict:
    allowed: bool          # may this action auto-run right now?
    outcome: str           # "allow" | "queue" | "deny"
    reason: str
    crucible_allowed: bool | None      # CRUCIBLE in-envelope? (None if it errored)
    warden: ToolDecision | None        # the WARDEN tool decision (None if not reached/errored)


@dataclass(frozen=True)
class CrucibleResult:
    """The minimal shape the composition needs from the CRUCIBLE authority half."""
    allowed: bool
    reason: str


def conjunctive_decide(
    *,
    crucible_authorize: Callable[[], CrucibleResult],
    warden_decide: Callable[[], ToolDecision],
) -> GateVerdict:
    """Compose the two gates, first-failure-wins, fail-closed. Both halves are thunks."""
    # 1. CRUCIBLE first — its killswitch step is the absolute stop. Any deny OR error => DENY.
    try:
        cru = crucible_authorize()
    except Exception as exc:  # a raised EthicsViolation (halted/expired/out-of-scope/…) or any error
        return GateVerdict(False, "deny", f"CRUCIBLE gate error/refusal (fail-closed): {exc}", None, None)
    if not cru.allowed:
        return GateVerdict(False, "deny", f"CRUCIBLE denied: {cru.reason}", False, None)

    # 2. WARDEN tool gate.
    try:
        war = warden_decide()
    except Exception as exc:
        return GateVerdict(False, "deny", f"WARDEN gate error (fail-closed): {exc}", True, None)
    if war.outcome == "auto":
        return GateVerdict(True, "allow", "both gates allow: CRUCIBLE in-envelope AND WARDEN auto", True, war)
    if war.outcome == "queue":
        return GateVerdict(False, "queue", f"in envelope, but WARDEN needs owner approval: {war.reason}", True, war)
    # "deny" OR any unrecognised WARDEN outcome → DENY. Only an explicit "auto" may ALLOW, so a
    # new/unexpected outcome string can never silently open the gate (fail-closed conjunction).
    return GateVerdict(False, "deny", f"WARDEN refused tool {war.tool!r} (outcome={war.outcome!r}): {war.reason}", True, war)


def build_offense_gate(
    *,
    slug: str,
    trust_root: Any,
    classify: Callable[[str], str],
    floor: str = DEFAULT_FLOOR,
    ceiling: str = DEFAULT_CEILING,
    killswitch: Any = None,
    actions_taken: int = 0,
    now: Any = None,
) -> Callable[[str, str, bool], GateVerdict]:
    """Return ``gate(tool_name, target_url, destructive) -> GateVerdict`` wired to the REAL gates.

    Offense-side only: imports ``framework`` lazily (this module never runs in the sovereign env).
    ``trust_root`` MUST be the governance TrustRoot — the CRUCIBLE authority is loaded verified,
    so a tampered scope/window/destructive-flag is rejected at load (the map's biggest fail-open).
    A ``None`` trust_root is refused: it would load the authority UNSIGNED, so it fails closed here.
    """
    if trust_root is None:
        raise ValueError(
            "build_offense_gate requires the governance trust_root: a None trust_root loads the "
            "CRUCIBLE authority UNSIGNED/unverified, so a tampered scope/window/destructive flag "
            "would pass the gate. Fail-closed refusal."
        )

    def gate(tool_name: str, target_url: str, destructive: bool = False) -> GateVerdict:
        def crucible_authorize() -> CrucibleResult:
            # Lazy import keeps the module import-clean; only reachable in env-offense.
            from framework.v2.authority.gate import authorize_action, load_authority_for_gate
            from framework.v2.authority.models import ActionRequest

            authority = load_authority_for_gate(slug, trust_root=trust_root)  # verified, fail-closed
            req = ActionRequest(target=target_url, action_kind="offense", destructive=destructive)
            decision = authorize_action(
                authority, req, killswitch=killswitch, actions_taken=actions_taken, now=now,
            )
            return CrucibleResult(allowed=bool(decision.allowed), reason=decision.reason)

        def warden_decide() -> ToolDecision:
            return decide_tool(tool_name, classify=classify, floor=floor, ceiling=ceiling)

        return conjunctive_decide(crucible_authorize=crucible_authorize, warden_decide=warden_decide)

    return gate
