"""
planner.executor — bridges goal-tree leaves to the MAO blackboard.

The planner picks a leaf, hands it to this module, and gets back a
posted Hypothesis event ID. The exploit-agent claims it on the next
coordinator tick. The planner reads back results to learn whether
the leaf succeeded or failed.

Two responsibilities live here:

  - `dispatch_leaf` — turn a GoalNode into a HypothesisPayload and
    post it to the blackboard.
  - `resolve_leaf`  — walk the blackboard for a Result/Finding tied
    to a previously-dispatched leaf and return a structured outcome.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..agents.blackboard import Blackboard
from ..agents.models import HypothesisPayload
from ..common import logging as v2log
from .goal_tree import GoalNode


_log = v2log.get_logger(__name__)


@dataclass
class LeafOutcome:
    """What the planner learns when a leaf's hypothesis resolves."""

    resolved: bool                    # has the result come back yet?
    success: bool = False
    finding_event_id: int | None = None
    refute_reason: str = ""
    requests: int = 0
    seconds: float = 0.0


def _hypothesis_handle(leaf: GoalNode) -> str:
    return f"L-{leaf.id:04d}"


def dispatch_leaf(
    *,
    blackboard: Blackboard,
    engagement_slug: str,
    leaf: GoalNode,
) -> int:
    """Post a Hypothesis on the blackboard for the exploit-agent to claim.

    Returns the new event id.  The handle is `L-NNNN` so the planner
    can later locate the matching result.
    """
    handle = _hypothesis_handle(leaf)
    payload = HypothesisPayload(
        handle=handle,
        surface=leaf.surface or "(unspecified)",
        bug_class=leaf.bug_class or "unclassified",
        given=f"goal-tree leaf {leaf.id}: {leaf.label[:120]}",
        if_action=leaf.label,
        then_observation="branch confirms a finding for this archetype",
        because_model=(
            f"prior_p_success={leaf.prior_p_success:.2f}; "
            f"value={leaf.value:.2f}; "
            f"derived from archetype attack-tree seed"
        ),
        refute_on="exploit-agent's executor reports failure",
        cheap_test="see archetype playbook for this bug class",
        confidence=leaf.prior_p_success,
        status="open",
    )
    eid = blackboard.post(
        engagement=engagement_slug, kind="hypothesis",
        agent_name="planner", payload=payload.model_dump(by_alias=True),
    )
    _log.info(
        "planner.executor.dispatched",
        leaf_id=leaf.id, handle=handle, event_id=eid,
        bug_class=leaf.bug_class, surface=leaf.surface,
    )
    return eid


def resolve_leaf(
    *,
    blackboard: Blackboard,
    engagement_slug: str,
    leaf: GoalNode,
) -> LeafOutcome:
    """Look on the blackboard for a Result tied to this leaf's hypothesis.

    The hypothesis lives by handle (L-NNNN). The exploit-agent posts a
    Plan->Action->Result chain whose Plan.targets_hypothesis matches.
    """
    handle = _hypothesis_handle(leaf)
    plans = blackboard.read(engagement=engagement_slug, kinds=["plan"])
    matching_plan = None
    for p in plans:
        if p.payload.get("targets_hypothesis") == handle:
            matching_plan = p
            break
    if matching_plan is None:
        return LeafOutcome(resolved=False)

    # find action under this plan
    actions = blackboard.read(engagement=engagement_slug, kinds=["action"])
    matching_action = None
    for a in actions:
        if a.parent_id == matching_plan.id:
            matching_action = a
            break
    if matching_action is None:
        return LeafOutcome(resolved=False)

    # find result under this action
    results = blackboard.read(engagement=engagement_slug, kinds=["result"])
    matching_result = None
    for r in results:
        if r.parent_id == matching_action.id:
            matching_result = r
            break
    if matching_result is None:
        return LeafOutcome(resolved=False)

    success = bool(matching_result.payload.get("success", False))

    # find finding under the result (if any)
    finding_event_id: int | None = None
    if success:
        for f in blackboard.read(engagement=engagement_slug, kinds=["finding"]):
            if f.parent_id == matching_result.id:
                finding_event_id = f.id
                break

    elapsed_ms = float(matching_result.payload.get("elapsed_ms", 0.0))
    return LeafOutcome(
        resolved=True,
        success=success,
        finding_event_id=finding_event_id,
        refute_reason=matching_result.payload.get("note", "") if not success else "",
        requests=1,
        seconds=elapsed_ms / 1000.0,
    )
