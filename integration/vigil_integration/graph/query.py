"""
graph.query — retrieval-only, non-authoritative reads over the projected graph (VIGIL-FUSION F4, slice 1).

redamon's ``query_prior_chains`` is the cross-session learning primitive: it surfaces a prior
engagement's high/critical findings AND its failure lessons so the next run starts warm. VIGIL keeps
that value but binds it to the sovereign rule that **no consumer may read authority from the graph**:

  * Every result is stamped ``authoritative = False`` / ``retrieval_only = True``. It is *context* for
    the reasoning core, never a grant. Any ACTION it suggests still clears WARDEN + the conjunctive
    gate + the egress gate — being in a prior chain authorizes nothing.
  * A ``PriorChainContext.confirmed_findings`` list can only ever contain CONFIRMED nodes (it is built
    from ``GraphView.confirmed_findings``); a lead is physically unable to appear there. Leads are
    surfaced, if at all, in a SEPARATE ``leads`` field that is explicitly labelled unproven.
  * Only ACTIVE (non-retired) nodes are returned — a refuted lead is excluded.

Import-clean: pydantic + .model + stdlib only.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from .model import EdgeType, GraphView, NodeLabel

_HIGH_SEVERITIES = frozenset({"high", "critical"})


class FindingSummary(BaseModel):
    ref: str
    title: str = ""
    severity: str = ""
    bug_class: str = ""
    evidence_ref: str = ""      # present ⇔ confirmed (the signed proof)
    spine_hash: str = ""


class FailureLesson(BaseModel):
    lesson: str
    tool: str = ""
    reason: str = ""
    spine_hash: str = ""


class PriorChainContext(BaseModel):
    """Cross-session retrieval context. **Non-authoritative and FROZEN** — the model is immutable
    (``frozen=True``), so a consumer cannot flip ``authoritative``/``retrieval_only`` to fabricate a
    grant. Nothing here grants a tier, promotes a finding, or widens scope; any action it suggests
    still clears WARDEN + the conjunctive gate + the egress gate."""

    model_config = ConfigDict(frozen=True)

    authoritative: bool = False
    retrieval_only: bool = True
    engagement_id: str = ""
    confirmed_findings: list[FindingSummary] = Field(default_factory=list)   # CONFIRMED only, ever
    leads: list[FindingSummary] = Field(default_factory=list)                # unproven, clearly separated
    failure_lessons: list[FailureLesson] = Field(default_factory=list)


def _node_target(node_props: dict[str, Any]) -> str:
    for k in ("target", "host", "target_host", "url", "domain"):
        v = node_props.get(k)
        if isinstance(v, str) and v:
            return v
    return ""


def _summary(node) -> FindingSummary:
    p = node.props
    return FindingSummary(
        ref=str(p.get("ref") or p.get("finding_ref") or node.id),
        title=str(p.get("title") or ""),
        severity=str(p.get("severity") or ""),
        bug_class=str(p.get("bug_class") or ""),
        evidence_ref=node.provenance.evidence_ref,
        spine_hash=node.provenance.spine_hash,
    )


def query_prior_chains(view: GraphView, *, target: Optional[str] = None,
                       high_only: bool = False, limit: int = 5) -> PriorChainContext:
    """Retrieve prior CONFIRMED findings + failure lessons as non-authoritative context. Optionally
    filter to a ``target`` host and to high/critical severities. Confirmed findings and leads are
    returned in SEPARATE fields — a lead can never masquerade as a confirmed finding."""
    if not isinstance(view, GraphView):
        return PriorChainContext()
    lim = max(0, int(limit)) if isinstance(limit, int) else 5

    def _match(node) -> bool:
        if target is not None and _node_target(node.props) != target:
            return False
        if high_only and str(node.props.get("severity", "")).lower() not in _HIGH_SEVERITIES:
            return False
        return True

    confirmed = [_summary(n) for n in view.confirmed_findings() if _match(n)][:lim]
    leads = [_summary(n) for n in view.lead_findings() if _match(n)][:lim]
    lessons: list[FailureLesson] = []
    for n in view.active_nodes(NodeLabel.CHAIN_FAILURE):
        lesson = str(n.props.get("lesson_learned") or n.props.get("lesson") or "").strip()
        if lesson:
            lessons.append(FailureLesson(lesson=lesson, tool=str(n.props.get("tool") or ""),
                                         reason=str(n.props.get("reason") or ""),
                                         spine_hash=n.provenance.spine_hash))
    return PriorChainContext(authoritative=False, retrieval_only=True, engagement_id=view.group_id,
                             confirmed_findings=confirmed, leads=leads, failure_lessons=lessons[:lim])


def successful_tools(view: GraphView) -> list[str]:
    """Tools whose step PRODUCED a CONFIRMED finding — a retrieval hint for the reasoning core (a
    suggestion, never a grant). Deterministic (sorted). Only confirmed findings count."""
    if not isinstance(view, GraphView):
        return []
    confirmed_ids = {n.id for n in view.confirmed_findings()}
    step_ids = {e.src for e in view.edges if e.is_active and e.type == EdgeType.PRODUCED
                and e.dst in confirmed_ids}
    tools: set[str] = set()
    for sid in step_ids:
        node = view.get(sid)
        if node is not None:
            tool = node.props.get("tool") or node.props.get("tool_name")
            if isinstance(tool, str) and tool:
                tools.add(tool)
    return sorted(tools)
