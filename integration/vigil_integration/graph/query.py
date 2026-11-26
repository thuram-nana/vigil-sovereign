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

**S2 — JOIN-verified CONFIRMED at this boundary.** The projector (``graph.projector``) is the single
enforcement point for the evidence join (``VIGIL_GRAPH_EVIDENCE_JOIN``): under the flag a CONFIRMED node
has already had its ``evidence_ref`` dereferenced + RE-VERIFIED (via the S1 resolver's reuse of
``verify_certificate``) and bound to its finding/engagement/host-in-scope. So ``confirmed_findings()`` here
returns ONLY join-verified facts WITHOUT re-running (or duplicating) any verification — this layer never
mints a second verifier; it reads the already-tightened view. A fact the join could not re-establish was
demoted UPSTREAM to a lead carrying ``props["evidence_join"] == "unresolved_evidence"``, so it appears only
in the separate ``leads`` field, surfaced via ``FindingSummary.unresolved_reason`` (never as a fact).

Import-clean: pydantic + .model + stdlib only.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, model_serializer

from .model import EVIDENCE_JOIN_UNRESOLVED, EdgeType, GraphView, NodeLabel, _join_unresolved

_HIGH_SEVERITIES = frozenset({"high", "critical"})


class FindingSummary(BaseModel):
    ref: str
    title: str = ""
    severity: str = ""
    bug_class: str = ""
    evidence_ref: str = ""      # present ⇔ confirmed (the signed proof)
    spine_hash: str = ""
    # S2: for a lead the projector DEMOTED because the evidence join failed, WHY ("unresolved_evidence").
    # Dropped from the canonical form when empty (serializer below) so a confirmed finding — and every
    # pre-S2 / flag-OFF summary — serialises BYTE-IDENTICALLY to before this field existed.
    unresolved_reason: str = ""

    @model_serializer(mode="wrap")
    def _ser(self, handler):
        data = handler(self)
        if not data.get("unresolved_reason"):
            data.pop("unresolved_reason", None)
        return data


class FailureLesson(BaseModel):
    lesson: str
    tool: str = ""
    reason: str = ""
    spine_hash: str = ""


class ObjectiveSummary(BaseModel):
    """A projected charter objective (S3). It carries NO ``evidence_ref`` and no confirmation: a Goal is
    an inert read-model node, never a FACT. ``objective_id`` is the node's stable key (``objective:<id>``);
    ``title`` is a best-effort label from the Goal's props (presented through the F3 redactor before any
    export). This summary grants nothing — it is retrieval context only."""

    objective_id: str
    title: str = ""
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


class ObjectiveContext(BaseModel):
    """Retrieval context listing the projected charter objectives (S3). **Non-authoritative and FROZEN**,
    exactly like ``PriorChainContext``: surfacing a Goal grants nothing. A Goal is inert — it is never a
    finding, never confirmed, and its presence here never authorizes a tier, promotes a finding, or widens
    scope; any action it suggests still clears WARDEN + the conjunctive gate + the egress gate."""

    model_config = ConfigDict(frozen=True)

    authoritative: bool = False
    retrieval_only: bool = True
    engagement_id: str = ""
    objectives: list[ObjectiveSummary] = Field(default_factory=list)


def _node_target(node_props: dict[str, Any]) -> str:
    for k in ("target", "host", "target_host", "url", "domain"):
        v = node_props.get(k)
        if isinstance(v, str) and v:
            return v
    return ""


def _summary(node) -> FindingSummary:
    p = node.props
    # S2: a finding the join DEMOTED is intrinsically confirmed but surfaces as a lead — it carries NO
    # proof (its evidence_ref did not re-establish), so the summary blanks evidence_ref and names the
    # reason. A join-CONFIRMED node (tag == "confirmed") is a normal fact: no unresolved_reason.
    demoted = _join_unresolved(node)
    return FindingSummary(
        ref=str(p.get("ref") or p.get("finding_ref") or node.id),
        title=str(p.get("title") or ""),
        severity=str(p.get("severity") or ""),
        bug_class=str(p.get("bug_class") or ""),
        evidence_ref="" if demoted else node.provenance.evidence_ref,
        spine_hash=node.provenance.spine_hash,
        unresolved_reason=EVIDENCE_JOIN_UNRESOLVED if demoted else "",
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


def _objective_title(props: dict[str, Any]) -> str:
    for k in ("title", "objective", "name", "description", "label"):
        v = props.get(k)
        if isinstance(v, str) and v:
            return v
    return ""


def objectives(view: GraphView) -> ObjectiveContext:
    """Surface the projected charter objectives (S3) as NON-AUTHORITATIVE, frozen retrieval context — the
    "read surfacing a Goal" that proves a Goal authorizes nothing. Only ACTIVE (non-retired) OBJECTIVE
    nodes are returned, deterministically ordered by node id. A Goal is inert: it carries no evidence_ref,
    is never a finding, and nothing here grants a tier or promotes anything. Total on a non-view."""
    if not isinstance(view, GraphView):
        return ObjectiveContext()
    rows = [
        ObjectiveSummary(objective_id=n.id.split(":", 1)[1] if ":" in n.id else n.id,
                         title=_objective_title(n.props), spine_hash=n.provenance.spine_hash)
        for n in sorted(view.active_nodes(NodeLabel.OBJECTIVE), key=lambda n: n.id)
    ]
    return ObjectiveContext(authoritative=False, retrieval_only=True,
                            engagement_id=view.group_id, objectives=rows)
