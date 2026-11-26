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
from .projector import NO_RETEST

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


# ==========================================================================================================
# F4 slice S4 — remediation/retest lifecycle retrieval (non-authoritative, INERT). The ONE traversal
# finding→remediation→retest, surfaced as retrieval context only — it grants nothing and promotes nothing.
# ==========================================================================================================
class RetestSummary(BaseModel):
    seq: int = 0
    status: str = ""          # verified_fixed / still_vulnerable / inconclusive / refused / unverified / rolled_back
    state: str = ""           # the RE-VERIFIED 4-state verdict (empty when the tick did not re-verify)
    label: str = ""           # the drift label (proven-fixed / still-proven / regressed / present / …)
    verified: bool = False


class RemediationSummary(BaseModel):
    remediation_id: str = ""
    finding_ref: str = ""                 # the finding it is confirmed-linked to (REMEDIATED_BY); "" ⇒ fail-closed
    verdict: str = ""
    bug_class: str = ""
    original_finding_cert_digest: str = ""
    retests: list[RetestSummary] = Field(default_factory=list)
    current_status: str = NO_RETEST       # latest retest status, or NO_RETEST — distinguishes a remediation
                                          # WITHOUT a retest from one with a passing (verified_fixed) retest.


class LifecycleContext(BaseModel):
    """The projected finding→remediation→retest lifecycle as NON-AUTHORITATIVE retrieval context. FROZEN +
    ``authoritative=False`` — like ``PriorChainContext`` it grants nothing; the remediation/retest nodes it
    reflects are INERT (never FACT findings). A remediation with no retest is distinguishable from one with a
    passing retest via ``current_status`` (``no_retest`` vs ``verified_fixed``)."""

    model_config = ConfigDict(frozen=True)

    authoritative: bool = False
    retrieval_only: bool = True
    engagement_id: str = ""
    remediations: list[RemediationSummary] = Field(default_factory=list)


def lifecycle_chains(view: GraphView) -> LifecycleContext:
    """Traverse the projected lifecycle in ONE pass: every active REMEDIATION node, the finding it is
    confirmed-linked to (``Finding -[REMEDIATED_BY]-> Remediation``), and its re-verified retests
    (``Remediation -[RETESTED_BY]-> Retest``). Deterministic (remediations + retests sorted). Returns only
    non-authoritative context — a lead/opinion can never appear as a fact here, and nothing is promoted."""
    if not isinstance(view, GraphView):
        return LifecycleContext()
    # map each remediation node id → the finding it is linked to (active REMEDIATED_BY edge).
    linked_finding: dict[str, str] = {}
    for e in view.edges:
        if e.is_active and e.type == EdgeType.REMEDIATED_BY and e.src.startswith("finding:"):
            linked_finding[e.dst] = e.src[len("finding:"):]
    rems: list[RemediationSummary] = []
    for node in view.active_nodes(NodeLabel.REMEDIATION):
        retests: list[RetestSummary] = []
        for e in view.edges:
            if not (e.is_active and e.type == EdgeType.RETESTED_BY and e.src == node.id):
                continue
            rt = view.get(e.dst)
            if rt is None or not rt.is_active:
                continue
            p = rt.props
            retests.append(RetestSummary(
                seq=int(p.get("seq") or 0), status=str(p.get("status") or ""),
                state=str(p.get("state") or ""), label=str(p.get("label") or ""),
                verified=bool(p.get("verified"))))
        retests.sort(key=lambda r: r.seq)
        rems.append(RemediationSummary(
            remediation_id=str(node.props.get("remediation_id") or node.id),
            finding_ref=linked_finding.get(node.id, ""),
            verdict=str(node.props.get("verdict") or ""),
            bug_class=str(node.props.get("bug_class") or ""),
            original_finding_cert_digest=str(node.props.get("original_finding_cert_digest") or ""),
            retests=retests,
            current_status=(retests[-1].status if retests else NO_RETEST)))
    rems.sort(key=lambda r: r.remediation_id)
    return LifecycleContext(authoritative=False, retrieval_only=True, engagement_id=view.group_id,
                            remediations=rems)


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
