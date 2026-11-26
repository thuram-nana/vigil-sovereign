"""
graph.coverage — a NON-AUTHORITATIVE, honesty-preserving coverage rollup over the projected graph
(VIGIL-FUSION F4, slice S5; default-OFF behind ``VIGIL_COVERAGE_VIEW``).

``coverage(view)`` rolls the combined read-model (S3 objectives + REACHES/PURSUES, S2's JOIN-verified
confirmed/lead split, S4's remediation/retest lifecycle, and S5's ``TESTED`` coverage edges) into a compact
answer to "what did we cover, and — scrupulously — what did we NOT?". It is a CONSUMER, never a producer:

  * It GRANTS nothing and AUTHORIZES nothing. Every result is stamped ``authoritative=False`` /
    ``retrieval_only=True`` and the model is FROZEN, so a consumer cannot flip those flags to fabricate a
    grant. A coverage claim must never become an input that relaxes a gate.
  * "Nothing found" is NEVER reported as CLEAN/safe. An asset with no finding is ``not_tested`` — silence —
    UNLESS a RETAINED benign/negative RESPONSE record exists for it, in which case ``tested_no_finding``.
    Absence-of-edge is not proof-of-absence; a REACHED surface is not a COMPLETE surface (``SCOPE_NOTE``).
  * It trusts only JOIN-verified (S2) confirmed facts and authenticated-lifecycle (S4) nodes — it never
    re-confirms from unproven input. A LEAD is never a fact: a lead finding is surfaced under
    ``leads_unverified``, never ``findings_confirmed``; an unverified remediation never reads
    ``verified_fixed``.
  * It counts only ACTIVE (non-retired) nodes/edges (bi-temporal honoured — a refuted lead drops), and it is
    a PURE function of the view: same view → byte-identical, SORTED coverage JSON (no wallclock / RNG).
  * Every label in the export passes the SAME F3 redactor the Neo4j export path runs on node props
    (``vigil_integration.tools.redact_tool_args``) — no host/credential/token can ride a label or a count.

Import-clean: pydantic + stdlib + ``.model`` / ``.projector`` status constants; the F3 redactor is imported
LAZILY (function-local) so this module's scope stays light and framework-free.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .coverage_flag import COVERAGE_ENV, coverage_view_enabled
from .model import EdgeType, GraphView, NodeLabel
from .projector import (
    NO_RETEST,
    _STATUS_INCONCLUSIVE,
    _STATUS_STILL_VULNERABLE,
    _STATUS_VERIFIED_FIXED,
)

# -- per-asset coverage STATE (independent of any finding VERDICT) ----------------------------------------
NOT_TESTED = "not_tested"              # silence — no test edge, no retained benign record (never CLEAN)
TESTED = "tested"                      # a test was exercised against the asset (edge present, or a finding)
TESTED_NO_FINDING = "tested_no_finding"  # a RETAINED benign/negative response record AND no finding

# -- per-finding remediation presence + retest verdict (derived ONLY from JOIN/S4-verified nodes) ---------
REMEDIATION_PRESENT = "present"
REMEDIATION_ABSENT = "absent"
RETEST_VERIFIED_FIXED = "verified_fixed"
RETEST_STILL_VULNERABLE = "still_vulnerable"
RETEST_INCONCLUSIVE = "inconclusive"
RETEST_NONE = "none"                   # no JOIN-linked remediation, or a linked remediation with no retest

# The recon/bridge asset labels — the surfaces a finding AFFECTS, a path REACHES, a step TESTED.
_ASSET_LABELS = frozenset({
    NodeLabel.HOST, NodeLabel.ENDPOINT, NodeLabel.PORT, NodeLabel.CVE, NodeLabel.TECHNOLOGY,
})
# The edge types by which a finding AFFECTS an asset (the finding→recon bridges).
_AFFECTS_EDGES = frozenset({
    EdgeType.FINDING_RELATES_CVE, EdgeType.FINDING_AFFECTS_ENDPOINT, EdgeType.FINDING_AFFECTS_PORT,
    EdgeType.FINDING_AFFECTS_TECH, EdgeType.FOUND_ON,
})

# A measured scope note, repeated on every export. NOT a completeness guarantee (D13): coverage is measured
# counts + honest states, never "fully protected / complete coverage / all threats blocked".
SCOPE_NOTE = ("non-authoritative measured coverage; absence-of-edge is not proof-of-absence and a reached "
              "surface is not a complete surface; silence reads as not_tested, never as safe")


def _redact(label: str) -> str:
    """Pass one export LABEL through the SAME F3 redactor the Neo4j export path runs on node props
    (``tools.redact_tool_args``) — a host-userinfo / Bearer / secret-kv inside a label is masked before it can
    leave as a coverage label. Non-secret labels pass through unchanged (so joins/ids are stable). Imported
    lazily to keep this module's scope light; fail-open to the raw string only if the redactor is unavailable
    would LEAK, so it fails CLOSED to a masked marker instead."""
    from ..tools import redact_tool_args   # noqa: PLC0415 — lazy: keep module scope light + framework-free
    try:
        return str(redact_tool_args({"_": str(label)}).get("_", ""))
    except Exception:          # noqa: BLE001 — a redactor error must never leak the raw label
        return "<redacted>"


class GoalCoverage(BaseModel):
    """Per-Goal coverage. ``actions_pursuing`` is the count of ACTIVE ChainSteps that PURSUE the Goal;
    ``confirmed_finding_reaches`` is True iff some CONFIRMED (JOIN-verified) finding AFFECTS an asset that
    REACHES this Goal. A Goal with ZERO actions is ``uncovered`` — surfaced, never hidden. A Goal is inert:
    this grants nothing."""

    model_config = ConfigDict(frozen=True)

    goal_id: str
    title: str = ""
    actions_pursuing: int = 0
    confirmed_finding_reaches: bool = False
    uncovered: bool = True


class AssetCoverage(BaseModel):
    """Per-asset coverage. ``coverage_state`` (``not_tested`` / ``tested`` / ``tested_no_finding``) is
    INDEPENDENT of any finding verdict — it reflects test evidence only. CONFIRMED and LEAD findings that
    AFFECT the asset are counted SEPARATELY. ``not_tested`` is silence (never CLEAN); ``tested_no_finding``
    REQUIRES a retained benign/negative response record."""

    model_config = ConfigDict(frozen=True)

    asset_id: str
    label: str = ""
    coverage_state: str = NOT_TESTED
    confirmed_findings: int = 0
    lead_findings: int = 0
    reaches_goals: list[str] = Field(default_factory=list)


class FindingCoverage(BaseModel):
    """Per-finding coverage. ``remediation`` (present/absent) is derived ONLY from a JOIN-verified
    ``Finding -[REMEDIATED_BY]-> Remediation`` edge (the projector draws it only when the finding cert
    re-verified); ``retest`` is the latest AUTHENTICATED (S4) retest verdict — ``verified_fixed`` only on a
    genuine authenticated REMEDIATED tick, never on an unverified/rolled-back one."""

    model_config = ConfigDict(frozen=True)

    finding_ref: str
    severity: str = ""
    remediation: str = REMEDIATION_ABSENT
    retest: str = RETEST_NONE


class CoverageView(BaseModel):
    """The coverage rollup — NON-AUTHORITATIVE and FROZEN. ``authoritative=False`` / ``retrieval_only=True``
    (a consumer cannot flip them). ``findings_confirmed`` holds ONLY JOIN-verified facts; a LEAD is under
    ``leads_unverified``. Everything is SORTED so the dump is byte-deterministic for a fixed view."""

    model_config = ConfigDict(frozen=True)

    authoritative: bool = False
    retrieval_only: bool = True
    engagement_id: str = ""
    goals: list[GoalCoverage] = Field(default_factory=list)
    assets: list[AssetCoverage] = Field(default_factory=list)
    findings_confirmed: list[FindingCoverage] = Field(default_factory=list)
    leads_unverified: list[FindingCoverage] = Field(default_factory=list)
    scope_note: str = SCOPE_NOTE


def _finding_severity(node) -> str:
    return str(node.props.get("severity") or "")


def _latest_retest_status(view: GraphView, remediation_id: str) -> str:
    """The latest ACTIVE retest status for a remediation node (``Remediation -[RETESTED_BY]-> Retest``),
    ordered by the tick seq. ``NO_RETEST`` when the remediation has no active retest. The projector already
    capped an unauthenticated/rolled-back series to ``rolled_back`` (never ``verified_fixed``), so this reads
    only what the attestation-log authority vouched for."""
    best_seq = -1
    best_status = NO_RETEST
    for e in view.edges:
        if not (e.is_active and e.type == EdgeType.RETESTED_BY and e.src == remediation_id):
            continue
        rt = view.get(e.dst)
        if rt is None or not rt.is_active:
            continue
        seq = int(rt.props.get("seq") or 0)
        if seq >= best_seq:
            best_seq = seq
            best_status = str(rt.props.get("status") or NO_RETEST)
    return best_status


def _retest_verdict(status: str) -> str:
    """Map a projected retest status to the honest coverage verdict. ``verified_fixed`` ONLY from a genuine
    authenticated REMEDIATED tick; ``still_vulnerable`` stays itself; EVERYTHING else that is not a pass —
    ``inconclusive`` / ``rolled_back`` / ``unverified`` / ``refused`` — reads ``inconclusive`` (we cannot
    conclude fixed), and no retest reads ``none``. An unverified remediation thus NEVER shows verified_fixed."""
    if status == _STATUS_VERIFIED_FIXED:
        return RETEST_VERIFIED_FIXED
    if status == _STATUS_STILL_VULNERABLE:
        return RETEST_STILL_VULNERABLE
    if status == NO_RETEST:
        return RETEST_NONE
    # inconclusive / rolled_back / unverified / refused / anything unknown → cannot conclude "fixed"
    return RETEST_INCONCLUSIVE


def _finding_coverage(view: GraphView, finding_node, remediated_by: dict[str, list[str]]) -> FindingCoverage:
    """Coverage for ONE finding: remediation present iff a JOIN-verified ``REMEDIATED_BY`` edge links it to a
    remediation; retest from the latest AUTHENTICATED retest on that remediation. Derived ONLY from
    JOIN/S4-verified nodes — an UNLINKED remediation (its finding cert did not re-verify) is never attributed,
    so it can never surface a ``verified_fixed`` for the finding."""
    fid = finding_node.id
    rem_ids = remediated_by.get(fid, [])
    if not rem_ids:
        return FindingCoverage(finding_ref=_redact(str(finding_node.props.get("ref") or fid)),
                               severity=_redact(_finding_severity(finding_node)),
                               remediation=REMEDIATION_ABSENT, retest=RETEST_NONE)
    # present: aggregate the retest verdict across the finding's linked remediations FAILING TOWARD NOT-SAFE.
    # A finding legitimately owns >1 ``REMEDIATED_BY`` edge (``_project_remediation`` draws one per re-verified
    # remediation record for the same finding_ref — attempt 1 may claim fixed, attempt 2's retest may PROVE
    # still-vulnerable). An authenticated STILL_VULNERABLE (or an INCONCLUSIVE) retest is proof the finding is
    # not safely fixed and MUST DOMINATE an optimistic verified_fixed — never the reverse. So a finding reads
    # ``verified_fixed`` ONLY when NO linked remediation is still_vulnerable or inconclusive; a single
    # authenticated still_vulnerable can never be masked by another remediation's "fixed."
    verdicts = [_retest_verdict(_latest_retest_status(view, rid)) for rid in rem_ids]
    if RETEST_STILL_VULNERABLE in verdicts:
        retest = RETEST_STILL_VULNERABLE
    elif RETEST_INCONCLUSIVE in verdicts:
        retest = RETEST_INCONCLUSIVE
    elif RETEST_VERIFIED_FIXED in verdicts:
        retest = RETEST_VERIFIED_FIXED
    else:
        retest = RETEST_NONE
    return FindingCoverage(finding_ref=_redact(str(finding_node.props.get("ref") or fid)),
                           severity=_redact(_finding_severity(finding_node)),
                           remediation=REMEDIATION_PRESENT, retest=retest)


def coverage(view: GraphView) -> CoverageView:
    """Roll the projected graph up into a NON-AUTHORITATIVE coverage view. Total on a non-view (returns the
    empty, fail-closed-honest view). Pure + deterministic: same view → byte-identical sorted output, no
    wallclock/RNG. Counts only ACTIVE nodes/edges; trusts only JOIN-verified facts; reports silence as
    ``not_tested``, never CLEAN. Every label passes the F3 redactor before it leaves."""
    if not isinstance(view, GraphView):
        return CoverageView()

    confirmed_ids = {n.id for n in view.confirmed_findings()}       # S2 JOIN-verified facts only
    lead_nodes = view.lead_findings()                              # active leads (incl. S2-demoted facts)
    lead_ids = {n.id for n in lead_nodes}

    # finding → assets it AFFECTS (active bridge edges); and per asset, the confirmed/lead finding counts.
    asset_confirmed: dict[str, int] = {}
    asset_lead: dict[str, int] = {}
    confirmed_affected_assets: set[str] = set()
    for e in view.edges:
        if not (e.is_active and e.type in _AFFECTS_EDGES):
            continue
        if e.src in confirmed_ids:
            asset_confirmed[e.dst] = asset_confirmed.get(e.dst, 0) + 1
            confirmed_affected_assets.add(e.dst)
        elif e.src in lead_ids:
            asset_lead[e.dst] = asset_lead.get(e.dst, 0) + 1

    # asset → goals it REACHES (active edges, active endpoints); goal → whether a confirmed finding reaches it.
    asset_reaches: dict[str, set[str]] = {}
    goal_reached_by_confirmed: dict[str, bool] = {}
    for e in view.edges:
        if not (e.is_active and e.type == EdgeType.REACHES):
            continue
        asset = view.get(e.src)
        goal = view.get(e.dst)
        if asset is None or not asset.is_active or goal is None or not goal.is_active:
            continue
        asset_reaches.setdefault(e.src, set()).add(e.dst)
        if e.src in confirmed_affected_assets:
            goal_reached_by_confirmed[e.dst] = True

    # goal → count of DISTINCT active ChainSteps that PURSUE it.
    goal_actions: dict[str, set[str]] = {}
    for e in view.edges:
        if not (e.is_active and e.type == EdgeType.PURSUES):
            continue
        step = view.get(e.src)
        if step is not None and not step.is_active:   # a retired step does not count (bi-temporal)
            continue
        goal_actions.setdefault(e.dst, set()).add(e.src)

    # asset → test evidence: has an active TESTED edge; has a RETAINED benign/negative response record.
    asset_tested: dict[str, bool] = {}
    asset_benign: dict[str, bool] = {}
    for e in view.edges:
        if not (e.is_active and e.type == EdgeType.TESTED):
            continue
        asset = view.get(e.dst)
        if asset is None or not asset.is_active:
            continue
        asset_tested[e.dst] = True
        if bool(e.props.get("benign_record")):
            asset_benign[e.dst] = True

    # ---- Goals (sorted by id). A Goal with zero pursuing actions is surfaced as uncovered. ----
    goals: list[GoalCoverage] = []
    for n in sorted(view.active_nodes(NodeLabel.OBJECTIVE), key=lambda n: n.id):
        gid = n.id.split(":", 1)[1] if ":" in n.id else n.id
        n_actions = len(goal_actions.get(n.id, set()))
        goals.append(GoalCoverage(
            goal_id=_redact(gid),
            title=_redact(str(n.props.get("title") or n.props.get("objective") or
                              n.props.get("name") or n.props.get("description") or "")),
            actions_pursuing=n_actions,
            confirmed_finding_reaches=goal_reached_by_confirmed.get(n.id, False),
            uncovered=(n_actions == 0)))

    # ---- Assets (sorted by id). State is independent of the finding verdict; silence stays not_tested. ----
    assets: list[AssetCoverage] = []
    for n in sorted((x for x in view.active_nodes() if x.label in _ASSET_LABELS), key=lambda n: n.id):
        c_count = asset_confirmed.get(n.id, 0)
        l_count = asset_lead.get(n.id, 0)
        affects = (c_count + l_count) > 0
        if affects:
            state = TESTED                                   # a finding proves the asset was exercised
        elif asset_benign.get(n.id):
            state = TESTED_NO_FINDING                        # retained benign/negative record, no finding
        elif asset_tested.get(n.id):
            state = TESTED                                   # a test ran, no retained negative proof, no finding
        else:
            state = NOT_TESTED                               # silence — NEVER reported as CLEAN
        assets.append(AssetCoverage(
            asset_id=_redact(n.id), label=_redact(n.label.value), coverage_state=state,
            confirmed_findings=c_count, lead_findings=l_count,
            reaches_goals=sorted(_redact(g) for g in asset_reaches.get(n.id, set()))))

    # ---- Findings: confirmed (JOIN-verified facts) vs leads_unverified — the lead/fact split carries in. ----
    remediated_by: dict[str, list[str]] = {}
    for e in view.edges:
        if e.is_active and e.type == EdgeType.REMEDIATED_BY:
            rem = view.get(e.dst)
            if rem is not None and rem.is_active:
                remediated_by.setdefault(e.src, []).append(e.dst)

    confirmed_cov = [
        _finding_coverage(view, n, remediated_by)
        for n in sorted(view.confirmed_findings(), key=lambda n: n.id)
    ]
    leads_cov = [
        _finding_coverage(view, n, remediated_by)
        for n in sorted(lead_nodes, key=lambda n: n.id)
    ]

    return CoverageView(
        authoritative=False, retrieval_only=True, engagement_id=view.group_id,
        goals=goals, assets=assets, findings_confirmed=confirmed_cov, leads_unverified=leads_cov,
        scope_note=SCOPE_NOTE)


__all__ = [
    "COVERAGE_ENV", "coverage_view_enabled",
    "NOT_TESTED", "TESTED", "TESTED_NO_FINDING",
    "REMEDIATION_PRESENT", "REMEDIATION_ABSENT",
    "RETEST_VERIFIED_FIXED", "RETEST_STILL_VULNERABLE", "RETEST_INCONCLUSIVE", "RETEST_NONE",
    "SCOPE_NOTE",
    "GoalCoverage", "AssetCoverage", "FindingCoverage", "CoverageView", "coverage",
]
