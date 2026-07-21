"""
remediation.triage — the deterministic triage half of CypherFix, re-plumbed sovereign (VIGIL-FUSION F10).

redamon's TriageOrchestrator is hybrid: Phase-1 ``_collect_all`` runs 9 hardcoded Cypher queries against a
Neo4j attack-graph at ZERO LLM cost (ground truth), then Phase-2 lets an LLM correlate/dedup/prioritize
into a ``RemediationDraft`` of ``TriageFinding`` objects that are POSTed to ``/api/remediations/batch``.

VIGIL keeps the deterministic Phase-1 verbatim in spirit — **9 fixed queries over the F4 graph read-model**
(``vigil_integration.graph``) — but binds the whole stage to the sovereign rule:

  * The 9 queries run over the PROJECTED ``GraphView`` (the signed-spine read-model), not raw Cypher —
    deterministic, oracle-friendly, zero LLM cost. The live Neo4j backend is the deferred slice.
  * **A ``TriageFinding`` may spawn a remediation ONLY if it is an oracle-confirmed FACT** — a graph
    CONFIRMED node carrying a signed ``evidence_ref``. A LEAD can NEVER trigger a codefix. This is
    enforced twice: at the TYPE level (``TriageFinding._confirmed_needs_evidence`` refuses a confirmed
    finding with no signed ref, closing the deserialization path) and at the spawn boundary
    (``may_remediate`` / ``spawn_remediation`` refuse a lead fail-closed).
  * The LLM's correlate/dedup/prioritize output would be a PROPOSAL the gate re-ranks; here the
    deterministic collection + severity prioritization is what ``run_triage`` performs — nothing an LLM
    asserts is trusted, and confirmed findings and unproven leads live in SEPARATE fields so a lead can
    never masquerade as a fact.
  * Deterministic ordering, no wallclock / RNG: dedup + prioritization sort on (severity, exploit
    signals, chain depth, ref) so the same graph yields a byte-identical draft.

Total on malformed input: a non-``GraphView``, a torn node, or a garbage prop degrades to "no signal"
(an empty / smaller draft), never a raise.

Import-clean: pydantic + stdlib + the F4 graph read-model only (no ``framework.*``/``strix.*``/network).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Callable

from pydantic import BaseModel, Field, model_validator

from ..graph import EdgeType, GraphNode, GraphView

# --- deterministic severity ranking ------------------------------------------------------------

_SEVERITY_RANK: dict[str, int] = {
    "critical": 4, "high": 3, "medium": 2, "moderate": 2, "low": 1, "info": 0, "informational": 0,
}


def severity_rank(severity: Any) -> int:
    """Deterministic severity → rank (critical=4 … info=0). An unknown/blank severity ranks -1 so it
    sorts LAST but stably (never crashes on a non-string prop)."""
    return _SEVERITY_RANK.get(str(severity or "").strip().lower(), -1)


def _node_target(props: dict[str, Any]) -> str:
    for k in ("target", "host", "target_host", "url", "domain"):
        v = props.get(k)
        if isinstance(v, str) and v:
            return v
    return ""


def _str_list(v: Any) -> list[str]:
    return [str(x) for x in v if isinstance(x, (str, int))] if isinstance(v, list) else []


# --- the triage finding + draft ----------------------------------------------------------------


class TriageFinding(BaseModel):
    """One ranked candidate for remediation. ``confirmed`` is the veracity flag: it is set True ONLY
    from a graph CONFIRMED finding node (an oracle-signed FACT) and REQUIRES a non-empty signed
    ``evidence_ref`` — the same invariant the F2 ``Finding`` carries. Every other field (severity, cvss,
    exploit signals, attack chain) is context derived from the node props; it is non-authoritative."""

    ref: str
    title: str = ""
    bug_class: str = ""              # remediation_type / category
    severity: str = ""
    target: str = ""
    confirmed: bool = False          # True ⇔ oracle-confirmed FACT (may spawn a remediation)
    evidence_ref: str = ""           # signed proof; REQUIRED when confirmed
    spine_hash: str = ""
    attack_chain_path: list[str] = Field(default_factory=list)
    cve_ids: list[str] = Field(default_factory=list)
    exploit_available: bool = False
    cisa_kev: bool = False
    target_repo: str = ""
    target_branch: str = ""
    priority: int = 0                # deterministic rank position (1 = highest); 0 until ranked

    @model_validator(mode="after")
    def _confirmed_needs_evidence(self) -> "TriageFinding":
        """Type-level enforcement of the sovereign rule: a CONFIRMED triage finding MUST carry a
        non-whitespace signed evidence reference. Refuses ``TriageFinding(confirmed=True,
        evidence_ref="")`` so a replayed/untrusted record can never construct an evidence-less
        'confirmed' finding that could spawn a codefix."""
        if self.confirmed and not (self.evidence_ref or "").strip():
            raise ValueError("a CONFIRMED triage finding requires a non-empty signed evidence reference")
        return self

    @property
    def may_spawn_remediation(self) -> bool:
        """The single predicate the codefix pipeline keys on: only an oracle-confirmed FACT with a
        signed evidence ref may spawn a remediation (a LEAD never can)."""
        return self.confirmed and bool((self.evidence_ref or "").strip())


class RemediationDraft(BaseModel):
    """The triage output. ``findings`` holds ONLY confirmed, deduped, severity-prioritized facts (each
    may spawn a remediation); ``leads`` surfaces unconfirmed proposals SEPARATELY and clearly labelled —
    a lead can never appear in ``findings`` (the anti-trust-laundering split, at the triage boundary)."""

    findings: list[TriageFinding] = Field(default_factory=list)   # CONFIRMED only, ever — ranked
    leads: list[TriageFinding] = Field(default_factory=list)      # unproven; never spawn a codefix
    summary: str = ""
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_type: dict[str, int] = Field(default_factory=dict)


# --- the 9 deterministic triage queries over the projected graph -------------------------------


def _confirmed_nodes(view: GraphView) -> list[GraphNode]:
    """The ground-truth set: active, oracle-CONFIRMED finding nodes, in deterministic id order."""
    return sorted(view.confirmed_findings(), key=lambda n: n.id)


def _finding_src_ids(view: GraphView, *edge_types: EdgeType) -> set[str]:
    return {e.src for e in view.edges if e.is_active and e.type in edge_types}


def _finding_dst_ids(view: GraphView, *edge_types: EdgeType) -> set[str]:
    return {e.dst for e in view.edges if e.is_active and e.type in edge_types}


def _q_all_confirmed(view: GraphView) -> list[GraphNode]:
    """Q1 — every oracle-confirmed finding (the completeness baseline)."""
    return _confirmed_nodes(view)


def _q_critical(view: GraphView) -> list[GraphNode]:
    """Q2 — confirmed findings at CRITICAL severity."""
    return [n for n in _confirmed_nodes(view) if severity_rank(n.props.get("severity")) >= 4]


def _q_high_or_critical(view: GraphView) -> list[GraphNode]:
    """Q3 — confirmed findings at HIGH or CRITICAL severity."""
    return [n for n in _confirmed_nodes(view) if severity_rank(n.props.get("severity")) >= 3]


def _q_kev_or_exploitable(view: GraphView) -> list[GraphNode]:
    """Q4 — confirmed findings flagged CISA-KEV or with a known public exploit (prioritization signal)."""
    return [n for n in _confirmed_nodes(view)
            if bool(n.props.get("cisa_kev")) or bool(n.props.get("exploit_available"))]


def _q_cve_correlated(view: GraphView) -> list[GraphNode]:
    """Q5 — confirmed findings correlated to a CVE bridge node."""
    ids = _finding_src_ids(view, EdgeType.FINDING_RELATES_CVE)
    return [n for n in _confirmed_nodes(view) if n.id in ids]


def _q_asset_affecting(view: GraphView) -> list[GraphNode]:
    """Q6 — confirmed findings affecting a concrete asset (endpoint / port / technology)."""
    ids = _finding_src_ids(view, EdgeType.FINDING_AFFECTS_ENDPOINT, EdgeType.FINDING_AFFECTS_PORT,
                           EdgeType.FINDING_AFFECTS_TECH, EdgeType.FOUND_ON)
    return [n for n in _confirmed_nodes(view) if n.id in ids]


def _q_attack_chain_member(view: GraphView) -> list[GraphNode]:
    """Q7 — confirmed findings that are the product of an attack-chain step (carry a graph-derived path)."""
    ids = _finding_dst_ids(view, EdgeType.PRODUCED, EdgeType.LED_TO)
    return [n for n in _confirmed_nodes(view) if n.id in ids]


def _q_duplicate_class(view: GraphView) -> list[GraphNode]:
    """Q8 — confirmed findings sharing a (bug_class, target) with another confirmed finding (dedup
    candidates the ranker collapses)."""
    groups: dict[tuple[str, str], list[GraphNode]] = defaultdict(list)
    for n in _confirmed_nodes(view):
        groups[(str(n.props.get("bug_class") or ""), _node_target(n.props))].append(n)
    out = [n for members in groups.values() if len(members) > 1 for n in members]
    return sorted(out, key=lambda n: n.id)


def _q_severity_prioritized(view: GraphView) -> list[GraphNode]:
    """Q9 — every confirmed finding, severity-ranked (the prioritization pass)."""
    return sorted(_confirmed_nodes(view), key=lambda n: (-severity_rank(n.props.get("severity")), n.id))


@dataclass(frozen=True)
class TriageQuery:
    """One deterministic triage query, mirroring redamon's ``{name, phase, description, query}`` shape —
    but ``fn`` is a pure Python function over the projected ``GraphView``, not a Cypher string."""

    name: str
    phase: str
    description: str
    fn: Callable[[GraphView], list[GraphNode]]


# The 9 FIXED queries — the zero-LLM-cost ground-truth collection phase (deterministic).
TRIAGE_QUERIES: tuple[TriageQuery, ...] = (
    TriageQuery("all_confirmed", "collect", "every oracle-confirmed finding", _q_all_confirmed),
    TriageQuery("critical", "collect", "confirmed findings at CRITICAL severity", _q_critical),
    TriageQuery("high_or_critical", "collect", "confirmed findings at HIGH+ severity", _q_high_or_critical),
    TriageQuery("kev_or_exploitable", "prioritize", "KEV / public-exploit findings", _q_kev_or_exploitable),
    TriageQuery("cve_correlated", "correlate", "findings correlated to a CVE", _q_cve_correlated),
    TriageQuery("asset_affecting", "correlate", "findings affecting a concrete asset", _q_asset_affecting),
    TriageQuery("attack_chain_member", "correlate", "findings on an attack chain", _q_attack_chain_member),
    TriageQuery("duplicate_class", "dedup", "duplicate (class,target) findings", _q_duplicate_class),
    TriageQuery("severity_prioritized", "prioritize", "all confirmed, severity-ranked", _q_severity_prioritized),
)
assert len(TRIAGE_QUERIES) == 9, "CypherFix triage runs exactly 9 deterministic queries"


# --- building + ranking the draft --------------------------------------------------------------


def _triage_finding_from_node(node: GraphNode) -> TriageFinding:
    """Build a ``TriageFinding`` from a graph node. Confirmation is NOT taken from anyone's word — it is
    re-derived from the node's oracle-signed provenance (``is_confirmed`` ⇒ CONFIRMED finding node) AND a
    non-empty signed ``evidence_ref``. A confirmed node that somehow lacks a signed ref degrades to a
    lead (fail-closed), so an evidence-less 'confirmed' finding can never reach the draft."""
    p = node.props if isinstance(node.props, dict) else {}
    ev = (node.provenance.evidence_ref or "").strip()
    confirmed = bool(node.is_confirmed) and bool(ev)
    return TriageFinding(
        ref=str(p.get("ref") or p.get("finding_ref") or node.id),
        title=str(p.get("title") or ""),
        bug_class=str(p.get("bug_class") or p.get("category") or ""),
        severity=str(p.get("severity") or ""),
        target=_node_target(p),
        confirmed=confirmed,
        evidence_ref=ev if confirmed else "",
        spine_hash=node.provenance.spine_hash,
        attack_chain_path=_str_list(p.get("attack_chain_path")),
        cve_ids=_str_list(p.get("cve_ids")),
        exploit_available=bool(p.get("exploit_available")),
        cisa_kev=bool(p.get("cisa_kev")),
        target_repo=str(p.get("target_repo") or ""),
        target_branch=str(p.get("target_branch") or ""),
    )


def _priority_key(f: TriageFinding) -> tuple:
    """Deterministic rank: severity desc, then KEV, then public-exploit, then chain depth, then ref asc
    (a total, stable tiebreak — no wallclock / RNG)."""
    return (-severity_rank(f.severity), -int(f.cisa_kev), -int(f.exploit_available),
            -len(f.attack_chain_path), f.ref)


def _dedup_by_ref(findings: list[TriageFinding]) -> list[TriageFinding]:
    """Collapse findings sharing a ``ref`` — keep the highest-severity representative, tie-broken by
    ``spine_hash`` (deterministic). First-appearance order is preserved (re-sorted by priority after)."""
    best: dict[str, TriageFinding] = {}
    order: list[str] = []
    for f in findings:
        cur = best.get(f.ref)
        if cur is None:
            best[f.ref] = f
            order.append(f.ref)
        elif (severity_rank(f.severity), f.spine_hash) > (severity_rank(cur.severity), cur.spine_hash):
            best[f.ref] = f
    return [best[r] for r in order]


def _count(findings: list[TriageFinding], key: Callable[[TriageFinding], str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in findings:
        out[key(f)] = out.get(key(f), 0) + 1
    return out


def run_triage(view: Any, *, existing_refs: Any = (), high_only: bool = False) -> RemediationDraft:
    """Run the 9 deterministic triage queries over the projected graph and assemble a prioritized,
    deduped ``RemediationDraft``.

    Only oracle-CONFIRMED findings can enter ``findings`` (each may spawn a remediation); unconfirmed
    leads are surfaced separately in ``leads``. ``existing_refs`` (already-remediated refs) are excluded
    so only NEW findings are drafted (redamon's dedup-against-prior rule). ``high_only`` restricts to
    HIGH+ severity. Deterministic: the same graph yields a byte-identical draft. Total: a non-``GraphView``
    or any per-node malformation degrades to a smaller/empty draft, never a raise."""
    if not isinstance(view, GraphView):
        return RemediationDraft(summary="no graph view (fail-closed: nothing to triage)")
    existing = frozenset(str(r) for r in existing_refs) if isinstance(
        existing_refs, (list, tuple, set, frozenset)) else frozenset()

    # collect unique confirmed node ids across all 9 queries, in first-seen (deterministic) order
    id_set: set[str] = set()
    seen_ids: list[str] = []
    for q in TRIAGE_QUERIES:
        try:
            nodes = q.fn(view)
        except Exception:   # noqa: BLE001 — one bad query never aborts triage (total)
            continue
        for n in nodes:
            if isinstance(n, GraphNode) and n.id not in id_set:
                id_set.add(n.id)
                seen_ids.append(n.id)

    findings: list[TriageFinding] = []
    for nid in seen_ids:
        node = view.get(nid)
        if node is None:
            continue
        try:
            tf = _triage_finding_from_node(node)
        except Exception:   # noqa: BLE001 — a torn node is dropped, never crashes triage
            continue
        if not tf.confirmed:                              # only oracle-confirmed facts are drafted
            continue
        if high_only and severity_rank(tf.severity) < 3:
            continue
        if tf.ref in existing:                            # already remediated → only NEW findings
            continue
        findings.append(tf)

    findings = _dedup_by_ref(findings)
    findings.sort(key=_priority_key)
    for i, tf in enumerate(findings):
        tf.priority = i + 1

    leads: list[TriageFinding] = []
    for n in sorted(view.lead_findings(), key=lambda n: n.id):
        try:
            leads.append(_triage_finding_from_node(n))
        except Exception:   # noqa: BLE001
            continue

    return RemediationDraft(
        findings=findings,
        leads=leads,
        summary=(f"{len(findings)} confirmed finding(s) eligible for remediation; "
                 f"{len(leads)} unconfirmed lead(s) surfaced (never spawn a codefix)"),
        by_severity=_count(findings, key=lambda f: (f.severity or "unknown").strip().lower() or "unknown"),
        by_type=_count(findings, key=lambda f: f.bug_class or "unknown"),
    )


# --- the sovereign spawn boundary --------------------------------------------------------------


def may_remediate(finding: Any) -> tuple[bool, str]:
    """THE sovereign gate for remediation spawning: return ``(allowed, reason)``. A remediation may be
    spawned ONLY from an oracle-confirmed FACT carrying a signed evidence reference. A LEAD, a
    non-``TriageFinding``, or a confirmed finding with no signed ref is REFUSED fail-closed. Pure/total."""
    if not isinstance(finding, TriageFinding):
        return False, "not a triage finding (fail-closed)"
    if not finding.confirmed:
        return False, "triage finding is a LEAD, not an oracle-confirmed FACT — remediation refused"
    if not (finding.evidence_ref or "").strip():
        return False, "confirmed finding carries no signed evidence reference — refused (fail-closed)"
    return True, "oracle-confirmed fact — remediation may be spawned"
