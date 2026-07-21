"""
graph.projector — the one-way spine→graph projector (VIGIL-FUSION F4, slice 1).

**This is the single most dangerous fusion in the program (trust-laundering), so the sovereign rules
are enforced HERE, deterministically:**

  1. **Projection-only, from signed spine records.** The graph is written ONLY by ``project`` over a
     list of ``SpineRecord``. There is no other writer; nothing an LLM or a tool asserts reaches the
     graph except as a spine record, and its veracity is re-derived, never trusted.
  2. **Confirmed ⇔ oracle-signed.** A finding projects to a CONFIRMED node ONLY if the record is a FACT
     carrying BOTH a non-empty signed ``evidence_ref`` AND a ``signature_ref`` (``_is_confirmed``).
     Anything else — including a record that merely *claims* ``status="fact"`` with no evidence — is a
     LEAD. The graph can never launder an unproven claim into a fact.
  3. **Rebuildable + deterministic.** ``project`` sorts records by ``(seq, hash)`` and is a pure
     function — the same spine yields a byte-identical ``GraphView``, so the read-model can be rebuilt
     and independently verified against the spine and cannot silently diverge. No wallclock / RNG: the
     temporal coordinate is the spine ``seq``.
  4. **Bi-temporal, never delete.** A ``refute`` record retires the target node (and its edges) by
     setting ``invalid_from = seq`` — the node stays for audit; it is only excluded from active queries.
  5. **Scope-gated bridges.** A recon bridge to a host/CVE/… is created only if the injected
     ``scope_gate`` admits the host (in-scope only). No gate ⇒ the records are trusted as already
     spine-gated (documented; production wires the host egress/scope gate).
  6. **The graph is inert.** It returns a view; it authorizes nothing. No consumer may read authority
     from it (enforced by the query layer returning only non-authoritative retrieval context).

Import-clean: pydantic + .model + stdlib only.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Optional

from pydantic import BaseModel, Field

from .model import (
    ConfirmationStatus,
    EdgeType,
    GraphEdge,
    GraphNode,
    GraphView,
    NodeLabel,
    Provenance,
)


class SpineRecord(BaseModel):
    """One signed spine record fed to the projector. In production these are read from the CRUCIBLE
    signed spine / the F2 ``AgentState`` fact & lead stores; the projector never trusts a field's
    *claim* of confirmation — it re-derives it from the signed evidence (``_is_confirmed``)."""

    seq: int                        # monotonic spine index (the deterministic temporal coordinate)
    hash: str                       # this record's signed hash
    kind: str                       # chain | step | finding | failure | decision | refute | bridge
    engagement_id: str = ""         # group_id / charter scope
    signature_ref: str = ""         # signed-head / signature reference
    status: str = "lead"            # lead | fact  (a fact still needs evidence_ref to confirm)
    evidence_ref: str = ""          # SCITT/OpenVEX cert id / signed oracle evidence
    props: dict[str, Any] = Field(default_factory=dict)
    # identity + links (stable ids so a lead→confirmed upgrade merges the SAME node)
    chain_id: str = ""
    step_id: str = ""
    finding_ref: str = ""
    parent_step_id: str = ""        # the step that PRODUCED this finding/failure/decision
    prev_step_id: str = ""          # the preceding step (NEXT_STEP)
    refutes_id: str = ""            # for kind=refute: the node id to retire
    targets: list[dict[str, Any]] = Field(default_factory=list)   # [{"type":"cve"/"host"/..,"value":..}]


def _is_confirmed(rec: SpineRecord) -> bool:
    """A record is CONFIRMED iff it is an oracle-minted FACT carrying a non-empty signed evidence ref
    AND a signature ref. This mirrors the F2 ``Finding`` invariant — a bare ``status="fact"`` with no
    signed evidence is NOT confirmed; it is a lead."""
    return (rec.status == "fact"
            and bool((rec.evidence_ref or "").strip())
            and bool((rec.signature_ref or "").strip()))


def _is_oracle_grounded_refutation(rec: SpineRecord) -> bool:
    """A refutation may DEMOTE a confirmed fact only if it is itself oracle-grounded — it carries a
    signed ``evidence_ref`` + ``signature_ref`` attesting that a re-execution FAILED. Per the veracity
    firewall, demotion comes only from re-execution failing, never from an unauthenticated opinion; a
    bare ``kind="refute"`` claim (an LLM's 'looks like a false positive') can retire only a LEAD."""
    return bool((rec.evidence_ref or "").strip()) and bool((rec.signature_ref or "").strip())


def _provenance(rec: SpineRecord, confirmed: bool) -> Provenance:
    return Provenance(
        spine_hash=rec.hash,
        signature_ref=rec.signature_ref,
        evidence_ref=rec.evidence_ref if confirmed else "",   # a lead carries NO evidence ref
        engagement_id=rec.engagement_id,
        confirmation=ConfirmationStatus.CONFIRMED if confirmed else ConfirmationStatus.LEAD,
    )


_BRIDGE_LABELS: dict[str, NodeLabel] = {
    "cve": NodeLabel.CVE, "host": NodeLabel.HOST, "ip": NodeLabel.HOST, "subdomain": NodeLabel.HOST,
    "port": NodeLabel.PORT, "technology": NodeLabel.TECHNOLOGY, "tech": NodeLabel.TECHNOLOGY,
    "endpoint": NodeLabel.ENDPOINT,
}
_FINDING_BRIDGE_EDGE: dict[NodeLabel, EdgeType] = {
    NodeLabel.CVE: EdgeType.FINDING_RELATES_CVE,
    NodeLabel.ENDPOINT: EdgeType.FINDING_AFFECTS_ENDPOINT,
    NodeLabel.PORT: EdgeType.FINDING_AFFECTS_PORT,
    NodeLabel.TECHNOLOGY: EdgeType.FINDING_AFFECTS_TECH,
    NodeLabel.HOST: EdgeType.FOUND_ON,
}

ScopeGate = Callable[[str], bool]


def _bridge_host(target_type: str, value: str) -> str:
    """The host component to scope-check for a bridge target. A HOST is the value itself; an ENDPOINT
    (``https://host/path``) and a PORT (``host:22``) carry a host that must be gated too, so an
    out-of-scope host cannot re-enter the world-model wearing an endpoint/port label."""
    label = _BRIDGE_LABELS.get(target_type)
    if label == NodeLabel.HOST:
        return value
    if label == NodeLabel.ENDPOINT:
        m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://([^/?#]+)", value)
        host = m.group(1) if m else value
        return host.rsplit("@", 1)[-1].split(":", 1)[0].strip("[]")   # strip userinfo + :port + ipv6 []
    if label == NodeLabel.PORT:
        return value.rsplit(":", 1)[0].strip("[]") if ":" in value else value
    return ""   # cve / technology carry no host


def _host_in_scope(target_type: str, value: str, scope_gate: Optional[ScopeGate]) -> bool:
    """A bridge that carries a host (host / endpoint / port) must clear the injected scope gate — only
    in-scope hosts become nodes, whatever label they wear. cve/technology are not host-scoped. No gate
    ⇒ trust the spine's pre-gating (the action that produced the record already cleared the live gate)."""
    host = _bridge_host(target_type, value)
    if not host:                 # no host component (cve/tech) → not host-scoped
        return True
    if scope_gate is None:
        return True
    try:
        return bool(scope_gate(host))
    except Exception:            # noqa: BLE001 — a gate error is fail-closed (host excluded)
        return False


def _project_record(view: GraphView, rec: SpineRecord, scope_gate: Optional[ScopeGate]) -> None:
    kind = (rec.kind or "").lower()
    if kind == "refute":
        if rec.refutes_id:
            target = view.get(rec.refutes_id)
            # a confirmed, oracle-signed fact can be demoted ONLY by an oracle-grounded refutation —
            # an unauthenticated refute silently dropping a proven finding is the mirror of laundering.
            if target is not None and target.is_confirmed and not _is_oracle_grounded_refutation(rec):
                return
            view.retire_node(rec.refutes_id, rec.seq)
        return

    if kind == "chain":
        cid = rec.chain_id or rec.hash
        view.upsert_node(GraphNode(id=f"chain:{cid}", label=NodeLabel.ATTACK_CHAIN,
                                   props=dict(rec.props), provenance=_provenance(rec, False),
                                   valid_from=rec.seq))
        return

    if kind == "step":
        sid = rec.step_id or rec.hash
        node = GraphNode(id=f"step:{sid}", label=NodeLabel.CHAIN_STEP, props=dict(rec.props),
                         provenance=_provenance(rec, False), valid_from=rec.seq)
        view.upsert_node(node)
        if rec.chain_id:
            view.add_edge(GraphEdge(src=f"chain:{rec.chain_id}", dst=node.id, type=EdgeType.HAS_STEP,
                                    provenance=_provenance(rec, False), valid_from=rec.seq))
        if rec.prev_step_id:
            view.add_edge(GraphEdge(src=f"step:{rec.prev_step_id}", dst=node.id, type=EdgeType.NEXT_STEP,
                                    provenance=_provenance(rec, False), valid_from=rec.seq))
        return

    if kind == "finding":
        confirmed = _is_confirmed(rec)
        fid = rec.finding_ref or rec.hash
        node = GraphNode(id=f"finding:{fid}", label=NodeLabel.CHAIN_FINDING, props=dict(rec.props),
                         provenance=_provenance(rec, confirmed), valid_from=rec.seq)
        node = view.upsert_node(node)
        if rec.parent_step_id:
            view.add_edge(GraphEdge(src=f"step:{rec.parent_step_id}", dst=node.id, type=EdgeType.PRODUCED,
                                    provenance=_provenance(rec, confirmed), valid_from=rec.seq))
            view.add_edge(GraphEdge(src=f"step:{rec.parent_step_id}", dst=node.id, type=EdgeType.LED_TO,
                                    provenance=_provenance(rec, confirmed), valid_from=rec.seq))
        _project_bridges(view, rec, node.id, confirmed, scope_gate)
        return

    if kind == "failure":
        node = GraphNode(id=f"failure:{rec.hash}", label=NodeLabel.CHAIN_FAILURE, props=dict(rec.props),
                         provenance=_provenance(rec, False), valid_from=rec.seq)
        view.upsert_node(node)
        if rec.parent_step_id:
            view.add_edge(GraphEdge(src=f"step:{rec.parent_step_id}", dst=node.id,
                                    type=EdgeType.FAILED_WITH, provenance=_provenance(rec, False),
                                    valid_from=rec.seq))
        return

    if kind == "decision":
        node = GraphNode(id=f"decision:{rec.hash}", label=NodeLabel.CHAIN_DECISION, props=dict(rec.props),
                         provenance=_provenance(rec, False), valid_from=rec.seq)
        view.upsert_node(node)
        if rec.parent_step_id:
            view.add_edge(GraphEdge(src=node.id, dst=f"step:{rec.parent_step_id}",
                                    type=EdgeType.DECISION_PRECEDED, provenance=_provenance(rec, False),
                                    valid_from=rec.seq))
        return
    # unknown kind → silently ignored (fail-closed: an unrecognized record projects nothing)


def _project_bridges(view: GraphView, rec: SpineRecord, finding_id: str, confirmed: bool,
                     scope_gate: Optional[ScopeGate]) -> None:
    """Bridge a finding to recon targets (CVE/host/port/tech/endpoint). A HOST target must clear the
    scope gate. The bridge edge/​target inherits the finding's confirmation — a lead's bridges are lead
    edges (never presented as confirmed relationships)."""
    for t in rec.targets:
        if not isinstance(t, dict):
            continue
        ttype = str(t.get("type", "")).lower()
        value = str(t.get("value", "")).strip()
        label = _BRIDGE_LABELS.get(ttype)
        if not label or not value:
            continue
        if not _host_in_scope(ttype, value, scope_gate):
            continue
        tid = f"{label.value.lower()}:{value}"
        view.upsert_node(GraphNode(id=tid, label=label, props={"value": value},
                                   provenance=_provenance(rec, False), valid_from=rec.seq))
        edge_type = _FINDING_BRIDGE_EDGE.get(label, EdgeType.FOUND_ON)
        view.add_edge(GraphEdge(src=finding_id, dst=tid, type=edge_type,
                                provenance=_provenance(rec, confirmed), valid_from=rec.seq))


def spine_record_from_finding(finding: Any, *, seq: int, hash: str, signature_ref: str = "",
                              engagement_id: str = "", parent_step_id: str = "",
                              targets: Optional[list[dict[str, Any]]] = None) -> SpineRecord:
    """Build a ``finding`` SpineRecord from an F2 ``agent.state.Finding``. Confirmation is NOT taken from
    the finding's word — it is re-derived by ``_is_confirmed`` from ``status`` + the finding's signed
    ``evidence_ref`` + the spine record's ``signature_ref`` (which the caller supplies from the signed
    spine entry). A finding not yet on the signed spine (no ``signature_ref``) projects as a LEAD."""
    return SpineRecord(
        seq=seq, hash=hash, kind="finding",
        engagement_id=engagement_id, signature_ref=signature_ref,
        status=str(getattr(finding, "status", "lead") or "lead"),
        evidence_ref=str(getattr(finding, "evidence_ref", "") or ""),
        finding_ref=str(getattr(finding, "ref", "") or hash),
        parent_step_id=parent_step_id,
        props={"ref": str(getattr(finding, "ref", "") or ""),
               "title": str(getattr(finding, "title", "") or ""),
               "severity": str(getattr(finding, "severity", "") or ""),
               "bug_class": str(getattr(finding, "bug_class", "") or ""),
               "source": str(getattr(finding, "source", "") or "")},
        targets=targets or [])


def project(records: list[SpineRecord], *, group_id: str = "",
            scope_gate: Optional[ScopeGate] = None) -> GraphView:
    """Project a list of signed spine records into a typed ``GraphView`` — the ONLY writer. Deterministic
    (records applied in ``(seq, hash)`` order), so the same spine rebuilds a byte-identical view. A
    finding is CONFIRMED only when its record carries signed oracle evidence; everything else is a LEAD.
    Never raises on a malformed record LIST — a non-``SpineRecord`` element (e.g. a torn/None row from
    a lossy spine loader) is skipped, not crashed on."""
    view = GraphView(group_id=group_id)
    clean = [r for r in (records or []) if isinstance(r, SpineRecord)]   # pre-filter → total on garbage
    # total order: (seq, hash, canonical body) so two records sharing (seq, hash) still sort
    # deterministically — the same record set rebuilds a byte-identical view in ANY input order.
    for rec in sorted(clean, key=lambda r: (r.seq, r.hash, r.model_dump_json())):
        try:
            _project_record(view, rec, scope_gate)
        except Exception:   # noqa: BLE001 — a malformed record must not abort the whole projection
            continue
    return view
