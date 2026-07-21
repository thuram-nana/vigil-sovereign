"""
graph.model — the typed attack-chain graph model (VIGIL-FUSION F4, slice 1).

Reimplements the SHAPE of redamon's EvoGraph (``chain_graph_writer.py``, MIT; see NOTICE) — the typed
provenance DAG ``AttackChain → ChainStep → {ChainFinding | ChainFailure | ChainDecision}`` bridged to a
recon graph (CVE/host/port/tech) — but as a **derived read-model**, never a parallel source of truth.
The sovereign distinctions are baked into the TYPES so the graph can never launder an unproven claim
into a fact:

  * ``ConfirmationStatus`` splits every finding node into ``CONFIRMED`` vs ``LEAD``. A CONFIRMED node
    carries a signed evidence reference; a LEAD is an unproven proposal. They are DISTINCT node states,
    so a query for confirmed facts can never return a lead (enforced in ``graph.query``).
  * ``Provenance`` on every node = the signed spine ``spine_hash`` (the node's identity key) + the
    ``signature_ref`` + the ``evidence_ref`` (SCITT/OpenVEX cert id) + the ``engagement_id`` (group_id /
    charter scope). Because every node is keyed on a signed spine hash, the whole graph is rebuildable
    and independently verifiable from the spine and cannot silently diverge.
  * Bi-temporal ``valid_from`` / ``invalid_from`` (from pentagi's Graphiti, reimplemented). When the
    oracle refutes a lead, the projector sets ``invalid_from`` — it NEVER deletes. The temporal
    coordinate is the spine SEQUENCE (a monotonic integer), NOT a wallclock, so projection stays
    deterministic and rebuildable (no ``Date.now`` — the spine rule).

Nothing in this module makes anything true or authorizes anything; it is a passive typed view. The
projector (``graph.projector``) is the only writer, and it writes only from signed spine records.

Import-clean: pydantic + stdlib only.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class NodeLabel(str, Enum):
    """Node labels — the attack-chain core + the recon-graph bridge targets."""

    ATTACK_CHAIN = "AttackChain"
    CHAIN_STEP = "ChainStep"
    CHAIN_FINDING = "ChainFinding"
    CHAIN_FAILURE = "ChainFailure"
    CHAIN_DECISION = "ChainDecision"
    # recon-graph bridge targets
    CVE = "CVE"
    HOST = "Host"            # IP / subdomain
    PORT = "Port"
    TECHNOLOGY = "Technology"
    ENDPOINT = "Endpoint"


class EdgeType(str, Enum):
    """Relationship types (redamon's EvoGraph edge vocabulary)."""

    HAS_STEP = "HAS_STEP"
    NEXT_STEP = "NEXT_STEP"
    LED_TO = "LED_TO"
    DECISION_PRECEDED = "DECISION_PRECEDED"
    PRODUCED = "PRODUCED"
    FAILED_WITH = "FAILED_WITH"
    CHAIN_TARGETS = "CHAIN_TARGETS"
    STEP_TARGETED = "STEP_TARGETED"
    STEP_EXPLOITED = "STEP_EXPLOITED"
    STEP_IDENTIFIED = "STEP_IDENTIFIED"
    FOUND_ON = "FOUND_ON"
    FINDING_RELATES_CVE = "FINDING_RELATES_CVE"
    FINDING_AFFECTS_ENDPOINT = "FINDING_AFFECTS_ENDPOINT"
    FINDING_AFFECTS_PORT = "FINDING_AFFECTS_PORT"
    FINDING_AFFECTS_TECH = "FINDING_AFFECTS_TECH"


class ConfirmationStatus(str, Enum):
    """The veracity of a finding node. The whole anti-trust-laundering guarantee rests on this split:
    only an oracle-confirmed, signed-evidence record projects to CONFIRMED; everything else is a LEAD."""

    CONFIRMED = "confirmed"   # oracle-confirmed FACT, carries a signed evidence ref
    LEAD = "lead"             # unproven proposal — never queryable as a fact


class Provenance(BaseModel):
    """Every node's link back to the signed spine. ``spine_hash`` is the node's identity (so the graph
    is rebuildable from the spine); a CONFIRMED node additionally carries a non-empty ``evidence_ref``."""

    spine_hash: str = ""
    signature_ref: str = ""
    evidence_ref: str = ""          # SCITT/OpenVEX cert id (present ⇔ confirmed)
    engagement_id: str = ""         # group_id / charter scope
    confirmation: ConfirmationStatus = ConfirmationStatus.LEAD


class GraphNode(BaseModel):
    """One node. ``id`` is keyed on the signed spine hash for spine-derived nodes (findings/steps) or a
    deterministic natural key for bridge targets (``cve:CVE-...``, ``host:...``). ``invalid_from`` is the
    spine sequence at which a refutation retired the node (None = currently valid)."""

    id: str
    label: NodeLabel
    props: dict[str, Any] = Field(default_factory=dict)
    provenance: Provenance = Field(default_factory=Provenance)
    valid_from: int = 0                     # spine sequence the node was projected at
    invalid_from: Optional[int] = None      # spine sequence a refutation retired it (never deleted)
    invalid_grounded: bool = False          # was the retiring refutation oracle-grounded (signed)?

    @property
    def is_active(self) -> bool:
        return self.invalid_from is None

    @property
    def is_confirmed(self) -> bool:
        return (self.label == NodeLabel.CHAIN_FINDING
                and self.provenance.confirmation == ConfirmationStatus.CONFIRMED)


class GraphEdge(BaseModel):
    """One relationship. Carries the provenance of the spine record that created it, and its own
    bi-temporal retirement (an edge off a retired lead is retired with it)."""

    src: str
    dst: str
    type: EdgeType
    props: dict[str, Any] = Field(default_factory=dict)
    provenance: Provenance = Field(default_factory=Provenance)
    valid_from: int = 0
    invalid_from: Optional[int] = None

    @property
    def is_active(self) -> bool:
        return self.invalid_from is None

    def key(self) -> tuple[str, str, str]:
        return (self.src, self.dst, self.type.value)


class GraphView(BaseModel):
    """The projected read-model for ONE engagement (group_id). ``nodes`` is keyed by node id (MERGE
    semantics: re-projecting the same spine hash updates, never duplicates); ``edges`` is deduplicated
    by (src, dst, type). Serialisable so it can be snapshotted, and deterministic so it rebuilds
    byte-identically from the same spine records."""

    group_id: str = ""
    nodes: dict[str, GraphNode] = Field(default_factory=dict)
    edges: list[GraphEdge] = Field(default_factory=list)

    def upsert_node(self, node: GraphNode) -> GraphNode:
        """MERGE on id: a repeated spine hash updates the existing node in place rather than duplicating.
        A node's confirmation is monotone — it can only move LEAD→CONFIRMED (an oracle confirming a prior
        lead), never CONFIRMED→LEAD (nothing can un-prove a signed fact)."""
        existing = self.nodes.get(node.id)
        if existing is None:
            self.nodes[node.id] = node
            return node
        # keep the strongest confirmation seen (monotone upgrade only)
        if (existing.is_confirmed and not node.is_confirmed):
            merged_conf = existing.provenance
        else:
            merged_conf = node.provenance if node.provenance.confirmation == ConfirmationStatus.CONFIRMED \
                else existing.provenance
        existing.props.update(node.props)
        existing.provenance = merged_conf
        # RESURRECTION: an oracle confirmation lands on a node that a NON-oracle-grounded (bare) refute
        # retired → clear the retirement (a proven fact must not stay suppressed by an unauthenticated
        # opinion recorded before the proof). An oracle-GROUNDED retirement is NOT auto-resurrected.
        if (merged_conf.confirmation == ConfirmationStatus.CONFIRMED
                and existing.invalid_from is not None and not existing.invalid_grounded):
            existing.invalid_from = None
        if node.invalid_from is not None:
            existing.invalid_from = node.invalid_from
        return existing

    def add_edge(self, edge: GraphEdge) -> GraphEdge:
        for e in self.edges:
            if e.key() == edge.key():
                e.props.update(edge.props)
                return e
        self.edges.append(edge)
        return edge

    def get(self, node_id: str) -> Optional[GraphNode]:
        return self.nodes.get(node_id)

    def retire_node(self, node_id: str, at_seq: int, *, grounded: bool = False) -> bool:
        """Bi-temporal retire: set ``invalid_from`` on the node and every edge touching it. Never
        deletes. ``grounded`` records whether the retiring refutation was oracle-grounded (a non-grounded
        retirement is resurrectable by a later oracle confirmation). Returns True if the node was active."""
        node = self.nodes.get(node_id)
        if node is None or node.invalid_from is not None:
            return False
        node.invalid_from = at_seq
        node.invalid_grounded = grounded
        for e in self.edges:
            if (e.src == node_id or e.dst == node_id) and e.invalid_from is None:
                e.invalid_from = at_seq
        return True

    def active_nodes(self, label: Optional[NodeLabel] = None) -> list[GraphNode]:
        return [n for n in self.nodes.values() if n.is_active and (label is None or n.label == label)]

    def confirmed_findings(self) -> list[GraphNode]:
        """The ONLY facts. An active ChainFinding whose provenance is CONFIRMED — a lead can never
        appear here (the anti-trust-laundering guarantee, at the query boundary)."""
        return [n for n in self.nodes.values() if n.is_active and n.is_confirmed]

    def lead_findings(self) -> list[GraphNode]:
        return [n for n in self.nodes.values()
                if n.is_active and n.label == NodeLabel.CHAIN_FINDING and not n.is_confirmed]
