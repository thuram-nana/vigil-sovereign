"""
vigil_integration.graph — the attack-chain graph memory as a signed-spine projection (VIGIL-FUSION F4).

A reimplementation of redamon's EvoGraph as a DERIVED READ-MODEL, never a parallel source of truth.
``model`` is the typed graph (confirmed/lead split, spine-hash provenance, bi-temporal valid/invalid).
``projector`` is the ONLY writer — a deterministic, projection-only function over signed spine records
that confirms a finding solely on signed oracle evidence and retires (never deletes) a refuted lead.
``query`` reads it back as non-authoritative retrieval context (a lead can never be returned as a fact,
and nothing here grants a tier). Neo4j is the deferred live backend; this slice is the pure projector.
"""

from .model import (
    ConfirmationStatus,
    EdgeType,
    GraphEdge,
    GraphNode,
    GraphView,
    NodeLabel,
    Provenance,
)
from .projector import (
    SpineRecord,
    project,
    spine_record_from_finding,
)
from .query import (
    FailureLesson,
    FindingSummary,
    PriorChainContext,
    query_prior_chains,
    successful_tools,
)

__all__ = [
    # model
    "NodeLabel", "EdgeType", "ConfirmationStatus", "Provenance", "GraphNode", "GraphEdge", "GraphView",
    # projector
    "SpineRecord", "project", "spine_record_from_finding",
    # query
    "PriorChainContext", "FindingSummary", "FailureLesson", "query_prior_chains", "successful_tools",
]
