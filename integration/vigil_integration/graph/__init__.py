"""
vigil_integration.graph — the attack-chain graph memory as a signed-spine projection (VIGIL-FUSION F4).

A reimplementation of redamon's EvoGraph as a DERIVED READ-MODEL, never a parallel source of truth.
``model`` is the typed graph (confirmed/lead split, spine-hash provenance, bi-temporal valid/invalid).
``projector`` is the ONLY writer — a deterministic, projection-only function over signed spine records
that confirms a finding solely on signed oracle evidence and retires (never deletes) a refuted lead.
``query`` reads it back as non-authoritative retrieval context (a lead can never be returned as a fact,
and nothing here grants a tier). Neo4j is the deferred live backend; this slice is the pure projector.

S3 (default-OFF behind ``VIGIL_GRAPH_OBJECTIVES``) extends the read-model with an INERT ``OBJECTIVE``
node for a declared charter objective and the ``REACHES`` (Asset→Goal) / ``PURSUES`` (ChainStep→Goal)
edges. A Goal is never a FACT: it carries no evidence_ref, is never returned by ``confirmed_findings``,
and authorizes nothing; with the flag off the view is byte-identical to the pre-S3 read-model.
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
from .objectives_flag import OBJECTIVES_ENV, objectives_enabled
from .projector import (
    SpineRecord,
    project,
    spine_record_from_finding,
)
from .query import (
    FailureLesson,
    FindingSummary,
    ObjectiveContext,
    ObjectiveSummary,
    PriorChainContext,
    objectives,
    query_prior_chains,
    successful_tools,
)

__all__ = [
    # model
    "NodeLabel", "EdgeType", "ConfirmationStatus", "Provenance", "GraphNode", "GraphEdge", "GraphView",
    # projector
    "SpineRecord", "project", "spine_record_from_finding",
    # S3 charter-objective flag (default-OFF)
    "OBJECTIVES_ENV", "objectives_enabled",
    # query
    "PriorChainContext", "FindingSummary", "FailureLesson", "query_prior_chains", "successful_tools",
    "ObjectiveContext", "ObjectiveSummary", "objectives",
]
