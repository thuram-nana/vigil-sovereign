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

S2 (default-OFF behind ``VIGIL_GRAPH_EVIDENCE_JOIN``) dereferences + re-verifies a confirmed finding's
``evidence_ref`` (reusing the S1 resolver's ``verify_certificate``, authenticity anchored out-of-band) and
demotes — at the ``confirmed_findings()`` query boundary only — any fact whose cert cannot be re-established;
it never mutates intrinsic ``is_confirmed``, so flag-off is byte-identical.

S4 (default-OFF behind ``VIGIL_GRAPH_LIFECYCLE``) projects the existing signed remediation/retest certs as
the INERT ``REMEDIATION`` / ``RETEST`` nodes and ``REMEDIATED_BY`` / ``RETESTED_BY`` edges, re-verified
through an injected :class:`LifecycleVerifier` (no second verifier, no live retest); with the flag off the
view is byte-identical to the pre-S4 read-model.
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
    FindingLink,
    LifecycleVerifier,
    RetestSeries,
    RetestTick,
    SpineRecord,
    lifecycle_enabled,
    make_default_lifecycle,
    project,
    spine_record_from_finding,
)
from .query import (
    FailureLesson,
    FindingSummary,
    LifecycleContext,
    ObjectiveContext,
    ObjectiveSummary,
    PriorChainContext,
    RemediationSummary,
    RetestSummary,
    lifecycle_chains,
    objectives,
    query_prior_chains,
    successful_tools,
)

__all__ = [
    # model
    "NodeLabel", "EdgeType", "ConfirmationStatus", "Provenance", "GraphNode", "GraphEdge", "GraphView",
    # projector
    "SpineRecord", "project", "spine_record_from_finding",
    # projector — F4 slice S4 lifecycle (flag-gated; default OFF)
    "LifecycleVerifier", "FindingLink", "RetestTick", "RetestSeries", "make_default_lifecycle",
    "lifecycle_enabled",
    # S3 charter-objective flag (default-OFF)
    "OBJECTIVES_ENV", "objectives_enabled",
    # query
    "PriorChainContext", "FindingSummary", "FailureLesson", "query_prior_chains", "successful_tools",
    "ObjectiveContext", "ObjectiveSummary", "objectives",
    # query — F4 slice S4 lifecycle retrieval
    "LifecycleContext", "RemediationSummary", "RetestSummary", "lifecycle_chains",
]
