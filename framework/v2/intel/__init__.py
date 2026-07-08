"""
framework.v2.intel — the Intelligence & Reconnaissance Engine.

Turns CRUCIBLE from a scanner that *collects* into an engine that *reasons over*
intelligence. The one-substrate principle: every intel datum is an `Observation`;
nothing enters the graph except by PROJECTING an Observation onto the world-model,
where the existing Beta-belief upsert handles corroboration, refutation, and
provenance for free. On top of that substrate sit entity resolution (many refs → one
asset), evidence fusion, and — in the `confidence` sibling package — the Scientific
Confidence Engine.

Phase A (the reasoning core): refs + Observation model + fusion + the projection
keystone + entity resolution. Phase B (the collection spine) composes on it:
transport-injected offline-first collectors, the IntelIngest single writer, and
the VOI-driven ReconPlanner.
"""

from .refs import ArtifactTier, EntityRef, canonicalize
from .models import (
    Credibility,
    IntelSourceKind,
    Observation,
    Polarity,
    Reliability,
    SourceReliability,
)
from .transport import (
    DisabledTransport,
    FixtureTransport,
    GuardedHttpTransport,
    MappingTransport,
    RawRecord,
    Transport,
)
from .ingest import IngestResult, IntelIngest
from .planner import ReconPlan, ReconPlanner, ReconTask
from .store import IntelStore
from .live import (
    DEFAULT_COLLECTOR_HOSTS,
    LIVE_ENDPOINTS,
    build_live_transport,
    normalize_response,
)
from .temporal import (
    ENUMERATIVE_SOURCE_KINDS,
    SurfaceDelta,
    TemporalIndex,
    TimelineEvent,
)
from .predict import AssetHypothesis, AssetPredictor, assess_prediction
from .from_cloud import observations_from_cloud
from .from_sbom import observations_from_sbom
from .learn import (
    SourceYield,
    credit_discovery,
    credit_finding,
    planner_priors,
    source_prior,
)

__all__ = [
    "ArtifactTier", "EntityRef", "canonicalize",
    "Credibility", "IntelSourceKind", "Observation", "Polarity", "Reliability",
    "SourceReliability",
    # Phase B — collection spine
    "Transport", "RawRecord", "DisabledTransport", "FixtureTransport",
    "MappingTransport", "GuardedHttpTransport",
    "IntelIngest", "IngestResult", "IntelStore",
    "ReconPlanner", "ReconPlan", "ReconTask",
    # gated live recon
    "build_live_transport", "normalize_response", "LIVE_ENDPOINTS", "DEFAULT_COLLECTOR_HOSTS",
    # Phase C — temporal + prediction
    "TemporalIndex", "SurfaceDelta", "TimelineEvent", "ENUMERATIVE_SOURCE_KINDS",
    "AssetPredictor", "AssetHypothesis", "assess_prediction",
    # Phase D — learning
    "SourceYield", "source_prior", "planner_priors", "credit_discovery", "credit_finding",
    # offline asset-graph ingestion (cloud/IAM + supply-chain)
    "observations_from_cloud", "observations_from_sbom",
]
