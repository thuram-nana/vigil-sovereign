"""
framework.v2.intel — the Intelligence & Reconnaissance Engine.

Turns CRUCIBLE from a scanner that *collects* into an engine that *reasons over*
intelligence. The one-substrate principle: every intel datum is an `Observation`;
nothing enters the graph except by PROJECTING an Observation onto the world-model,
where the existing Beta-belief upsert handles corroboration, refutation, and
provenance for free. On top of that substrate sit entity resolution (many refs → one
asset), evidence fusion, and — in the `confidence` sibling package — the Scientific
Confidence Engine.

Phase A (this package's first slice): refs + Observation model + fusion + the
projection keystone + entity resolution. Collectors, the adaptive recon planner,
temporal intelligence, and prediction compose on this spine.
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

__all__ = [
    "ArtifactTier", "EntityRef", "canonicalize",
    "Credibility", "IntelSourceKind", "Observation", "Polarity", "Reliability",
    "SourceReliability",
]
