"""
redpen — the Red-Pen adversarial reproduction engine (offense plane, VIGIL R1, design §7.2).

Public surface for the map -> attack -> refute-by-reproduction -> certify pipeline. Everything is behind
``VIGIL_REDPEN_ENABLED`` (default OFF): with the flag off :func:`run_redpen` is inert. All ``framework`` /
SDK work is lazy behind the certify seam, so importing this package pulls no ``framework`` (FATAL-2) and
never imports ``sigil`` (the offense plane holds no keys).

R3 (the PR-review worker) is the primary consumer: it calls :func:`run_redpen` with a local checkout, the
changed paths, a gateway-backed reviewer and the governance signers, and posts the returned FACTs (LEADs
stay on the dashboard).
"""

from __future__ import annotations

from .certify import (
    CertifyResult,
    certify_candidate,
)
from .engine import (
    DEFAULT_LENSES,
    REDPEN_ENABLED_ENV,
    LensCandidate,
    LensRequest,
    LensResponse,
    RedPenFact,
    RedPenLead,
    RedPenReport,
    RedPenReviewer,
    SkippedLens,
    redpen_enabled,
    run_redpen,
)
from .reproduce import (
    DEFAULT_REPRO_TIMEOUT,
    DEFAULT_RUNS_REQUIRED,
    Reproduction,
    reproduce_candidate,
)

__all__ = [
    "run_redpen",
    "redpen_enabled",
    "REDPEN_ENABLED_ENV",
    "DEFAULT_LENSES",
    "LensCandidate",
    "LensRequest",
    "LensResponse",
    "RedPenReviewer",
    "RedPenReport",
    "RedPenFact",
    "RedPenLead",
    "SkippedLens",
    "reproduce_candidate",
    "Reproduction",
    "DEFAULT_REPRO_TIMEOUT",
    "DEFAULT_RUNS_REQUIRED",
    "certify_candidate",
    "CertifyResult",
]
