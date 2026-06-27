"""
socialdefense — defensive detection of social-engineering attacks.

The inverse of the Bucket-C capabilities the framework refuses to build:
instead of *generating* phishing or impersonation, this scores *inbound*
content for the indicators of a social-engineering attack, to protect an
organisation's people. It is pure defence — it analyses messages the
operator received; it produces nothing offensive and contacts no one.

Deterministic and offline: a curated indicator set (urgency, credential
harvesting, authority impersonation, lookalike domains, sender/reply-to
mismatch, financial-action requests, secrecy requests, dangerous
attachments) yields a weighted risk score and a recommendation. A
production deployment augments this with ML/LLM classifiers; the
heuristic core is honest, testable, and a useful first filter on its own.

Deepfake *audio/video* detection needs media-forensic models and is out
of scope here; this package covers text/email social engineering.

Public surface:

    from framework.v2.socialdefense import (
        MessageArtifact, PhishingSignal, PhishingAssessment, RiskBand,
        assess_message,
    )
"""

from __future__ import annotations

from .detectors import assess_message
from .models import (
    MessageArtifact,
    PhishingAssessment,
    PhishingSignal,
    RiskBand,
)

__all__ = [
    "MessageArtifact",
    "PhishingSignal",
    "PhishingAssessment",
    "RiskBand",
    "assess_message",
]
