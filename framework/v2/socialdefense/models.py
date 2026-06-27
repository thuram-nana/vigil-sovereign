"""
socialdefense.models — schemas for inbound social-engineering assessment.
"""

from __future__ import annotations

import enum

from pydantic import BaseModel, ConfigDict, Field


class MessageArtifact(BaseModel):
    """An inbound message to assess. All fields optional except the body
    so partial captures (e.g. body-only) still score."""

    model_config = ConfigDict(extra="forbid")

    body: str = Field(min_length=0)
    subject: str = Field(default="")
    sender_display: str = Field(default="", description="Friendly 'From' name.")
    sender_address: str = Field(default="", description="From email address.")
    reply_to: str = Field(default="", description="Reply-To address, if any.")
    urls: list[str] = Field(default_factory=list, description="Links in the message.")
    attachments: list[str] = Field(default_factory=list, description="Attachment filenames.")


class PhishingSignal(BaseModel):
    """One indicator found in a message."""

    model_config = ConfigDict(extra="forbid")

    kind: str
    weight: float = Field(ge=0.0, le=1.0, description="Per-signal severity weight.")
    evidence: str = Field(description="What triggered it (redacted/truncated).")


class RiskBand(str, enum.Enum):
    MINIMAL = "minimal"
    LOW = "low"
    ELEVATED = "elevated"
    HIGH = "high"
    CRITICAL = "critical"


class PhishingAssessment(BaseModel):
    """The verdict for one message."""

    model_config = ConfigDict(extra="forbid")

    score: float = Field(ge=0.0, le=1.0, description="noisy-OR over signal weights.")
    band: RiskBand
    signals: list[PhishingSignal] = Field(default_factory=list)
    recommendation: str = ""
