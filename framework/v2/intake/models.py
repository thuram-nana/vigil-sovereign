"""
intake.models — Pydantic types for UTI fingerprinting and intake.

Every fingerprint detector returns a `DetectionResult`. The intake
pipeline aggregates them into a `Fingerprint`. The classifier maps
the `Fingerprint` to an `Archetype`.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Captured HTTP exchanges (the input to every detector)
# ---------------------------------------------------------------------------


class HTTPExchange(BaseModel):
    """One request/response pair captured during intake."""

    model_config = ConfigDict(populate_by_name=True)

    method: str = "GET"
    url: str
    status: int
    headers: dict[str, str] = Field(default_factory=dict)
    body_excerpt: str = Field(
        default="", description="Up to 16 KB of the response body."
    )
    cookies: dict[str, str] = Field(default_factory=dict)
    elapsed_ms: float = 0.0
    note: str = ""

    def header(self, name: str) -> str:
        """Case-insensitive header lookup."""
        if name in self.headers:
            return self.headers[name]
        target = name.lower()
        for k, v in self.headers.items():
            if k.lower() == target:
                return v
        return ""


# ---------------------------------------------------------------------------
# Detection results
# ---------------------------------------------------------------------------


class Detection(BaseModel):
    """One specific signal a detector found."""

    label: str = Field(description="Canonical token, e.g. 'laravel', 'cloudflare'.")
    category: str = Field(
        description="Class of signal: server, framework, cms, auth, api, "
                    "payment, cdn, waf, security-header, ...",
    )
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(
        default_factory=list,
        description="Human-readable lines naming the signals that triggered.",
    )


class DetectionResult(BaseModel):
    """All detections produced by one detector module."""

    detector: str
    detections: list[Detection] = Field(default_factory=list)

    def best(self) -> Detection | None:
        return max(self.detections, key=lambda d: d.confidence) if self.detections else None

    def labels(self, min_confidence: float = 0.0) -> list[str]:
        return [d.label for d in self.detections if d.confidence >= min_confidence]


# ---------------------------------------------------------------------------
# Fingerprint — the aggregate of every detector
# ---------------------------------------------------------------------------


class Fingerprint(BaseModel):
    """The flat, structured fingerprint of a target."""

    target_url: str
    detectors: dict[str, DetectionResult] = Field(default_factory=dict)
    security_headers: dict[str, str] = Field(default_factory=dict)
    cookies_seen: list[str] = Field(default_factory=list)
    paths_probed: list[str] = Field(default_factory=list)
    request_count: int = 0
    notes: list[str] = Field(default_factory=list)

    def best_per_category(self) -> dict[str, Detection]:
        """One Detection per category (the highest-confidence one)."""
        out: dict[str, Detection] = {}
        for r in self.detectors.values():
            for d in r.detections:
                cur = out.get(d.category)
                if cur is None or d.confidence > cur.confidence:
                    out[d.category] = d
        return out

    def labels(self) -> list[str]:
        """Flat list of every detected label."""
        out: list[str] = []
        for r in self.detectors.values():
            out.extend(r.labels())
        return out

    def to_text(self) -> str:
        """Render to a single text blob for embedding / similarity search."""
        parts = [f"target_url: {self.target_url}"]
        for cat, d in sorted(self.best_per_category().items()):
            parts.append(f"{cat}: {d.label} ({d.confidence:.2f})")
        if self.security_headers:
            parts.append("security_headers: " + ", ".join(
                f"{k}={v[:40]}" for k, v in self.security_headers.items()
            ))
        if self.cookies_seen:
            parts.append("cookies: " + ", ".join(self.cookies_seen[:8]))
        return "\n".join(parts)


# ---------------------------------------------------------------------------
# Archetype + classification
# ---------------------------------------------------------------------------


class Archetype(BaseModel):
    """One archetype loaded from intake/archetypes/*.yaml."""

    name: str
    slug: str
    description: str = ""
    fingerprints_required_any: list[str] = Field(default_factory=list)
    fingerprints_optional: list[str] = Field(default_factory=list)
    common_vulnerabilities: list[str] = Field(default_factory=list)
    playbook_priorities: list[str] = Field(default_factory=list)
    attack_tree_seeds: list[str] = Field(default_factory=list)
    notes: str = ""


class ArchetypeMatch(BaseModel):
    archetype: Archetype
    score: float = Field(ge=0.0, le=1.0)
    matched_required: list[str] = Field(default_factory=list)
    matched_optional: list[str] = Field(default_factory=list)


class Classification(BaseModel):
    """Result of stack_classifier.classify()."""

    primary: ArchetypeMatch
    runners_up: list[ArchetypeMatch] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Intake outcome
# ---------------------------------------------------------------------------


class IntakeOutcome(BaseModel):
    """Top-level result of intake.run()."""

    target_url: str
    slug: str
    fingerprint: Fingerprint
    classification: Classification
    scaffold_dir: str
    charter_draft_path: str
    threat_model_path: str
    attack_tree_path: str
    fingerprint_json_path: str
    request_count: int
    notes: list[str] = Field(default_factory=list)
