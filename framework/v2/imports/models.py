"""
imports.models — the normalized third-party finding + the import result.

``ImportedFinding`` is the tool-agnostic shape every external export is parsed into
(the same shape ``eval.validation.NormalizedFinding`` speaks, plus a derived host).
``ImportResult`` is what one import produced — the leads minted plus the ingest
roll-up. Both are pure, validated data shapes; parsing lives in ``parsers`` and
observation minting in ``to_observations``.

The single load-bearing honesty rule lives here in a field name: ``tool_confirmed``
records the SOURCE tool's own confidence. It is NEVER a CRUCIBLE fact — a
CRUCIBLE fact needs a fired oracle over data a real target produced. An imported
finding is a lead until one of our oracles re-verifies it.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..common.errors import CrucibleError


class ImportAdapterError(CrucibleError):
    """An external-tool importer could not parse its input. A recoverable
    measurement error (the export was malformed / the wrong shape), never an
    authorization decision. Fail-loud so a bad file never silently mints nothing."""


class ImportedFinding(BaseModel):
    """One finding parsed from a third-party tool's export, in a tool-agnostic shape.

    ``bug_class`` is normalized+lowercased; ``location`` is the URL / path+param the
    finding sits on; ``host`` is derived from the location for the asset-tier
    observation. ``tool_confirmed`` is the source tool's OWN confidence — metadata,
    never a CRUCIBLE fact."""

    model_config = ConfigDict(extra="forbid")

    tool: str = Field(min_length=1, description="Source tool label (nuclei/zap/burp/...).")
    bug_class: str = Field(description="Normalized, lowercased bug class.")
    location: str = Field(default="", description="URL, path+param, or bare host the finding sits on.")
    host: str = Field(default="", description="Host derived from the location (asset-tier subject).")
    severity: str = ""
    tool_confirmed: bool = Field(
        default=False,
        description="The SOURCE tool's own confidence — metadata, never a CRUCIBLE oracle fact.",
    )
    evidence: str = ""

    @field_validator("bug_class")
    @classmethod
    def _normalize_bug_class(cls, v: str) -> str:
        return (v or "").strip().lower() or "unknown"


class ImportResult(BaseModel):
    """What one import produced. ``leads`` are the parsed findings (labelled,
    unverified); the counters mirror ``intel.ingest.IngestResult`` — ``applied``
    observations changed world-model belief, ``dropped`` were reliability-0.
    ``warnings`` collects non-fatal parse notes."""

    model_config = ConfigDict(extra="forbid")

    source_tool: str
    format: str
    leads: list[ImportedFinding] = Field(default_factory=list)
    observations: int = 0
    applied: int = 0
    dropped: int = 0
    persisted: int = 0
    warnings: list[str] = Field(default_factory=list)
    doctrine: str = (
        "Imported findings are LEADS (GROUNDING_INTEL), never facts. A CRUCIBLE oracle "
        "re-verifies where possible; an un-re-verifiable third-party finding stays a "
        "labelled lead."
    )
