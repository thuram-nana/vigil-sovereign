"""
imports — EXTERNAL-TOOL IMPORTERS (Wave 6 platformization).

Adapters that ingest a THIRD-PARTY security tool's export (a Nuclei / ZAP / Burp /
sqlmap report, or a generic findings JSON) INTO the shared world-model as
provenance-tagged OBSERVATIONS / leads — never as facts.

The doctrine is prove-don't-guess, made concrete:

  * A third-party finding is a LEAD. The importer mints it as an intel
    ``Observation`` (source_kind WEB_SCANNER / OPERATOR_INGEST) that projects onto
    the world-model with a provenance of ``intel:import:*`` — so it classifies as
    GROUNDING_INTEL (real, collected, but NOT oracle-proof), never GROUNDING_GROUNDED.
    It is deliberately NOT a ``FINDING`` node — a FINDING is reserved for what a
    CRUCIBLE oracle has re-verified.
  * An oracle re-verifies where possible; a finding we cannot re-verify stays a
    labelled lead (``lead: True, unverified: True`` in the observation attrs).
  * The importer is PURE of wallclock / rng and mints CLAIM-KEYED, idempotent
    ``obs_id``s, so re-importing the same report is a no-op (byte-identical).

Public surface (import from here, not the submodules):

    from framework.v2.imports import (
        ImportedFinding, ImportResult,
        parse_export, available_formats, detect_format, ImportAdapterError,
        import_report, ImportFindingsTool,
    )

This module generalizes the two existing importer families — ``eval.adapters``
(third-party output parsers, reused verbatim) and ``intel.from_scan`` / ``from_sbom``
(observation minting) — into one operator-facing seam. It is OFF the scanner hot
path: nothing here runs unless an importer is explicitly invoked.
"""

from __future__ import annotations

from .importer import import_report
from .models import ImportAdapterError, ImportedFinding, ImportResult
from .parsers import available_formats, detect_format, parse_export
from .tool import ImportFindingsTool

__all__ = [
    "ImportAdapterError",
    "ImportedFinding",
    "ImportFindingsTool",
    "ImportResult",
    "available_formats",
    "detect_format",
    "import_report",
    "parse_export",
]
