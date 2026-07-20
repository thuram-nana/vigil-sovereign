"""
vigil_integration — the seam between the offense engine and the sovereign personal core.

Deliberately import-clean: this package pulls neither ``framework.*`` nor ``strix.*``, so it can
live in the offense-free env-sovereign. The sovereign-facing inert-finding receiver is exported
here; the offense worker is imported explicitly (``vigil_integration.offense_worker``) by the
offense side, keeping the default import surface minimal.
"""

from __future__ import annotations

from .inert_finding import (
    SCHEMA,
    InertFindingError,
    ValidatedFinding,
    build_envelope,
    validate_inert_finding,
)

__all__ = [
    "SCHEMA",
    "InertFindingError",
    "ValidatedFinding",
    "build_envelope",
    "validate_inert_finding",
]
