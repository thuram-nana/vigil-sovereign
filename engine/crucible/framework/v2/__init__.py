"""
CRUCIBLE v2 — autonomous, learning, universal offensive-intelligence
platform layered on top of v1.

v1 is the cognitive canon: prose, playbooks, scripts, templates. v2
turns that canon into executable substrate while preserving every
v1 file byte-for-byte. Read framework/v2/README.md for the layout.

This package is intentionally import-light at top level. Subsystems
load on demand.
"""

from __future__ import annotations

__version__ = "2.0.0a1"

__all__ = ["__version__"]
