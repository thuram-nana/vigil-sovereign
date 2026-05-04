"""
intake — UTI, the Universal Target Intake.

Convert any web URL into a fully scaffolded engagement folder under
`targets/<slug>/`, with a charter draft, draft threat model, draft
attack tree, and a fingerprint JSON. Every step honours the ethics
gates: no scaffolding without operator-attested authorization; no
active testing until the operator signs charter.md.
"""

from __future__ import annotations

from .intake import run

__all__ = ["run"]
