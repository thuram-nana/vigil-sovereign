"""
aegis.registry — the additive vocabulary AEGIS registers into the shared substrate.

AEGIS does NOT own a private oracle set; it extends the ONE verifier/world-model vocabulary by
ADDITIVE APPENDS (never rewrites), so an AI-attack class asserted as oracle-provable cannot be
a hallucinated label (``require_known_bug_class`` parse-rejects OOV) and no existing class's
oracle set or verdict changes. The appends live in their home modules:

  * OracleKind members + BUG_CLASS_ORACLES rows + aliases  → ``verify/verifier.py`` + ``verify/models.py``
  * the oracle bodies                                      → ``verify/oracles.py`` (NOT here — avoids an aegis↔verify cycle)
  * IntelSourceKind members                                → ``intel/models.py``
  * _ALTERNATIVES / _CONFIRMATION_LR rows                  → ``confidence/decision.py``

This module is the single place that NAMES the AEGIS vocabulary and can self-check that every
append is actually present — used by the byte-identical gate test. It imports only the shared
substrate; nothing here is on the scan/engage/benchmark/__main__ gate path.
"""

from __future__ import annotations

from ..intel.models import IntelSourceKind
from ..verify.models import OracleKind
from ..verify.verifier import BUG_CLASS_ORACLES, known_bug_classes, normalize_bug_class

# The AEGIS confirmed classes and the ONE oracle each maps to (the honest split — P1/P2).
AEGIS_BUG_CLASS_ORACLES: dict[str, OracleKind] = {
    "prompt_injection": OracleKind.PROMPT_INJECTION,
    "system_prompt_disclosure": OracleKind.SYSTEM_PROMPT_DISCLOSURE,
    "automated_access": OracleKind.AUTOMATED_ACCESS,
}

# Aliases folded onto the honest canonical classes (never their own confirmed class).
AEGIS_ALIASES: dict[str, str] = {
    "jailbreak": "prompt_injection",
    "system_prompt_leak": "system_prompt_disclosure",
    "automated_scraping": "automated_access",   # honeypot proves AUTOMATION, not "scraping" (P1)
}

# The inbound telemetry source kinds (LEAD tier).
AEGIS_SOURCE_KINDS: tuple[IntelSourceKind, ...] = (
    IntelSourceKind.REQUEST_TELEMETRY,
    IntelSourceKind.LLM_INTERACTION,
)


def verify_registration() -> None:
    """Fail loudly if any additive append is missing — a cheap self-check the gate test runs.
    Confirms the AEGIS classes are known, map to their oracle, and fold aliases correctly."""
    known = known_bug_classes()
    for cls, kind in AEGIS_BUG_CLASS_ORACLES.items():
        assert cls in BUG_CLASS_ORACLES, f"AEGIS class {cls!r} missing from BUG_CLASS_ORACLES"
        assert BUG_CLASS_ORACLES[cls] == (kind,), f"AEGIS class {cls!r} maps to the wrong oracle"
        assert cls in known, f"AEGIS class {cls!r} not in known_bug_classes()"
    for alias, canonical in AEGIS_ALIASES.items():
        assert normalize_bug_class(alias) == canonical, f"AEGIS alias {alias!r} does not fold to {canonical!r}"


def aegis_bug_classes() -> frozenset[str]:
    """The canonical AEGIS confirmed classes (exactly the classes AEGIS adds to the vocabulary)."""
    return frozenset(AEGIS_BUG_CLASS_ORACLES)
