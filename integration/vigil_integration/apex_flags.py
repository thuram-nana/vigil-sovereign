"""apex_flags — the keyless, offense-plane master flag for APEX PR-3 (Impact & Closure).

Mirrors ``redpen.engine.redpen_enabled`` and ``framework.v2.apex_impact.apex_impact_enabled``: a single
default-OFF env flag, read at call time, that gates PR-3's autonomous close-the-loop capabilities in the
integration plane (the proof-carrying-remediation close-the-loop and the continuous retest scheduler). The
sovereign plane reads the SAME var via ``sigil.config.apex_impact_enabled``.

Import-clean (stdlib only), keyless — reads an env flag, never a secret (FATAL-2 clean).
"""
from __future__ import annotations

import os

APEX_IMPACT_ENV = "VIGIL_APEX_IMPACT"
_TRUTHY = frozenset({"1", "true", "yes", "on"})


def apex_impact_enabled() -> bool:
    """True iff APEX Impact & Closure is switched on (``VIGIL_APEX_IMPACT`` ∈ {1,true,yes,on}). Default OFF:
    unset / empty / any other value is OFF, and the PCR close-the-loop + the retest scheduler are then inert
    (no proposal, no PR, no certificate minted, no cadence tick). Read at call time."""
    return (os.environ.get(APEX_IMPACT_ENV) or "").strip().lower() in _TRUTHY


__all__ = ["apex_impact_enabled", "APEX_IMPACT_ENV"]
