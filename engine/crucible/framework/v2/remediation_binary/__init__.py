"""remediation_binary — binary/memory-safety auto-patch tier scaffold (X2).

[BUILT] SanitizerSilenceTier confirms a crash + proves remediation by ORACLE SILENCE (A6a).
[research-gated] patch synthesis (symbolic/CRS engine) is a stub that raises. See remediation_binary/tier.py.
A fix is proven by silence, never asserted; the oracle is the sole authority.
"""

from __future__ import annotations

from .tier import (
    BinaryPatch,
    BinaryPatchTier,
    CapturedCrash,
    SanitizerSilenceTier,
    SymbolicCrashRepairTier,
)

__all__ = [
    "BinaryPatchTier",
    "BinaryPatch",
    "CapturedCrash",
    "SanitizerSilenceTier",
    "SymbolicCrashRepairTier",
]
