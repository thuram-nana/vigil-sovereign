"""
verify — the deterministic oracle-verification layer.

A finding is confirmed when a REAL signal fires, not when a model asserts it.
This layer is the confirmation authority: it takes already-observed data and
runs pure, deterministic oracles that judge whether the claimed vulnerability
actually manifested.

Public surface (import from here, not from submodules):

    from framework.v2.verify import (
        OracleKind, OracleProbe, OracleSignal, VerificationResult,
        OracleVerifier, HIGH_CONFIDENCE,
        OOBReceiver, OOBHit,
        differential_response_oracle, achieved_state_oracle,
        side_effect_oracle, sanitizer_signal_oracle, oob_callback_oracle,
    )

The contract: `OracleVerifier.confirm(finding_context)` returns
`confirmed=True` only when >=1 oracle fired at or above HIGH_CONFIDENCE.
Absent inputs never pass — they skip. Prove, don't guess.
"""

from __future__ import annotations

from .models import (
    OracleKind,
    OracleProbe,
    OracleSignal,
    VerificationResult,
)
from .oob import OOBHit, OOBReceiver
from .oracles import (
    achieved_state_oracle,
    differential_response_oracle,
    oob_callback_oracle,
    sanitizer_signal_oracle,
    side_effect_oracle,
)
from .verifier import (
    BUG_CLASS_ORACLES,
    HIGH_CONFIDENCE,
    OracleVerifier,
    normalize_bug_class,
)

__all__ = [
    # models
    "OracleKind",
    "OracleProbe",
    "OracleSignal",
    "VerificationResult",
    # oracles
    "differential_response_oracle",
    "achieved_state_oracle",
    "side_effect_oracle",
    "sanitizer_signal_oracle",
    "oob_callback_oracle",
    # oob
    "OOBReceiver",
    "OOBHit",
    # verifier
    "OracleVerifier",
    "HIGH_CONFIDENCE",
    "BUG_CLASS_ORACLES",
    "normalize_bug_class",
]
