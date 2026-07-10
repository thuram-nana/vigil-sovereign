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
    policy_path_oracle,
    sanitizer_signal_oracle,
    service_reachability_oracle,
    side_effect_oracle,
    tls_weakness_oracle,
    version_range_oracle,
)
from .policy_path import (
    build_policy_graph,
    confirm_privilege_path,
    policy_path_context,
    privilege_path_query,
)
from .reachability import capture_handshake, confirm_reachable, reachable_context
from .tls import capture_tls_handshake, confirm_weak_tls, weak_tls_context
from .version import (
    confirm_vulnerable_dependency,
    version_in_affected,
    vulnerable_dependency_context,
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
    "service_reachability_oracle",
    "tls_weakness_oracle",
    "version_range_oracle",
    "policy_path_oracle",
    # reachability
    "capture_handshake",
    "confirm_reachable",
    "reachable_context",
    # tls posture
    "capture_tls_handshake",
    "confirm_weak_tls",
    "weak_tls_context",
    # supply-chain version-range
    "confirm_vulnerable_dependency",
    "version_in_affected",
    "vulnerable_dependency_context",
    # cloud IAM privilege path
    "build_policy_graph",
    "privilege_path_query",
    "policy_path_context",
    "confirm_privilege_path",
    # oob
    "OOBReceiver",
    "OOBHit",
    # verifier
    "OracleVerifier",
    "HIGH_CONFIDENCE",
    "BUG_CLASS_ORACLES",
    "normalize_bug_class",
]
