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
from .cicd_posture import (
    cicd_posture_context,
    confirm_cicd_posture,
    confirm_workflow,
    ingest_workflow,
)
from .email_auth import (
    confirm_dns_policy,
    confirm_email_auth_posture,
    email_auth_context,
    ingest_dns_policy,
)
from .mobile_posture import (
    confirm_mobile_controls,
    confirm_mobile_posture,
    mobile_posture_context,
)
from .k8s_posture import confirm_k8s_posture, k8s_posture_context
from .cloud_posture import confirm_cloud_posture, cloud_posture_context
from .mesh_posture import (
    confirm_mesh_posture,
    mesh_posture_context,
    ingest_mesh_config,
    confirm_mesh_config,
)
from .jwt_forgery import confirm_jwt_forgery, jwt_forgery_context
from .saml_forgery import confirm_saml_forgery, saml_forgery_context
from .oracles import (
    achieved_state_oracle,
    differential_response_oracle,
    honeypot_hit_oracle,
    jwt_forgery_oracle,
    cloud_posture_oracle,
    k8s_posture_oracle,
    mesh_posture_oracle,
    mobile_posture_oracle,
    email_auth_posture_oracle,
    oob_callback_oracle,
    policy_path_oracle,
    prompt_injection_oracle,
    saml_forgery_oracle,
    sanitizer_signal_oracle,
    service_reachability_oracle,
    side_effect_oracle,
    system_prompt_disclosure_oracle,
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
from .weak_crypto import (
    confirm_crypto_descriptor,
    confirm_weak_crypto_artifact,
    crypto_descriptor_context,
    signature_descriptor,
    signature_descriptors,
    weak_crypto_context,
)
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
    "k8s_posture_oracle",
    "cloud_posture_oracle",
    "mesh_posture_oracle",
    "mobile_posture_oracle",
    "jwt_forgery_oracle",
    "saml_forgery_oracle",
    # AEGIS (defensive dual) oracles
    "system_prompt_disclosure_oracle",
    "prompt_injection_oracle",
    "honeypot_hit_oracle",
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
    # k8s posture (kube-bench CIS-control-failure promotion)
    "confirm_k8s_posture",
    "k8s_posture_context",
    # cloud/CSPM posture (achieved-state promotion; Wave-F1)
    "confirm_cloud_posture",
    "cloud_posture_context",
    # service-mesh posture (achieved-state promotion + minimal offline ingestion; Wave-G3)
    "confirm_mesh_posture",
    "mesh_posture_context",
    "ingest_mesh_config",
    "confirm_mesh_config",
    # mobile static-posture (embedded private-key promotion; Phase-2)
    "confirm_mobile_posture",
    "mobile_posture_context",
    "confirm_mobile_controls",
    # SSO/JWT structural-forgery (Workstream-B)
    "confirm_jwt_forgery",
    "jwt_forgery_context",
    # SAML structural-forgery (Workstream NW-1)
    "confirm_saml_forgery",
    "saml_forgery_context",
    # oob
    "OOBReceiver",
    "OOBHit",
    # verifier
    "OracleVerifier",
    "HIGH_CONFIDENCE",
    "BUG_CLASS_ORACLES",
    "normalize_bug_class",
]
