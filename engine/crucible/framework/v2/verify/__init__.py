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

import importlib
from typing import TYPE_CHECKING, Any

# EAGER — the offense-free deterministic DETECTION CORE.
#
# ``models`` (value types), ``oracles`` (pure judge functions over already-observed evidence; stdlib +
# ``models`` only) and ``verifier`` (the ``OracleVerifier`` + ``BUG_CLASS_ORACLES`` dispatch) carry no
# network, no capture and no attack machinery, and the AEGIS defensive gateway's inline inspector reaches
# them directly. They stay EAGER so every ``from framework.v2.verify import <oracle>`` / ``OracleVerifier``
# call site keeps its exact types and behaviour, and ``make gate`` stays byte-identical.
from .models import (
    OracleKind,
    OracleProbe,
    OracleSignal,
    VerificationResult,
)
from .oracles import (
    achieved_state_oracle,
    anonymous_reachable_oracle,
    differential_response_oracle,
    exposed_secret_validity_oracle,
    gcp_sa_impersonation_oracle,
    honeypot_hit_oracle,
    iam_escalation_oracle,
    imds_credential_capture_oracle,
    jwt_forgery_oracle,
    cloud_posture_oracle,
    k8s_posture_oracle,
    k8s_workload_posture_oracle,
    k8s_rbac_verb_grant_oracle,
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
from .verifier import (
    BUG_CLASS_ORACLES,
    HIGH_CONFIDENCE,
    OracleVerifier,
    normalize_bug_class,
)

# ---------------------------------------------------------------------------
# AS-28 (closure + image, D34): LAZY re-export of the ACTIVE-OFFENSE / posture / capture surface.
#
# Importing this package used to EAGERLY load the WHOLE verify/ tree — including the modules that bind
# sockets and run OOB servers (``oob``, ``dns_collector``), do live active recon (``reachability``,
# ``reachability_cloud``, ``tls``), capture credentials off a live target (``imds_capture``,
# ``secret_capture``, ``gcp_impersonation_capture``, ``iam_escalation_capture``, ``k8s_rbac_grant``) or
# forge tokens (``jwt_forgery``, ``saml_forgery``). Any importer of ANY verify submodule — including the
# AEGIS DEFENSIVE gateway's ``from ..verify.adapter import FindingContext`` — ran this __init__ and so
# dragged that offensive machinery into its process image. That is the "offense code in the defense
# runtime" HIGH finding (plan §1, defect #9; threats T-7 / K13).
#
# These names now resolve via PEP 562 ``__getattr__`` on first access (then cached in ``globals()``) to
# the SAME object a direct ``from .<sub> import <name>`` yields — the public surface and behaviour are
# unchanged; only the TIMING of each submodule's import moves from "at package import" to "on first use".
# The defense gateway's import closure no longer reaches the active-offense submodules (proved by
# ``framework/v2/aegis/closure.py`` + ``aegis/tests/test_saas_closure.py``).
# ---------------------------------------------------------------------------

_LAZY_SYMBOLS: dict[str, str] = {
    "DNSCollector": "dns_collector",
    "OOBHit": "oob",
    "OOBReceiver": "oob",
    "anonymous_capture_context": "reachability_cloud",
    "azure_blob_url": "reachability_cloud",
    "build_policy_graph": "policy_path",
    "capture_anonymous_get": "reachability_cloud",
    "capture_handshake": "reachability",
    "capture_tls_handshake": "tls",
    "cicd_posture_context": "cicd_posture",
    "cloud_posture_context": "cloud_posture",
    "confirm_anonymous_reachable": "reachability_cloud",
    "confirm_cicd_posture": "cicd_posture",
    "confirm_cloud_posture": "cloud_posture",
    "confirm_crypto_descriptor": "weak_crypto",
    "confirm_dns_policy": "email_auth",
    "confirm_email_auth_posture": "email_auth",
    "confirm_gcp_impersonation_capture": "gcp_impersonation_capture",
    "confirm_iam_escalation_capture": "iam_escalation_capture",
    "confirm_identity_export": "identity_posture",
    "confirm_identity_posture": "identity_posture",
    "confirm_imds_capture": "imds_capture",
    "confirm_jwt_forgery": "jwt_forgery",
    "confirm_k8s_posture": "k8s_posture",
    "confirm_k8s_rbac_grant": "k8s_rbac_grant",
    "confirm_k8s_workload_posture": "k8s_workload_posture",
    "confirm_mesh_config": "mesh_posture",
    "confirm_mesh_posture": "mesh_posture",
    "confirm_mobile_controls": "mobile_posture",
    "confirm_mobile_posture": "mobile_posture",
    "confirm_privilege_path": "policy_path",
    "confirm_reachable": "reachability",
    "confirm_saml_forgery": "saml_forgery",
    "confirm_secret_capture": "secret_capture",
    "confirm_vulnerable_dependency": "version",
    "confirm_weak_crypto_artifact": "weak_crypto",
    "confirm_weak_tls": "tls",
    "confirm_workflow": "cicd_posture",
    "crypto_descriptor_context": "weak_crypto",
    "email_auth_context": "email_auth",
    "gcp_impersonation_capture_context": "gcp_impersonation_capture",
    "gcs_public_url": "reachability_cloud",
    "iam_escalation_capture_context": "iam_escalation_capture",
    "identity_posture_context": "identity_posture",
    "imds_capture_context": "imds_capture",
    "ingest_dns_policy": "email_auth",
    "ingest_identity_export": "identity_posture",
    "ingest_mesh_config": "mesh_posture",
    "ingest_workflow": "cicd_posture",
    "jwt_forgery_context": "jwt_forgery",
    "k8s_posture_context": "k8s_posture",
    "k8s_rbac_grant_context": "k8s_rbac_grant",
    "k8s_workload_posture_context": "k8s_workload_posture",
    "mesh_posture_context": "mesh_posture",
    "mobile_posture_context": "mobile_posture",
    "policy_path_context": "policy_path",
    "privilege_path_query": "policy_path",
    "reachable_context": "reachability",
    "s3_public_url": "reachability_cloud",
    "saml_forgery_context": "saml_forgery",
    "secret_capture_context": "secret_capture",
    "sign_oob_receipt": "oob",
    "signature_descriptor": "weak_crypto",
    "signature_descriptors": "weak_crypto",
    "verify_oob_receipt": "oob",
    "version_in_affected": "version",
    "vulnerable_dependency_context": "version",
    "weak_crypto_context": "weak_crypto",
    "weak_tls_context": "tls",
}

# Direct ``framework.v2.verify.<submodule>`` attribute access also resolves lazily (a submodule becomes a
# real package attribute once imported anywhere; until then, __getattr__ imports it on demand). The set is
# every verify/*.py module name, so ``verify.confirmation`` / ``verify.adapter`` / ``verify.reverify`` etc.
# keep working as attributes even though this __init__ no longer imports them.
_SUBMODULES: frozenset[str] = frozenset({
    "adapter", "cicd_posture", "client_side_posture", "cloud_posture", "collaborator",
    "collaborator_cli", "confirmation", "coverage_oracle", "dns_collector", "drift",
    "email_auth", "gcp_impersonation_capture", "iam_escalation_capture", "identity_posture",
    "imds_capture", "jwt_forgery", "k8s_posture", "k8s_rbac_grant", "k8s_workload_posture",
    "mesh_posture", "mobile_posture", "models", "oob", "oracle_version", "oracles",
    "plan_integrity", "poc_translate", "policy_path", "reachability", "reachability_cloud",
    "replay_harness", "reverify", "saml_forgery", "secret_capture", "tls", "verifier",
    "version", "weak_crypto",
})


def __getattr__(name: str) -> Any:
    """PEP 562 lazy loader. Resolve a re-exported symbol, or a verify submodule, on first access —
    caching it in ``globals()`` so this runs at most once per name — and FAIL CLOSED (``AttributeError``)
    for anything unknown, so a typo never silently returns ``None``."""
    sub = _LAZY_SYMBOLS.get(name)
    if sub is not None:
        value = getattr(importlib.import_module(f".{sub}", __name__), name)
        globals()[name] = value  # cache: __getattr__ is not invoked again for this name
        return value
    if name in _SUBMODULES:
        module = importlib.import_module(f".{name}", __name__)
        globals()[name] = module
        return module
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(_LAZY_SYMBOLS) | set(_SUBMODULES))


if TYPE_CHECKING:  # mypy sees the real, fully-typed surface; at runtime these resolve lazily via __getattr__.
    from .cicd_posture import cicd_posture_context as cicd_posture_context, confirm_cicd_posture as confirm_cicd_posture, confirm_workflow as confirm_workflow, ingest_workflow as ingest_workflow
    from .cloud_posture import cloud_posture_context as cloud_posture_context, confirm_cloud_posture as confirm_cloud_posture
    from .dns_collector import DNSCollector as DNSCollector
    from .email_auth import confirm_dns_policy as confirm_dns_policy, confirm_email_auth_posture as confirm_email_auth_posture, email_auth_context as email_auth_context, ingest_dns_policy as ingest_dns_policy
    from .gcp_impersonation_capture import confirm_gcp_impersonation_capture as confirm_gcp_impersonation_capture, gcp_impersonation_capture_context as gcp_impersonation_capture_context
    from .iam_escalation_capture import confirm_iam_escalation_capture as confirm_iam_escalation_capture, iam_escalation_capture_context as iam_escalation_capture_context
    from .identity_posture import confirm_identity_export as confirm_identity_export, confirm_identity_posture as confirm_identity_posture, identity_posture_context as identity_posture_context, ingest_identity_export as ingest_identity_export
    from .imds_capture import confirm_imds_capture as confirm_imds_capture, imds_capture_context as imds_capture_context
    from .jwt_forgery import confirm_jwt_forgery as confirm_jwt_forgery, jwt_forgery_context as jwt_forgery_context
    from .k8s_posture import confirm_k8s_posture as confirm_k8s_posture, k8s_posture_context as k8s_posture_context
    from .k8s_rbac_grant import confirm_k8s_rbac_grant as confirm_k8s_rbac_grant, k8s_rbac_grant_context as k8s_rbac_grant_context
    from .k8s_workload_posture import confirm_k8s_workload_posture as confirm_k8s_workload_posture, k8s_workload_posture_context as k8s_workload_posture_context
    from .mesh_posture import confirm_mesh_config as confirm_mesh_config, confirm_mesh_posture as confirm_mesh_posture, ingest_mesh_config as ingest_mesh_config, mesh_posture_context as mesh_posture_context
    from .mobile_posture import confirm_mobile_controls as confirm_mobile_controls, confirm_mobile_posture as confirm_mobile_posture, mobile_posture_context as mobile_posture_context
    from .oob import OOBHit as OOBHit, OOBReceiver as OOBReceiver, sign_oob_receipt as sign_oob_receipt, verify_oob_receipt as verify_oob_receipt
    from .policy_path import build_policy_graph as build_policy_graph, confirm_privilege_path as confirm_privilege_path, policy_path_context as policy_path_context, privilege_path_query as privilege_path_query
    from .reachability import capture_handshake as capture_handshake, confirm_reachable as confirm_reachable, reachable_context as reachable_context
    from .reachability_cloud import anonymous_capture_context as anonymous_capture_context, azure_blob_url as azure_blob_url, capture_anonymous_get as capture_anonymous_get, confirm_anonymous_reachable as confirm_anonymous_reachable, gcs_public_url as gcs_public_url, s3_public_url as s3_public_url
    from .saml_forgery import confirm_saml_forgery as confirm_saml_forgery, saml_forgery_context as saml_forgery_context
    from .secret_capture import confirm_secret_capture as confirm_secret_capture, secret_capture_context as secret_capture_context
    from .tls import capture_tls_handshake as capture_tls_handshake, confirm_weak_tls as confirm_weak_tls, weak_tls_context as weak_tls_context
    from .version import confirm_vulnerable_dependency as confirm_vulnerable_dependency, version_in_affected as version_in_affected, vulnerable_dependency_context as vulnerable_dependency_context
    from .weak_crypto import confirm_crypto_descriptor as confirm_crypto_descriptor, confirm_weak_crypto_artifact as confirm_weak_crypto_artifact, crypto_descriptor_context as crypto_descriptor_context, signature_descriptor as signature_descriptor, signature_descriptors as signature_descriptors, weak_crypto_context as weak_crypto_context

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
    "anonymous_reachable_oracle",
    "tls_weakness_oracle",
    "version_range_oracle",
    "policy_path_oracle",
    "k8s_posture_oracle",
    "k8s_workload_posture_oracle",
    "k8s_rbac_verb_grant_oracle",
    "cloud_posture_oracle",
    "mesh_posture_oracle",
    "mobile_posture_oracle",
    "jwt_forgery_oracle",
    "saml_forgery_oracle",
    "imds_credential_capture_oracle",
    "exposed_secret_validity_oracle",
    "gcp_sa_impersonation_oracle",
    "iam_escalation_oracle",
    # AEGIS (defensive dual) oracles
    "system_prompt_disclosure_oracle",
    "prompt_injection_oracle",
    "honeypot_hit_oracle",
    # reachability
    "capture_handshake",
    "confirm_reachable",
    "reachable_context",
    # active exposure (anonymous reachability of a public cloud resource)
    "capture_anonymous_get",
    "confirm_anonymous_reachable",
    "anonymous_capture_context",
    "s3_public_url",
    "gcs_public_url",
    "azure_blob_url",
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
    # k8s workload posture (live-cluster RBAC achieved-state promotion; C2·K8s)
    "confirm_k8s_workload_posture",
    "k8s_workload_posture_context",
    # k8s RBAC verb-grant (E4 TIER-2: rule-parsing dangerous-verb / default-SA grant confirmation)
    "confirm_k8s_rbac_grant",
    "k8s_rbac_grant_context",
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
    # E1 IMDS/metadata credential-capture (exploitation-chain achieved-effect confirmation; BUILD-PLAN §E1)
    "confirm_imds_capture",
    "imds_capture_context",
    # E5 exposed-secret validity (achieved-effect confirmation; BUILD-PLAN §E5)
    "confirm_secret_capture",
    "secret_capture_context",
    # E3 GCP service-account impersonation (achieved-effect confirmation; BUILD-PLAN §E3)
    "confirm_gcp_impersonation_capture",
    "gcp_impersonation_capture_context",
    # E2 IAM privilege-escalation PRIMITIVE (achieved-escalation confirmation; BUILD-PLAN §E2)
    "confirm_iam_escalation_capture",
    "iam_escalation_capture_context",
    # oob
    "OOBReceiver",
    "OOBHit",
    "sign_oob_receipt",
    "verify_oob_receipt",
    "DNSCollector",
    # verifier
    "OracleVerifier",
    "HIGH_CONFIDENCE",
    "BUG_CLASS_ORACLES",
    "normalize_bug_class",
]
