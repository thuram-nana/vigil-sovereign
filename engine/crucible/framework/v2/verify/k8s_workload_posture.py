"""
verify.k8s_workload_posture — the confirmation seam for the live-cluster k8s-RBAC posture oracle (C2·K8s).

The Kubernetes-RBAC achieved-state half of prove-don't-guess, and the LIVE-cluster sibling of
``verify.k8s_posture`` (which judges kube-bench control-plane CLI flags) / the RBAC twin of
``verify.cloud_posture``. A live cluster read reports "RoleBinding X binds cluster-admin to
system:anonymous". That is a THIRD-PARTY LEAD (``sensors.k8s_live`` mints it as ``GROUNDING_INTEL``) — a
`fact` only when a deterministic oracle proves a CONCRETE insecure achieved state over the RETAINED
binding. This module is that seam: it routes a retained RBAC-binding control through the pure
``k8s_workload_posture_oracle`` and returns a re-verifiable verdict.

Two properties make this a re-verification rather than a rubber-stamp of the collector's say-so, exactly
like ``verify.k8s_posture`` / ``verify.cloud_posture`` / ``verify.policy_path``:

  * The control judged is the sensor's RETAINED evidence (the binding's RAW ``subjects`` list + ``role``,
    NOT a boolean the collector pre-computed), so the oracle re-derives (anonymous ∧ dangerous-built-in-role)
    independently — a benign binding (the built-in ``system:public-info-viewer``, an anonymous binding to a
    non-dangerous/custom role, a binding with no anonymous subject) does NOT confirm.
  * The retained control is JSON-safe and the oracle is pure, so a confirmed k8s-workload-posture FACT
    RE-VERIFIES OFFLINE from its certificate (``verify.reverify``) with no cluster and no trust in the
    collector — re-run the membership-proof over the retained binding, get the same verdict, byte-for-byte.

Like ``verify.cloud_posture`` there is NO active probe and NO gate here: the "capture" is the offline,
kill-switch-gated live cluster read the sensor already ran; this is a pure re-derivation over it.
"""

from __future__ import annotations

from typing import Any, Mapping

from .adapter import FindingContext
from .models import VerificationResult
from .verifier import OracleVerifier


def k8s_workload_posture_context(control: Mapping[str, Any]) -> dict:
    """The verifier context for a retained live RBAC-binding control — routes to the k8s-workload-posture
    oracle."""
    return FindingContext.from_k8s_workload_control(dict(control or {})).to_verifier_context()


def confirm_k8s_workload_posture(
    control: Mapping[str, Any], *, verifier: OracleVerifier | None = None
) -> VerificationResult:
    """Judge a retained live RBAC-binding control with the deterministic oracle: ``confirmed`` iff the
    binding's RETAINED raw subjects + role provably grant a genuinely DANGEROUS built-in ClusterRole
    (cluster-admin / admin / edit) to an ANONYMOUS subject (system:anonymous / system:unauthenticated) —
    unauthenticated write/admin access no cluster ships by default. The retained ``control`` is JSON-safe,
    so the same verdict re-verifies offline from the finding's certificate via ``verify.reverify``. A benign
    binding — the built-in ``system:public-info-viewer``, an anonymous binding to a non-dangerous/custom
    role, or a binding with no anonymous subject — is NOT confirmed (it stays an honest LEAD). NO live
    cluster call is ever made: this is a pure re-derivation over already-ingested evidence."""
    return (verifier or OracleVerifier()).confirm(k8s_workload_posture_context(control))
