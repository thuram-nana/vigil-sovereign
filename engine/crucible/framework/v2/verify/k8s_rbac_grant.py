"""
verify.k8s_rbac_grant — the confirmation seam for the E4 TIER-2 K8s dangerous-VERB / default-ServiceAccount
RBAC verb-grant oracle (BUILD-PLAN §E4·TIER-2).

The STRONGER, rule-PARSING sibling of ``verify.k8s_workload_posture`` (TIER-1, which only name-matches a
dangerous BUILT-IN ClusterRole for an ANONYMOUS subject and never parses rules). A live cluster read reports
"ClusterRoleBinding X binds a custom ClusterRole C to system:anonymous", and a SEPARATE read of C returns its
``rules``. That is a THIRD-PARTY LEAD until a deterministic oracle PROVES, over the RETAINED binding + the
SEPARATELY-retained ``role_object``, that C's parsed rules grant a dangerous (verb,resource) capability to an
attacker-occupiable subject under the subject-gated near-zero-FP rule. This module is that seam: it routes a
retained ``{binding, role_object}`` control through the pure ``k8s_rbac_verb_grant_oracle`` and returns a
re-verifiable verdict.

Two properties make this a re-verification rather than a rubber-stamp of the collector's say-so, exactly like
``verify.k8s_workload_posture`` / ``verify.cloud_posture`` / ``verify.policy_path``:

  * The control judged is the sensor's RETAINED evidence (the binding's raw subjects + roleRef AND the role's
    raw ``rules`` + ``rules_source``, NOT a boolean the collector pre-computed), so the oracle re-derives the
    roleRef->role_object JOIN and the (dangerous-shape ∧ eligible-subject) judgment independently — the
    single-most-common legitimate delegation (default/default × the built-in ``admin`` in a namespace, a
    cluster-read backup/monitoring role bound to system:authenticated) does NOT confirm (it stays a LEAD).
  * The retained control is JSON-safe and the oracle is pure, so a confirmed FACT RE-VERIFIES OFFLINE from its
    certificate (``verify.reverify``) with no cluster and no trust in the collector — re-run the parse-proof
    over the retained binding + role_object, get the same verdict, byte-for-byte.

Like ``verify.cloud_posture`` there is NO active probe and NO gate here: the "capture" is the offline,
kill-switch-gated live cluster read the sensor already ran; this is a pure re-derivation over it.
"""

from __future__ import annotations

from typing import Any, Mapping

from .adapter import FindingContext
from .models import VerificationResult
from .verifier import OracleVerifier


def k8s_rbac_grant_context(control: Mapping[str, Any]) -> dict:
    """The verifier context for a retained RBAC binding + role_object control — routes to the E4 TIER-2
    k8s_rbac_verb_grant oracle."""
    return FindingContext.from_k8s_rbac_grant_control(dict(control or {})).to_verifier_context()


def confirm_k8s_rbac_grant(
    control: Mapping[str, Any], *, verifier: OracleVerifier | None = None
) -> VerificationResult:
    """Judge a retained RBAC ``{binding, role_object}`` control with the deterministic oracle: ``confirmed``
    iff the binding's RETAINED raw subjects + roleRef and the role's RETAINED parsed ``rules`` provably grant a
    dangerous (verb,resource) capability to an attacker-occupiable subject — an ANONYMOUS subject on ANY
    dangerous shape (full-wildcard, secret-read, or priv-esc), or the namespace-default ServiceAccount /
    system:authenticated ONLY on a FULL-WILDCARD grant via a ClusterRoleBinding. The retained ``control`` is
    JSON-safe, so the same verdict re-verifies offline from the finding's certificate via ``verify.reverify``.
    A legitimate delegation — the built-in ``admin`` role's Secrets get/list/watch bound to default:default in
    a namespace, a cluster-read backup role bound to system:authenticated, a named subject, a resourceNames-
    scoped single-secret get, a broken roleRef->role_object join, or aggregated static rules — is NOT confirmed
    (it stays an honest LEAD). NO live cluster call is ever made: this is a pure re-derivation over
    already-ingested evidence."""
    return (verifier or OracleVerifier()).confirm(k8s_rbac_grant_context(control))
