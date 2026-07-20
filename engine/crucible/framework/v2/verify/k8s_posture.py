"""
verify.k8s_posture — the confirmation seam for the k8s-posture oracle (Workstream 3).

The Kubernetes-runtime half of prove-don't-guess. A kube-bench CIS checker reports "control 1.2.1
(anonymous-auth) FAILED". That is a THIRD-PARTY LEAD (``sensors.k8s_runtime`` mints it as
``GROUNDING_INTEL``) — a `fact` only when a deterministic oracle proves a CONCRETE insecure setting
over the RETAINED control. This module is that seam: it routes a retained control through the pure
``k8s_posture_oracle`` and returns a re-verifiable verdict.

Two properties make this a re-verification rather than a rubber-stamp of the scanner's say-so, exactly
like ``verify.version`` / ``verify.policy_path``:

  * The control judged is the sensor's RETAINED evidence (the CIS-control lead's ``check_id`` / ``status``
    / ``actual_value``), NOT a re-run of kube-bench laundered into a fact. The lead says "FAIL"; the
    oracle re-derives the weakness from the observed value and fires only when it literally carries a
    dangerous flag (a benign/passing control does not confirm).
  * The retained control is JSON-safe and the oracle is pure, so a confirmed k8s-posture FACT
    RE-VERIFIES OFFLINE from its certificate (``verify.reverify``) with no cluster and no trust in the
    scanner — re-run the parse-proof over the retained control, get the same verdict, byte-for-byte.

Like ``verify.policy_path`` there is NO active probe and NO gate here: the "capture" is the offline,
kill-switch-gated kube-bench ingest the sensor already ran; this is a pure re-derivation over it.
"""

from __future__ import annotations

from typing import Any, Mapping

from .adapter import FindingContext
from .models import VerificationResult
from .verifier import OracleVerifier


def k8s_posture_context(control: Mapping[str, Any]) -> dict:
    """The verifier context for a retained kube-bench control — routes to the k8s-posture oracle."""
    return FindingContext.from_k8s_posture(dict(control or {})).to_verifier_context()


def confirm_k8s_posture(control: Mapping[str, Any], *, verifier: OracleVerifier | None = None) -> VerificationResult:
    """Judge a retained kube-bench control with the deterministic oracle: ``confirmed`` iff the control
    hard-FAILED AND its observed value provably carries a dangerous insecure setting. The retained
    ``control`` is JSON-safe, so the same verdict re-verifies offline from the finding's certificate via
    ``verify.reverify``. A passing/benign control — or a FAIL with no captured value — is NOT confirmed
    (it stays an honest LEAD)."""
    return (verifier or OracleVerifier()).confirm(k8s_posture_context(control))
