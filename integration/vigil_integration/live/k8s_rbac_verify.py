"""k8s_rbac_verify — VIGIL-owned admission / certification route for an anonymous-privileged K8s-RBAC
achieved-effect FACT (BUILD-PLAN §E4 — the LIVE-capture PRODUCER for the existing k8s_workload_posture
oracle, mirroring ``imds_verify`` / ``secret_verify``).

The confirmation oracle for E4's flagship case — an ANONYMOUS subject (system:anonymous /
system:unauthenticated) bound to a dangerous BUILT-IN ClusterRole (cluster-admin / admin / edit) — already
exists and is red-penned (``verify.oracles.k8s_workload_posture_oracle``), and already ships over the ARTIFACT
surface (``k8s_posture.ingest_k8s_rbac`` parses an operator-supplied manifest). This module is the LIVE-capture
sibling: a WARDEN-gated live RBAC-enumeration runner (a follow-on slice) produces a RETAINED, secret-safe
binding capture, and this producer routes that capture through the SAME deterministic oracle, ADMITS it against
the registered ``k8s_exploit.rbac.anonymous_privileged_binding`` evidence branch (``verdict.admit`` — a fired
oracle over a fact-capable, precondition-holding branch is a FACT, anything else a LEAD), and — on a FACT —
mints the signed D2 certificate via ``oracle_adapter.certify_admitted`` (the ONLY sanctioned mint path; a
sovereign ``live/*`` module must never call ``build_certificate`` / ``confirm_and_certify`` directly).

A confirmed FACT then re-verifies OFFLINE from its certificate (``verify.reverify`` re-fires the same oracle)
and its retained ``oracle_context`` re-executes under the veracity firewall — BOTH engage automatically (the
cert builder and the firewall are generic over any finding carrying an ``oracle_context``).

INERT on scan/engage: nothing on the scan/engage/benchmark path mints a ``k8s_workload_misconfiguration``
finding over a live binding (the oracle is kept OUT of the frozen ``_ALL_ORACLES`` fallback), so the capability
fires ONLY when this producer is called EXPLICITLY over a runner capture — preserving the no-auto-fire gate.

FATAL-2: every framework import is FUNCTION-LOCAL; at module scope this is pure stdlib only, so importing it
co-loads no offense engine (mirrors ``imds_verify`` / ``secret_verify`` / ``cloud_live_posture``). The capture
is SECRET-SAFE by construction — the retained binding carries only RBAC metadata (subject names, role, roleRef
kind/apiGroup); the kubeconfig bearer token / client-cert used to READ the cluster is fingerprinted-and-
discarded by the runner and NEVER enters the capture — so the certificate carries no live credential yet
re-verifies offline. Real-transport LIVE-FIRE (running the enumeration runner against a real cluster's
kube-apiserver) is deferred on an operator-provisioned kubeconfig.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# The registered anonymous-privileged-binding evidence branch (docs/capability-matrix/evidence-branches.json).
# fact_capable (an unauthenticated subject bound to cluster-admin is an achieved-effect FACT); clean_capable
# :false (one gated read of a subset of bindings cannot prove no anonymous-privileged binding exists cluster-
# wide — that is the k8s_workload_posture.rbac_binding POSTURE branch's target, not this exploitation branch).
_BRANCH = "k8s_exploit.rbac.anonymous_privileged_binding"


@dataclass
class K8sRbacVerifyResult:
    """The outcome of routing ONE retained RBAC-binding capture through oracle -> admission -> (on FACT)
    certificate."""

    resource_kind: str
    verdict: str = "LEAD"                 # the admitted verdict value (FACT / LEAD / INCONCLUSIVE)
    is_fact: bool = False
    reason: str = ""
    finding_ref: str = ""
    finding: "dict | None" = None         # {check_id, bug_class, oracle_context} — the re-verifiable finding
    oracle_context: "dict | None" = None  # secret-safe; the retained proof reverify / the firewall re-fire
    certificate: Any = None               # the signed AdapterResult (None unless is_fact)
    admission: "tuple | None" = None      # (branch_id, verdict, reason) — the admission trail


def _oracle_signal(oracle_context: dict) -> "tuple[bool, bool]":
    """Run the deterministic k8s_workload_posture oracle over the retained ctx and return ``(fired,
    conclusive)`` WITHOUT minting. All framework imports are function-local (FATAL-2), exactly like
    ``secret_verify`` / ``imds_verify``."""
    from framework.v2.scanner.engine import probe_verdict  # noqa: PLC0415
    from framework.v2.verify.confirmation import adjudicate_finding, confirmed_from_result  # noqa: PLC0415
    from framework.v2.verify.verifier import OracleVerifier  # noqa: PLC0415

    verifier = OracleVerifier()
    finding = {"bug_class": "k8s_workload_misconfiguration", "oracle_context": oracle_context}
    result = adjudicate_finding(finding, oracle_context, verifier)
    fired = confirmed_from_result(result, finding, verifier) is not None
    verdict, _kinds = probe_verdict(result)
    conclusive = fired or verdict == "clean"
    return fired, conclusive


def _capture_wellformed(capture: Any) -> bool:
    """The branch precondition this producer can evaluate over the capture bytes ALONE: a dict carrying a
    subjects LIST and a non-empty role. The ORACLE, not this, decides fired/conclusive (and enforces the
    typed-subject + built-in-role discrimination) — this only STRUCTURAL-gates so an unparseable / partial
    capture cannot be admitted as a FACT."""
    return (isinstance(capture, dict)
            and isinstance(capture.get("subjects"), (list, tuple))
            and bool(str(capture.get("role", "")).strip()))


def _binding(cap: dict) -> dict:
    """The D2 fields to bind into the signed cert (allowlist-filtered by oracle_adapter). Secret-safe: only
    capture-method + partial-completeness — NEVER a kubeconfig token (the runner fingerprints-and-discards it
    and it never reaches this capture). The real tamper-evidence is the automatic ``oracle_context_digest``
    binding over the retained (secret-safe) binding."""
    return {"capture_method": "live_capture:k8s-rbac", "completeness": "partial"}


def rbac_verify(capture, *, engagement_slug: str = "k8s-rbac", signers: "list | None" = None,
                seq: int = 0) -> K8sRbacVerifyResult:
    """Route a retained RBAC-binding capture through oracle -> admission -> (on FACT) signed certificate.
    Returns a :class:`K8sRbacVerifyResult`; NEVER raises on a malformed capture (it is admitted as a
    LEAD/INCONCLUSIVE, never a FACT). A returned FACT carries a signed certificate whose retained
    ``oracle_context`` re-verifies offline (``verify.reverify``) and re-executes under the veracity firewall.

    No live cluster call is ever made here — this is pure re-derivation over an already-captured, WARDEN-gated,
    SECRET-SAFE binding (the kubeconfig credential was fingerprinted-and-discarded by the runner)."""
    from framework.v2.verify.k8s_workload_posture import k8s_workload_posture_context  # noqa: PLC0415 (FATAL-2)
    from ..oracle_adapter import certify_admitted  # noqa: PLC0415 (the ONLY sanctioned mint path)
    from .verdict import admit  # noqa: PLC0415 (pure stdlib module)

    signers = signers or []
    cap = capture if isinstance(capture, dict) else {}
    resource_kind = str(cap.get("resource_kind", "") or "").strip().lower() or "rolebinding"
    res = K8sRbacVerifyResult(resource_kind=resource_kind)

    oracle_context = k8s_workload_posture_context(cap)
    res.oracle_context = oracle_context
    _name = str(cap.get("name", "") or "").strip() or "binding"
    finding = {
        "check_id": f"k8s:rbac:{resource_kind}:{_name}:anonymous_privileged_binding",
        "bug_class": "k8s_workload_misconfiguration",
        "insertion_point": f"k8s:rbac:{resource_kind}:{_name}",
        "oracle_context": oracle_context,
    }
    res.finding = finding

    fired, conclusive = _oracle_signal(oracle_context)
    observed = {"binding_wellformed": _capture_wellformed(cap)}
    admitted = admit(_BRANCH, fired=fired, conclusive=conclusive, observed=observed)
    res.admission = (_BRANCH, admitted.verdict.value, admitted.reason)
    res.verdict = admitted.verdict.value
    res.reason = admitted.reason

    out = certify_admitted(finding, admitted, engagement_slug=engagement_slug, signers=signers, seq=seq,
                           provenance="reproduced", binding=_binding(cap))
    res.finding_ref = out.finding_ref
    res.is_fact = out.is_fact
    if out.is_fact:
        res.certificate = out
    return res
