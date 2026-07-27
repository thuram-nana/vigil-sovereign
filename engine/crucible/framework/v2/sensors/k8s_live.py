"""
sensors.k8s_live — LIVE, read-only Kubernetes RBAC posture as a gated SENSOR (Phase C2 · K8s).

The Kubernetes twin of the cloud live collectors. Where ``sensors.k8s_runtime.KubeBenchSensor`` ingests an
operator kube-bench ``--json`` export offline (control-plane CLI-flag CIS controls), this collector reads the
LIVE cluster RBAC READ-ONLY via the kubernetes client and mints binding LEADS that a NEW deterministic oracle
(``verify.oracles.k8s_workload_posture_oracle``) promotes to a FACT.

WHY RBAC-only, and WHY only this one FACT (near-zero-FP the hard way — the first cut over-promoted and was
BLOCKed): almost every "insecure-looking" k8s workload state is LEGITIMATE on a real cluster. Privileged /
host-network pods are used BY DESIGN by hardened system components (kube-proxy, CNI, CSI drivers) on every
cluster, so they are LEADS, not facts. Binding ``system:unauthenticated`` is also NOT per se insecure — every
cluster ships the built-in ``system:public-info-viewer`` binding to it (read-only /healthz, /version). The ONE
unambiguous, near-zero-FP CRITICAL fact is an ANONYMOUS subject (system:anonymous / system:unauthenticated)
bound to a genuinely DANGEROUS built-in role (cluster-admin / admin / edit) — anonymous WRITE/admin access,
which no cluster ships by default. The oracle re-derives THAT over the RAW retained subjects + role. Privileged
/ host-network / anonymous-binding-to-a-non-dangerous-role are deferred (future namespace-filtered leads).

Doctrine (identical to the cloud live collectors):
  * PROVE-DON'T-GUESS / ORACLE AUTHORITY. The collector mints only RBAC-binding LEADS (``GROUNDING_INTEL``)
    carrying the RAW subjects + role. A LEAD becomes a FACT only when ``k8s_workload_posture_oracle``
    re-derives, over that raw evidence, that an anonymous subject holds a dangerous built-in role — never
    because a live cluster call said so, and never a rubber-stamp of a boolean the collector pre-decided.
  * AMBIENT CREDENTIALS, NEVER HANDED OVER. The kubeconfig comes from the offense bridge's materialised
    ``KUBECONFIG`` (the operator sealed it in the Cloud-credentials plane), the default ``~/.kube/config``, or
    an IN-CLUSTER ServiceAccount. No secret is passed through args, argv, or the spine. No config ⇒ no-op.
  * GATED, FAIL-CLOSED, DECLARED == ACTUAL EGRESS. Tier-2 / ``ACTIVE_RECON``: the engagement must be entitled,
    and the cluster apiserver host is declared in ``egress_hosts`` (the operator provisions it in
    ``targets/<slug>/collector-hosts.txt`` — C1). BECAUSE the egress gate is skipped for an empty
    ``egress_hosts``, ``run`` ALSO refuses fail-closed unless the apiserver host it actually loaded is one it
    declared — so an ambient/default kubeconfig can never drive an UN-gated, out-of-scope cluster read.
  * READ-ONLY. Only ``list`` calls (``list_cluster_role_binding`` / ``list_role_binding_for_all_namespaces``).
  * DETERMINISM OF THE CORE. The response → control translation is a PURE, total, CI-tested function.
"""

from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlsplit

from ..agents.tools import ToolContext, ToolResult
from ..entitlement.models import Capability
from ..intel.models import Credibility, IntelSourceKind, Observation, Reliability, SourceReliability
from ..intel.refs import EntityRef
from ..worldmodel.models import NodeKind

# RBAC subjects that denote an UNAUTHENTICATED caller.
_ANON_SUBJECTS = frozenset({"system:anonymous", "system:unauthenticated"})
# The built-in read-only binding to system:unauthenticated present in EVERY cluster — benign, never a control.
_BENIGN_ANON_ROLES = frozenset({"system:public-info-viewer"})
_K8S_LIVE_RELIABILITY = SourceReliability(reliability=Reliability.B, credibility=Credibility.C2)


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


# ---------------------------------------------------------------------------
# pure translation: reduced read-only RBAC responses -> binding control LEADS
# (no SDK, no network — the deterministic, CI-tested core the oracle consumes)
# ---------------------------------------------------------------------------


def _binding_controls(bindings: Any) -> list[dict]:
    """One control per RBAC binding that grants a role to an ANONYMOUS subject — EXCEPT the benign built-in
    ``system:public-info-viewer`` binding (present in every cluster). ``bindings`` is the reduced read:
    ``[{"name", "namespace"?, "role"?, "subjects": ["system:anonymous", …]}]``. The RAW subjects + role ride
    in ``achieved_state`` so the oracle re-derives (anonymous ∧ dangerous-role) independently — the collector
    does NOT pre-decide 'insecure'. Total: odd entries skipped."""
    out: list[dict] = []
    if not isinstance(bindings, (list, tuple)):
        return out
    for b in bindings:
        if not isinstance(b, dict):
            continue
        name = str(b.get("name") or "").strip()
        if not name:
            continue
        subjects = b.get("subjects")
        subjects = [str(s) for s in subjects] if isinstance(subjects, (list, tuple)) else []
        role = str(b.get("role") or "")
        has_anon = any(_norm(s) in _ANON_SUBJECTS for s in subjects)
        if not has_anon or _norm(role) in _BENIGN_ANON_ROLES:
            continue                                    # not anonymous, or the benign default → no control
        ns = str(b.get("namespace") or "").strip()
        out.append({"check_id": f"binding:{ns}/{name}", "resource_kind": "rolebinding", "name": name,
                    "namespace": ns, "achieved_state": {"subjects": subjects, "role": role}})
    return out


def k8s_workload_controls(*, bindings: Any = ()) -> list[dict]:
    """The retained RBAC-binding controls a LIVE cluster read implies — the deterministic core the oracle
    promotes. PURE + total. Only anonymous-subject bindings (minus the benign default) are emitted; the
    oracle decides which are CRITICAL (anonymous ∧ dangerous-role)."""
    return _binding_controls(bindings)


def k8s_workload_observations(controls: list[dict], *, seq: int, source: str = "k8s_live") -> list[Observation]:
    """Mint a CONTROL observation per RBAC-binding control — a LEAD (``GROUNDING_INTEL``), never a confirmed
    weakness (the oracle re-derives the FACT over the retained raw subjects + role). Keyed
    ``k8s-workload:<check_id>``; claim-keyed ``obs_id`` -> re-ingest/dedup collapse to one; PURE. Mirrors
    ``kube_bench_observations``."""
    out: list[Observation] = []
    seen: set[str] = set()
    for c in controls:
        if not isinstance(c, dict):
            continue
        check_id = str(c.get("check_id") or "").strip()
        if not check_id:
            continue
        key = f"k8s-workload:{check_id}".lower()
        if key in seen:
            continue
        seen.add(key)
        ref = EntityRef(kind=NodeKind.CONTROL, key=key)
        state = c.get("achieved_state") if isinstance(c.get("achieved_state"), dict) else {}
        anon = [s for s in (state.get("subjects") or []) if _norm(s) in _ANON_SUBJECTS]
        out.append(Observation(
            obs_id=f"{source}:{seq}:{ref.node_id}||",
            source=source, source_kind=IntelSourceKind.CLOUD_POSTURE, collector=source,
            subject=ref, relation=None, object=None,
            attrs={k: v for k, v in {
                "check_id": check_id,
                "resource_kind": c.get("resource_kind") or None,
                "namespace": c.get("namespace") or None,
                "role": state.get("role") or None,
                "anonymous_subject": (anon[0] if anon else None),
                "benchmark": "k8s-rbac",
            }.items() if v},
            source_reliability=_K8S_LIVE_RELIABILITY, confidence=0.7, seq=seq))
    return out


# ---------------------------------------------------------------------------
# the live sensor
# ---------------------------------------------------------------------------


def _kubeconfig_server_host(path: str) -> str:
    """The current-context cluster's server hostname from a kubeconfig FILE. "" if indeterminate. Total."""
    if not path or not os.path.isfile(path):
        return ""
    try:
        import yaml
        doc = yaml.safe_load(open(path, encoding="utf-8").read())
    except Exception:
        return ""
    if not isinstance(doc, dict):
        return ""
    current = doc.get("current-context")
    ctxs = {c.get("name"): c for c in (doc.get("contexts") or []) if isinstance(c, dict)}
    cluster_name = (ctxs.get(current, {}).get("context", {}) or {}).get("cluster") if current else None
    for c in doc.get("clusters") or []:
        if isinstance(c, dict) and (cluster_name is None or c.get("name") == cluster_name):
            h = urlsplit(str((c.get("cluster", {}) or {}).get("server", "") or "")).hostname or ""
            if h:
                return h
    return ""


def _apiserver_host() -> str:
    """The cluster apiserver host the collector will reach — from the in-cluster env
    (``KUBERNETES_SERVICE_HOST``), the FIRST path of a (possibly colon-multi-path) ``$KUBECONFIG``, or the
    default ``~/.kube/config`` the kubernetes client falls back to. "" if indeterminate. Best-effort + total."""
    host = str(os.environ.get("KUBERNETES_SERVICE_HOST") or "").strip()
    if host:
        return host
    kubeconfig = str(os.environ.get("KUBECONFIG") or "").strip()
    for path in ([p for p in kubeconfig.split(os.pathsep) if p]
                 or [os.path.expanduser("~/.kube/config")]):
        h = _kubeconfig_server_host(path)
        if h:
            return h
    return ""


class K8sLiveSensor:
    """Live, read-only Kubernetes RBAC posture collector (Tier-2, ``ACTIVE_RECON``). Loads the ambient
    kubeconfig (materialised ``KUBECONFIG`` / default ``~/.kube/config``) or an in-cluster ServiceAccount,
    lists RBAC bindings READ-ONLY, and emits anonymous-subject binding controls as ``{"controls": [...]}``.
    Fail-closed no-op when the kubernetes client is absent, no cluster config is discoverable, OR the
    apiserver host it loads was not the declared/provisioned egress host."""

    name = "k8s_live"
    tier = "T2"
    capability = Capability.ACTIVE_RECON
    destructive = False

    _MAX_BINDINGS = 5000

    def __init__(self) -> None:
        host = _apiserver_host()
        self.egress_hosts: tuple[str, ...] = (host,) if host else ()

    @staticmethod
    def _safe(fn: Any, default: Any = None) -> Any:
        try:
            return fn()
        except Exception:
            return default

    def _reduce_bindings(self, rbac_v1: Any) -> list[dict]:
        out: list[dict] = []
        for lister in (lambda: rbac_v1.list_cluster_role_binding(),
                       lambda: rbac_v1.list_role_binding_for_all_namespaces()):
            obj = self._safe(lister)
            for b in (getattr(obj, "items", None) or [])[: self._MAX_BINDINGS]:
                meta = getattr(b, "metadata", None)
                name = str(getattr(meta, "name", "") or "").strip()
                if not name:
                    continue
                subjects = [str(getattr(s, "name", "") or "") for s in (getattr(b, "subjects", None) or [])]
                role = str(getattr(getattr(b, "role_ref", None), "name", "") or "")
                out.append({"name": name, "namespace": str(getattr(meta, "namespace", "") or ""),
                            "role": role, "subjects": subjects})
        return out

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        try:
            from kubernetes import client, config  # optional dependency
        except Exception:
            return ToolResult(ok=False, note=(
                "k8s_live: the kubernetes client is not installed — live cluster collection unavailable "
                "(fail-closed no-op). `pip install kubernetes` to enable."))
        loaded = False
        try:
            config.load_incluster_config()
            loaded = True
        except Exception:
            try:
                config.load_kube_config()
                loaded = True
            except Exception:
                loaded = False
        if not loaded:
            return ToolResult(ok=False, note=(
                "k8s_live: no cluster config discoverable (in-cluster ServiceAccount or a KUBECONFIG) — "
                "fail-closed no-op. Seal a kubeconfig in the Cloud-credentials plane, or run in-cluster."))
        # DECLARED == ACTUAL egress, fail-closed: the egress gate is skipped for an empty egress_hosts, so
        # verify HERE that the apiserver we actually loaded is the host we declared (and the operator
        # provisioned). An ambient/default kubeconfig pointing at an un-declared cluster is REFUSED.
        actual_host = self._safe(
            lambda: urlsplit(str(client.Configuration.get_default_copy().host or "")).hostname) or ""
        if not self.egress_hosts or actual_host not in self.egress_hosts:
            return ToolResult(ok=False, note=(
                f"k8s_live: the loaded cluster apiserver {actual_host or '?'!r} was not the declared egress "
                f"host {self.egress_hosts or '()'} — fail-closed. Provision the apiserver host in "
                f"targets/<slug>/collector-hosts.txt so the read is in scope."))
        bindings = self._safe(lambda: self._reduce_bindings(client.RbacAuthorizationV1Api()), [])
        controls = k8s_workload_controls(bindings=bindings)
        return ToolResult(
            ok=True,
            summary=f"k8s_live: cluster {actual_host} — {len(controls)} anonymous-subject RBAC binding(s) (read-only)",
            output={"controls": controls, "provider": "kubernetes", "apiserver": actual_host})

    def normalize(self, result: ToolResult, ctx: ToolContext, *, seq: int) -> list[Observation]:
        out = result.output or {}
        controls = out.get("controls")
        if not isinstance(controls, list) or not controls:
            return []
        return k8s_workload_observations(controls, seq=seq)
