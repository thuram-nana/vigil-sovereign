"""
sensors.k8s_live — LIVE, read-only Kubernetes workload/RBAC posture as a gated SENSOR (Phase C2 · K8s).

The Kubernetes twin of the cloud live collectors. Where ``sensors.k8s_runtime.KubeBenchSensor`` ingests an
operator kube-bench ``--json`` export offline (control-plane CLI-flag CIS controls), this collector reads the
LIVE cluster READ-ONLY via the kubernetes client and mints WORKLOAD/RBAC achieved-state control LEADS that a
NEW deterministic oracle (``verify.oracles.k8s_workload_posture_oracle``) promotes to FACTs. A live pod/binding
does NOT carry kube-bench's CLI flags, so the existing ``k8s_posture_oracle`` cannot judge it — hence the new
achieved-state oracle (modelled on ``cloud_posture_oracle``), which fires ONLY on an EXPLICIT insecure state.

Doctrine (identical to the cloud live collectors):
  * PROVE-DON'T-GUESS / ORACLE AUTHORITY. The collector mints only CONTROL LEADS (``GROUNDING_INTEL``). A LEAD
    becomes a FACT only when the deterministic ``k8s_workload_posture_oracle`` re-fires over the RETAINED
    control's achieved state — never because a live cluster call said so. Only an EXPLICIT insecure achieved
    state is emitted AND confirmed (a privileged container / a host-network pod / an RBAC binding to an
    anonymous subject), so a benign workload mints nothing (near-zero-FP by construction).
  * AMBIENT CREDENTIALS, NEVER HANDED OVER. The kubeconfig comes from the offense bridge's materialised
    ``KUBECONFIG`` (the operator sealed it in the Cloud-credentials plane) or an IN-CLUSTER ServiceAccount
    token. No secret is passed through args, argv, or the spine. No config ⇒ a clean fail-closed no-op.
  * GATED, FAIL-CLOSED. Tier-2 / ``ACTIVE_RECON``: the engagement must be entitled, and the cluster's
    apiserver host is declared in ``egress_hosts`` (the egress gate refuses the run unless the operator
    provisioned it in ``targets/<slug>/collector-hosts.txt`` — C1). SDK absent / no config / an API error ⇒
    an honest ``ok=False`` no-op that mints nothing.
  * READ-ONLY. Only ``list`` calls (``list_pod_for_all_namespaces``, ``list_cluster_role_binding``,
    ``list_role_binding_for_all_namespaces``). The collector never mutates the cluster.
  * DETERMINISM OF THE CORE. The response → control translation (``k8s_workload_controls`` and helpers) is a
    PURE, total, CI-tested function of the retained reduced responses — no SDK, no network.
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

# RBAC subjects that denote an UNAUTHENTICATED caller — a role bound to one grants anyone (no credential)
# the role's permissions.
_ANON_SUBJECTS = frozenset({"system:anonymous", "system:unauthenticated"})
_K8S_LIVE_RELIABILITY = SourceReliability(reliability=Reliability.B, credibility=Credibility.C2)


# ---------------------------------------------------------------------------
# pure translation: reduced read-only responses -> achieved-state control LEADS
# (no SDK, no network — the deterministic, CI-tested core the oracle consumes)
# ---------------------------------------------------------------------------


def _pod_controls(pods: Any) -> list[dict]:
    """One achieved-state control per EXPLICIT insecure pod property. ``pods`` is the reduced read:
    ``[{"name", "namespace"?, "privileged": bool, "host_network": bool}]``. Only privileged / host-network
    pods emit a control (a hardened pod emits nothing). Total: odd entries skipped."""
    out: list[dict] = []
    if not isinstance(pods, (list, tuple)):
        return out
    for p in pods:
        if not isinstance(p, dict):
            continue
        name = str(p.get("name") or "").strip()
        if not name:
            continue
        ns = str(p.get("namespace") or "").strip()
        base = f"pod:{ns}/{name}"
        if p.get("privileged") is True:
            out.append({"check_id": f"{base}:privileged", "resource_kind": "pod", "name": name,
                        "namespace": ns, "achieved_state": {"privileged": True}})
        if p.get("host_network") is True:
            out.append({"check_id": f"{base}:hostnetwork", "resource_kind": "pod", "name": name,
                        "namespace": ns, "achieved_state": {"host_network": True}})
    return out


def _binding_controls(bindings: Any) -> list[dict]:
    """One achieved-state control per RBAC binding that grants a role to an ANONYMOUS subject. ``bindings``:
    ``[{"name", "namespace"?, "role"?, "subjects": ["system:anonymous", …]}]``. Only anonymous-subject
    bindings emit a control. Total."""
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
        subjects = subjects if isinstance(subjects, (list, tuple)) else []
        if any(str(s or "").strip().lower() in _ANON_SUBJECTS for s in subjects):
            ns = str(b.get("namespace") or "").strip()
            out.append({"check_id": f"binding:{ns}/{name}", "resource_kind": "rolebinding", "name": name,
                        "namespace": ns, "achieved_state": {"anonymous_subject": True},
                        "role": str(b.get("role") or "")})
    return out


def k8s_workload_controls(*, pods: Any = (), bindings: Any = ()) -> list[dict]:
    """The retained achieved-state controls a LIVE cluster read implies — the deterministic core the oracle
    promotes. PURE + total. Only EXPLICIT insecure states are emitted (a benign cluster yields ``[]``)."""
    return _pod_controls(pods) + _binding_controls(bindings)


def k8s_workload_observations(controls: list[dict], *, seq: int, source: str = "k8s_live") -> list[Observation]:
    """Mint a CONTROL observation per achieved-state control — a LEAD (``GROUNDING_INTEL``), never a
    confirmed weakness (the ``k8s_workload_posture_oracle`` re-derives the FACT over the retained achieved
    state). Keyed ``k8s-workload:<check_id>`` so N controls mint N collision-free leads; claim-keyed
    ``obs_id`` -> re-ingest/reorder/duplicate collapse to one; PURE (no wallclock/rng). Mirrors
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
        out.append(Observation(
            obs_id=f"{source}:{seq}:{ref.node_id}||",
            source=source, source_kind=IntelSourceKind.CLOUD_POSTURE, collector=source,
            subject=ref, relation=None, object=None,
            attrs={k: v for k, v in {
                "check_id": check_id,
                "resource_kind": c.get("resource_kind") or None,
                "namespace": c.get("namespace") or None,
                "role": c.get("role") or None,
                "privileged": state.get("privileged") or None,
                "host_network": state.get("host_network") or None,
                "anonymous_subject": state.get("anonymous_subject") or None,
                "benchmark": "k8s-workload",
            }.items() if v},
            source_reliability=_K8S_LIVE_RELIABILITY, confidence=0.7, seq=seq))
    return out


# ---------------------------------------------------------------------------
# the live sensor
# ---------------------------------------------------------------------------


def _apiserver_host() -> str:
    """The cluster apiserver host the collector reaches — from the in-cluster env
    (``KUBERNETES_SERVICE_HOST``) or the current-context server URL in the ``KUBECONFIG`` file. "" if
    indeterminate. Best-effort + total (never raises)."""
    host = str(os.environ.get("KUBERNETES_SERVICE_HOST") or "").strip()
    if host:
        return host
    path = str(os.environ.get("KUBECONFIG") or "").strip()
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
            server = (c.get("cluster", {}) or {}).get("server", "")
            h = urlsplit(str(server or "")).hostname or ""
            if h:
                return h
    return ""


class K8sLiveSensor:
    """Live, read-only Kubernetes workload/RBAC posture collector (Tier-2, ``ACTIVE_RECON``). Loads the
    ambient kubeconfig (the offense-bridge-materialised ``KUBECONFIG``) or an in-cluster ServiceAccount,
    lists pods + RBAC bindings READ-ONLY, and emits achieved-state controls as
    ``{"controls": [...]}``. Fail-closed no-op when the kubernetes client is absent or no cluster config is
    discoverable. The apiserver host is declared as ``egress_hosts`` so the gate authorises exactly the
    cluster it reaches (the operator provisions it in collector-hosts.txt)."""

    name = "k8s_live"
    tier = "T2"
    capability = Capability.ACTIVE_RECON
    destructive = False

    _MAX_PODS = 5000
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

    def _reduce_pods(self, core_v1: Any) -> list[dict]:
        pods_obj = self._safe(lambda: core_v1.list_pod_for_all_namespaces(watch=False))
        items = getattr(pods_obj, "items", None) or []
        out: list[dict] = []
        for pod in items[: self._MAX_PODS]:
            meta = getattr(pod, "metadata", None)
            spec = getattr(pod, "spec", None)
            name = str(getattr(meta, "name", "") or "").strip()
            if not name:
                continue
            privileged = False
            for cont in (getattr(spec, "containers", None) or []):
                sc = getattr(cont, "security_context", None)
                if getattr(sc, "privileged", None) is True:
                    privileged = True
                    break
            out.append({"name": name, "namespace": str(getattr(meta, "namespace", "") or ""),
                        "privileged": privileged, "host_network": getattr(spec, "host_network", None) is True})
        return out

    def _reduce_bindings(self, rbac_v1: Any) -> list[dict]:
        out: list[dict] = []
        for lister, kind in ((lambda: rbac_v1.list_cluster_role_binding(), "clusterrolebinding"),
                             (lambda: rbac_v1.list_role_binding_for_all_namespaces(), "rolebinding")):
            obj = self._safe(lister)
            for b in (getattr(obj, "items", None) or [])[: self._MAX_BINDINGS]:
                meta = getattr(b, "metadata", None)
                name = str(getattr(meta, "name", "") or "").strip()
                if not name:
                    continue
                subjects = [str(getattr(s, "name", "") or "") for s in (getattr(b, "subjects", None) or [])]
                role = str(getattr(getattr(b, "role_ref", None), "name", "") or "")
                out.append({"name": name, "namespace": str(getattr(meta, "namespace", "") or ""),
                            "role": role, "subjects": subjects, "kind": kind})
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
        try:
            pods = self._reduce_pods(client.CoreV1Api())
        except Exception as e:
            return ToolResult(ok=False, note=(
                f"k8s_live: cluster read failed — kubeconfig invalid/expired or apiserver unreachable "
                f"(fail-closed): {type(e).__name__}"))
        bindings = self._safe(lambda: self._reduce_bindings(client.RbacAuthorizationV1Api()), [])
        controls = k8s_workload_controls(pods=pods, bindings=bindings)
        return ToolResult(
            ok=True,
            summary=f"k8s_live: cluster read — {len(controls)} insecure workload/RBAC control(s) over "
                    f"{len(pods)} pods (read-only)",
            output={"controls": controls, "provider": "kubernetes"})

    def normalize(self, result: ToolResult, ctx: ToolContext, *, seq: int) -> list[Observation]:
        out = result.output or {}
        controls = out.get("controls")
        if not isinstance(controls, list) or not controls:
            return []
        return k8s_workload_observations(controls, seq=seq)
