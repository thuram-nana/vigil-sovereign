"""sensors.mesh — ingest an operator-supplied service-mesh config export into mesh posture LEADS.

The capture feed that makes the service-mesh-posture oracle (``verify.mesh_posture``, Wave-G3) reachable in
a real ``engage --fuse-sensors`` run (a ``fusion.json`` task ``{sensor: "mesh_config", args: {config:
"/path/to/istio.yaml"}}``). Mirrors ``sensors.cicd.WorkflowScanSensor`` method-for-method: Tier-1, reads a
LOCAL Istio/Linkerd manifest FILE (JSON or, if PyYAML is present, YAML — single/multi-doc) OR a directory
of them (no network, no kubectl/istioctl call), parses each OFFLINE via
``verify.mesh_posture.ingest_mesh_config``, and mints one ``NodeKind.CONTROL`` LEAD per recognised mesh
resource, keyed ``mesh:<provider>:<kind>:<ns>/<name>``. The leads STOP here; the mesh-posture oracle
re-verifies a lead to a FACT only for a concrete insecure ACHIEVED STATE (permissive/disabled mTLS, an
allow-everyone AuthorizationPolicy, an unauthenticated Linkerd inbound policy). A STRICT/scoped/deny config
stays a LEAD. Pure + total (a malformed manifest is a non-ingestion, never a crash). NO mesh is attacked.
"""

from __future__ import annotations

import os

from ..agents.tools import ToolContext, ToolResult
from ..intel.models import Credibility, IntelSourceKind, Observation, Reliability, SourceReliability
from ..intel.refs import EntityRef
from ..verify.mesh_posture import ingest_mesh_config
from ..worldmodel.models import NodeKind

_MESH_RELIABILITY = SourceReliability(reliability=Reliability.B, credibility=Credibility.C2)
_MAX_CONTROLS = 2000
_MESH_EXTS = (".yaml", ".yml", ".json")


def _check_id(c: dict, source: str, i: int) -> str:
    """A stable, resource-identifying key for one mesh control, NAMESPACED BY SOURCE FILE
    (``<source>:<provider>:<kind>:<ns>/<name>``). The source prefix disambiguates genuinely-distinct
    resources that share a provider:kind:ns/name across files in a directory — a merged multi-cluster /
    duplicated export — so distinct resources never collapse onto one CONTROL node (review fix)."""
    provider = str(c.get("provider") or "mesh").strip()
    kind = str(c.get("resource_kind") or "resource").strip()
    ns = str(c.get("namespace") or "default").strip()
    name = str(c.get("name") or i).strip()
    src = (source or "").strip()
    return f"{(src + ':') if src else ''}{provider}:{kind}:{ns}/{name}"


def _read_mesh_files(path: str) -> list[tuple[str, str]]:
    """``(source-name, text)`` for a single mesh manifest file, or every ``*.yaml/.yml/.json`` under a
    directory (sorted → deterministic). Best-effort: an unreadable file is skipped, never raises."""
    out: list[tuple[str, str]] = []
    try:
        if os.path.isdir(path):
            names = sorted(n for n in os.listdir(path) if n.lower().endswith(_MESH_EXTS))
            paths = [(n, os.path.join(path, n)) for n in names]
        elif os.path.isfile(path):
            paths = [(os.path.basename(path), path)]
        else:
            return []
        for name, fp in paths:
            try:
                with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                    out.append((name, fh.read()))
            except OSError:
                continue
    except OSError:
        return []
    return out


def parse_mesh(path: str) -> list[dict]:
    """Parse a mesh manifest file/dir into per-resource control descriptors, each tagged with a stable,
    source-namespaced ``check_id`` so the lead and its later oracle-promoted FACT land on the SAME CONTROL
    node AND distinct resources across files never collide. Deterministic; ``[]`` when nothing recognised
    parses."""
    controls: list[dict] = []
    for source, text in _read_mesh_files(path):
        for c in ingest_mesh_config(text):
            c = dict(c)
            c["check_id"] = _check_id(c, source, len(controls))
            controls.append(c)
            if len(controls) >= _MAX_CONTROLS:
                return controls
    return controls


def mesh_control_observations(controls: list[dict], *, seq: int, source: str = "mesh_config") -> list[Observation]:
    """Mint one ``NodeKind.CONTROL`` LEAD per mesh resource, keyed ``mesh:<check_id>``. The retained
    achieved state (mtls_mode / action+rules / default_inbound_policy) rides in ``attrs`` so the mesh-posture
    oracle can re-derive the weakness. GROUNDING_INTEL, claim-keyed obs_ids (idempotent), pure."""
    out: list[Observation] = []
    seen: set[str] = set()
    for c in controls:
        cid = str(c.get("check_id") or "").strip()
        if not cid or cid in seen:
            continue
        seen.add(cid)
        ref = EntityRef(kind=NodeKind.CONTROL, key=f"mesh:{cid}")
        attrs = {"lead": True, "unverified": True, "check_id": cid,
                 "resource_kind": c.get("resource_kind"), "provider": c.get("provider"),
                 "mtls_mode": c.get("mtls_mode"), "action": c.get("action"),
                 "default_inbound_policy": c.get("default_inbound_policy")}
        out.append(Observation(
            obs_id=f"{source}:{seq}:{ref.node_id}||", source=source,
            source_kind=IntelSourceKind.OPERATOR_INGEST, collector=source, subject=ref,
            relation=None, object=None, attrs={k: v for k, v in attrs.items() if v not in (None, "")},
            source_reliability=_MESH_RELIABILITY, confidence=0.7, seq=seq))
    return out


class MeshConfigSensor:
    """Ingest an operator-provided Istio/Linkerd config export and mint mesh posture LEADS. args:
    ``{"config": "/path/to/istio.yaml"}`` (a file or a directory). Passive (Tier-1): reads local files, no
    network, no kubectl/istioctl call, no entitlement — kill-switch-gated via ``sensors.pipeline.run_sensor``.
    The leads STOP here; the mesh-posture oracle re-verifies a lead to a FACT. Mirrors ``WorkflowScanSensor``."""

    name = "mesh_config"
    tier = "T1"
    capability = None
    destructive = False
    egress_hosts: tuple = ()

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        path = args.get("config") if isinstance(args, dict) else None
        if not path or not isinstance(path, str):
            return ToolResult(ok=False, note="mesh_config requires args['config'] (a file or dir path)")
        if not (os.path.isfile(path) or os.path.isdir(path)):
            return ToolResult(ok=False, note=f"mesh_config: no mesh manifest file/dir at: {path}")
        controls = parse_mesh(path)
        return ToolResult(ok=True, summary=f"mesh: {len(controls)} mesh resource(s)",
                          output={"controls": controls})

    def normalize(self, result: ToolResult, ctx: ToolContext, *, seq: int):
        out = result.output or {}
        controls = out.get("controls")
        if not isinstance(controls, list):
            return []
        return mesh_control_observations(controls, seq=seq, source="mesh_config")

    def controls(self, result: ToolResult) -> list[dict]:
        """The retained mesh controls for the mesh-posture oracle (``confirm_mesh_posture``)."""
        out = result.output or {}
        c = out.get("controls")
        return c if isinstance(c, list) else []
