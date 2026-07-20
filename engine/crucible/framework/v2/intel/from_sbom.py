"""
intel.from_sbom — operator-provided software bill-of-materials → the asset graph.

Supply-chain risk is an asset-graph question: which components an application depends
on, transitively, and where a known-vulnerable package sits in that tree. This adapter
ingests an operator-provided SBOM (offline — a file the operator exports, matching the
gated-egress doctrine; no live registry scraping) and projects it as `PACKAGE` nodes
and `DEPENDS_ON` edges onto the same world-model everything else lives on.

Two input shapes are accepted, both total (a malformed entry is skipped, never raises):
  * a normalized form — ``{"application": name, "packages": [{"name","version","depends_on":[...]}]}``
  * CycloneDX — ``{"components":[{"name","version"}], "dependencies":[{"ref","dependsOn":[...]}]}``

Operator-provided inventory is authoritative, so observations carry a high self-report
reliability. Deterministic obs_ids make re-ingest idempotent.
"""

from __future__ import annotations

from typing import Any

from ..worldmodel.models import EdgeKind, NodeKind
from .models import (
    Credibility,
    IntelSourceKind,
    Observation,
    Reliability,
    SourceReliability,
)
from .refs import EntityRef

_OPERATOR = SourceReliability(reliability=Reliability.A, credibility=Credibility.C1)


def _pkg(name: str, version: str = "") -> EntityRef:
    key = f"{name}@{version}".strip("@").lower() if name else "?"
    return EntityRef(kind=NodeKind.PACKAGE, key=key)


def _mint(subject, *, seq, idx, relation=None, obj=None, attrs=None) -> Observation:
    rel = relation.value if relation else "_"
    oid = f"sbom:{seq}:{idx}:{subject.node_id}|{rel}|{obj.node_id if obj else '_'}"
    return Observation(
        obs_id=oid, source="sbom", source_kind=IntelSourceKind.OPERATOR_INGEST, collector="sbom",
        subject=subject, relation=relation, object=obj, attrs=attrs or {},
        source_reliability=_OPERATOR, confidence=0.95, seq=seq,
        raw_ref="sbom", evidence="operator SBOM")


def observations_from_sbom(sbom: dict, *, seq: int = 0) -> list[Observation]:
    """Project an operator SBOM into PACKAGE nodes + DEPENDS_ON edges. Returns [] on an
    unrecognised/empty document rather than raising."""
    if not isinstance(sbom, dict):
        return []
    out: list[Observation] = []
    idx = 0

    # CycloneDX: components + dependencies (by bom-ref/purl); normalized: packages[].
    components = sbom.get("components")
    if isinstance(components, list):
        # map bom-ref → package ref for the dependency graph
        ref_to_pkg: dict[str, EntityRef] = {}
        for c in components:
            if not isinstance(c, dict) or not c.get("name"):
                continue
            pkg = _pkg(str(c["name"]), str(c.get("version", "")))
            key = str(c.get("bom-ref") or c.get("purl") or c["name"])
            ref_to_pkg[key] = pkg
            out.append(_mint(pkg, seq=seq, idx=idx, attrs={"purl": c.get("purl", "")})); idx += 1
        for dep in sbom.get("dependencies", []) or []:
            if not isinstance(dep, dict):
                continue
            src = ref_to_pkg.get(str(dep.get("ref", "")))
            if src is None:
                continue
            for child_ref in dep.get("dependsOn", []) or []:
                child = ref_to_pkg.get(str(child_ref))
                if child is not None:
                    out.append(_mint(src, seq=seq, idx=idx, relation=EdgeKind.DEPENDS_ON, obj=child)); idx += 1
        return out

    # normalized form
    app_name = str(sbom.get("application") or "").strip()
    app = EntityRef(kind=NodeKind.APPLICATION, key=app_name.lower()) if app_name else None
    packages = sbom.get("packages")
    if not isinstance(packages, list):
        return out
    for p in packages:
        if not isinstance(p, dict) or not p.get("name"):
            continue
        pkg = _pkg(str(p["name"]), str(p.get("version", "")))
        out.append(_mint(pkg, seq=seq, idx=idx, attrs={k: p[k] for k in ("cve", "license") if k in p}))
        idx += 1
        if app is not None:
            out.append(_mint(app, seq=seq, idx=idx, relation=EdgeKind.DEPENDS_ON, obj=pkg)); idx += 1
        for child in p.get("depends_on", []) or []:
            child_ref = _pkg(str(child)) if "@" not in str(child) else _pkg(*str(child).split("@", 1))
            out.append(_mint(pkg, seq=seq, idx=idx, relation=EdgeKind.DEPENDS_ON, obj=child_ref)); idx += 1
    return out
