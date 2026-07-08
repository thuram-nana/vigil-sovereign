"""
intel.from_cloud — operator-provided cloud/IAM inventory → the asset graph.

Cloud attack paths are IAM-relation questions: who can assume which role, who is a
member of which group, and which principal holds a grant over which sensitive resource.
CRUCIBLE already MODELS these — `PRINCIPAL`/`CLOUD_RESOURCE`/`DATASTORE` node kinds and
`CAN_ASSUME`/`MEMBER_OF`/`HAS_GRANT` edges exist, and the knowledge operators
(`role-assumption`, `credential-reuse`) chain over them. What was missing was
COLLECTION. This adapter ingests an operator-provided cloud inventory export (offline —
no live cloud-credential scraping) and projects it as those exact nodes and edges, so
the existing IAM chaining fires over a real cloud topology.

Input (an operator export; total — malformed entries are skipped, never raises)::

    {"principals": [{"id": "role/admin", "kind": "role",
                     "can_assume": ["role/deploy"], "member_of": ["group/ops"]}],
     "resources":  [{"id": "s3/customer-data", "kind": "datastore",
                     "grants": [{"principal": "role/admin", "access": "read"}]}]}

Operator inventory is authoritative → high self-report reliability; deterministic
obs_ids → idempotent re-ingest.
"""

from __future__ import annotations

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

# resource "kind" hint → node kind (default cloud_resource)
_RESOURCE_KINDS = {
    "datastore": NodeKind.DATASTORE, "database": NodeKind.DATASTORE, "bucket": NodeKind.DATASTORE,
    "host": NodeKind.HOST, "service": NodeKind.SERVICE,
}


def _principal(pid: str) -> EntityRef:
    return EntityRef(kind=NodeKind.PRINCIPAL, key=str(pid).lower())


def _resource(rid: str, kind_hint: str) -> EntityRef:
    return EntityRef(kind=_RESOURCE_KINDS.get(str(kind_hint).lower(), NodeKind.CLOUD_RESOURCE),
                     key=str(rid).lower())


def _mint(subject, *, seq, idx, relation=None, obj=None, attrs=None) -> Observation:
    rel = relation.value if relation else "_"
    oid = f"cloud:{seq}:{idx}:{subject.node_id}|{rel}|{obj.node_id if obj else '_'}"
    return Observation(
        obs_id=oid, source="cloud", source_kind=IntelSourceKind.OPERATOR_INGEST, collector="cloud",
        subject=subject, relation=relation, object=obj, attrs=attrs or {},
        source_reliability=_OPERATOR, confidence=0.95, seq=seq,
        raw_ref="cloud-inventory", evidence="operator cloud/IAM inventory")


def observations_from_cloud(inventory: dict, *, seq: int = 0) -> list[Observation]:
    """Project an operator cloud/IAM inventory into PRINCIPAL / resource nodes and
    CAN_ASSUME / MEMBER_OF / HAS_GRANT edges (the shapes the IAM chaining operators
    consume). Total — unrecognised entries are skipped."""
    if not isinstance(inventory, dict):
        return []
    out: list[Observation] = []
    idx = 0

    for p in inventory.get("principals", []) or []:
        if not isinstance(p, dict) or not p.get("id"):
            continue
        pr = _principal(p["id"])
        out.append(_mint(pr, seq=seq, idx=idx, attrs={"kind": p.get("kind", "")})); idx += 1
        for target in p.get("can_assume", []) or []:
            out.append(_mint(pr, seq=seq, idx=idx, relation=EdgeKind.CAN_ASSUME, obj=_principal(target))); idx += 1
        for group in p.get("member_of", []) or []:
            out.append(_mint(pr, seq=seq, idx=idx, relation=EdgeKind.MEMBER_OF, obj=_principal(group))); idx += 1

    for r in inventory.get("resources", []) or []:
        if not isinstance(r, dict) or not r.get("id"):
            continue
        res = _resource(r["id"], r.get("kind", ""))
        out.append(_mint(res, seq=seq, idx=idx, attrs={"kind": r.get("kind", "")})); idx += 1
        for g in r.get("grants", []) or []:
            if not isinstance(g, dict) or not g.get("principal"):
                continue
            # PRINCIPAL --HAS_GRANT--> resource (the direction the operators read)
            out.append(_mint(_principal(g["principal"]), seq=seq, idx=idx,
                             relation=EdgeKind.HAS_GRANT, obj=res,
                             attrs={"access": g.get("access", "")})); idx += 1
    return out
