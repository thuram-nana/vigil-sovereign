"""
intel.collectors.asn_bgp — ASN / BGP routing origin as Observations.

For a host or netblock it emits the routing-origin facts the resolver's owner
logic consumes:
  * a ``NETBLOCK`` node claim (the announced prefix containing the host);
  * ``ASN --ANNOUNCES--> NETBLOCK`` — which, combined with netblock→host
    containment, lets the resolver attach the host's whole asset to the owning ASN
    via ``ASSET_OWNS`` (never merging the ASN into the asset).

Announcing an origin for a specific address is a point query here (not
enumerative). Routing data is high-reliability (A/2 — occasionally stale/hijacked).

Fixture payload shape::

    {"asn": "AS64501", "netblock": "10.15.4.0/24", "holder": "Company Inc"}
"""

from __future__ import annotations

from ...worldmodel.models import EdgeKind, NodeKind
from ..models import Credibility, IntelSourceKind, Reliability, SourceReliability
from ..refs import EntityRef, canonicalize
from ..transport import RawRecord
from .base import Collector


class AsnBgpCollector(Collector):
    source_kind = IntelSourceKind.ASN_BGP
    name = "asn_bgp"
    subject_kinds = frozenset({NodeKind.HOST, NodeKind.NETBLOCK, NodeKind.ASN})
    default_reliability = SourceReliability(reliability=Reliability.A, credibility=Credibility.C2)
    enumerative = False
    tpr, fpr, cost = 0.5, 0.05, 1.0

    def _parse(self, subject: EntityRef, rec: RawRecord, *, seq: int):
        p = rec.payload if isinstance(rec.payload, dict) else {}
        out = []
        idx = 0
        asn_raw = str(p.get("asn") or "").strip()
        nb_raw = str(p.get("netblock") or p.get("prefix") or "").strip()
        if asn_raw and nb_raw:
            asn = canonicalize(NodeKind.ASN, asn_raw)
            nb = canonicalize(NodeKind.NETBLOCK, nb_raw)
            out.append(self._mint(nb, rec=rec, seq=seq, idx=idx, confidence=0.85,
                                  attrs={"holder": p.get("holder", "")}))
            idx += 1
            out.append(self._mint(asn, rec=rec, seq=seq, idx=idx,
                                  relation=EdgeKind.ANNOUNCES, obj=nb, confidence=0.9))
            idx += 1
        return out
