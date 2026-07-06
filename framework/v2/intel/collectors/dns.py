"""
intel.collectors.dns — DNS resolution as Observations.

Asks the transport for a domain's records and emits:
  * ``DOMAIN --RESOLVES_TO--> HOST`` for each A / AAAA address;
  * ``DOMAIN --SAME_AS--> DOMAIN`` for a CNAME alias (a strong co-reference signal
    entity-resolution keys on).

DNS is a point query about one name — reliable but volatile, and NOT enumerative
(it tells you nothing about sibling names), so a name's absence from a later
lookup is not evidence the surface shrank.

Fixture payload shape::

    {"A": ["10.15.4.2"], "AAAA": ["2001:db8::1"], "CNAME": ["edge.company.com"]}
"""

from __future__ import annotations

from ...worldmodel.models import EdgeKind, NodeKind
from ..models import Credibility, IntelSourceKind, Reliability, SourceReliability
from ..refs import EntityRef, canonicalize
from ..transport import RawRecord
from .base import Collector


class DnsCollector(Collector):
    source_kind = IntelSourceKind.DNS
    name = "dns"
    subject_kinds = frozenset({NodeKind.DOMAIN})
    default_reliability = SourceReliability(reliability=Reliability.B, credibility=Credibility.C2)
    enumerative = False
    tpr, fpr, cost = 0.75, 0.1, 1.0

    def _parse(self, subject: EntityRef, rec: RawRecord, *, seq: int):
        p = rec.payload if isinstance(rec.payload, dict) else {}
        out = []
        idx = 0
        for addr in list(p.get("A", [])) + list(p.get("AAAA", [])):
            host = canonicalize(NodeKind.HOST, str(addr))
            out.append(self._mint(subject, rec=rec, seq=seq, idx=idx,
                                   relation=EdgeKind.RESOLVES_TO, obj=host, confidence=0.9))
            idx += 1
        for alias in list(p.get("CNAME", [])):
            target = canonicalize(NodeKind.DOMAIN, str(alias))
            if target.node_id == subject.node_id:
                continue
            out.append(self._mint(subject, rec=rec, seq=seq, idx=idx,
                                   relation=EdgeKind.SAME_AS, obj=target, confidence=0.92))
            idx += 1
        return out
