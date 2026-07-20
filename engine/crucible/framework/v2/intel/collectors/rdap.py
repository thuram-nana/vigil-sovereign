"""
intel.collectors.rdap — RDAP / WHOIS registration data as Observations.

The registry is authoritative for *ownership*, so this is the collector that
populates the OWNER tier. For a domain or IP it emits:
  * an ``ORGANIZATION`` node claim (the registrant / net holder);
  * ``ORGANIZATION --ASSET_OWNS--> <subject>`` — the owner link. Never a merge:
    the org owns the asset, it is not the same thing as the asset (the hard rule
    the resolver enforces at the tier boundary).
  * for an IP subject, a ``NETBLOCK`` node + ``ORGANIZATION --ASSET_OWNS--> NETBLOCK``.

RDAP is a point query (not enumerative). Registry data is high-reliability (A/1).

Fixture payload shape (domain)::

    {"org": "Company Inc", "registrar": "R", "handle": "COMPANY-1"}

Fixture payload shape (ip)::

    {"org": "Company Inc", "netblock": "10.15.4.0/24", "asn": "AS64501"}
"""

from __future__ import annotations

from ...worldmodel.models import EdgeKind, NodeKind
from ..models import Credibility, IntelSourceKind, Reliability, SourceReliability
from ..refs import EntityRef, canonicalize
from ..transport import RawRecord
from .base import Collector


class RdapCollector(Collector):
    source_kind = IntelSourceKind.RDAP_WHOIS
    name = "rdap"
    subject_kinds = frozenset({NodeKind.DOMAIN, NodeKind.HOST, NodeKind.NETBLOCK})
    default_reliability = SourceReliability(reliability=Reliability.A, credibility=Credibility.C1)
    enumerative = False
    tpr, fpr, cost = 0.6, 0.05, 1.0

    def _parse(self, subject: EntityRef, rec: RawRecord, *, seq: int):
        p = rec.payload if isinstance(rec.payload, dict) else {}
        out = []
        idx = 0
        # Carry registrant email / nameservers onto the domain node so downstream
        # inference can attribute shared ownership (registrant is an OWNER signal — it
        # must NOT merge assets, only attribute them; intel.infer handles that).
        if subject.kind is NodeKind.DOMAIN:
            dom_attrs: dict = {}
            if p.get("registrant_email"):
                dom_attrs["registrant_email"] = str(p["registrant_email"]).strip().lower()
            if p.get("nameservers"):
                dom_attrs["nameservers"] = str(p["nameservers"])
            if dom_attrs:
                out.append(self._mint(subject, rec=rec, seq=seq, idx=idx, confidence=0.85,
                                      attrs=dom_attrs))
                idx += 1
        org_name = str(p.get("org") or p.get("holder") or "").strip()
        if org_name:
            org = canonicalize(NodeKind.ORGANIZATION, org_name)
            out.append(self._mint(org, rec=rec, seq=seq, idx=idx, confidence=0.9,
                                  attrs={"registrar": p.get("registrar", ""), "handle": p.get("handle", "")}))
            idx += 1
            out.append(self._mint(org, rec=rec, seq=seq, idx=idx,
                                  relation=EdgeKind.ASSET_OWNS, obj=subject, confidence=0.9))
            idx += 1
            netblock = str(p.get("netblock") or "").strip()
            if netblock:
                nb = canonicalize(NodeKind.NETBLOCK, netblock)
                out.append(self._mint(org, rec=rec, seq=seq, idx=idx,
                                      relation=EdgeKind.ASSET_OWNS, obj=nb, confidence=0.85))
                idx += 1
        return out
