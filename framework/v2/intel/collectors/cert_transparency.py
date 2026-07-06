"""
intel.collectors.cert_transparency — Certificate Transparency as Observations.

A CT-log query for a domain returns every certificate ever logged for names under
it — an append-only public record. For each logged cert this emits:
  * ``DOMAIN --PRESENTS_CERT--> CERTIFICATE`` for every SAN on the cert (the shared
    cert is the strongest co-reference signal in the resolver — two domains on one
    dedicated cert are almost certainly one asset);
  * a node claim for each newly-seen subdomain name (a name on a logged cert is a
    domain that exists), which becomes a fresh recon subject.

CT is ENUMERATIVE: the query is a complete list, so a name absent from a fresh CT
result genuinely has no logged cert — temporal reasoning may treat its
disappearance as meaningful (unlike a point-query source).

Fixture payload shape::

    [{"fingerprint": "xyz", "names": ["api.company.com", "backend.company.com"],
      "not_after": "2026-01-01"}, ...]
"""

from __future__ import annotations

from ...worldmodel.models import EdgeKind, NodeKind
from ..models import Credibility, IntelSourceKind, Reliability, SourceReliability
from ..refs import EntityRef, canonicalize
from ..transport import RawRecord
from .base import Collector


class CertTransparencyCollector(Collector):
    source_kind = IntelSourceKind.CERT_TRANSPARENCY
    name = "cert_transparency"
    subject_kinds = frozenset({NodeKind.DOMAIN})
    default_reliability = SourceReliability(reliability=Reliability.A, credibility=Credibility.C2)
    enumerative = True
    tpr, fpr, cost = 0.85, 0.05, 1.5

    def _parse(self, subject: EntityRef, rec: RawRecord, *, seq: int):
        entries = rec.payload if isinstance(rec.payload, list) else rec.payload.get("certs", [])  # type: ignore[union-attr]
        out = []
        idx = 0
        apex = subject.key
        seen_names: set[str] = set()
        for entry in entries or []:
            if not isinstance(entry, dict):
                continue
            fp = str(entry.get("fingerprint") or entry.get("sha256") or "").strip()
            names = [str(n) for n in entry.get("names", []) if n]
            cert = canonicalize(NodeKind.CERTIFICATE, fp) if fp else None
            for raw_name in names:
                dom = canonicalize(NodeKind.DOMAIN, raw_name.lstrip("*."))
                # Only names within the queried apex (or the apex itself) are ours to claim.
                if not (dom.key == apex or dom.key.endswith("." + apex)):
                    continue
                if dom.node_id not in seen_names and dom.node_id != subject.node_id:
                    # a discovered subdomain exists (node claim)
                    out.append(self._mint(dom, rec=rec, seq=seq, idx=idx, confidence=0.85,
                                          attrs={"discovered_via": "cert_transparency", "apex": apex}))
                    idx += 1
                    seen_names.add(dom.node_id)
                if cert is not None:
                    out.append(self._mint(dom, rec=rec, seq=seq, idx=idx,
                                          relation=EdgeKind.PRESENTS_CERT, obj=cert, confidence=0.9,
                                          attrs={"not_after": entry.get("not_after", "")}))
                    idx += 1
        return out
