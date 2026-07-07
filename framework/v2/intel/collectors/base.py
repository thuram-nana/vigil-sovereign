"""
intel.collectors.base — the Collector contract + the Observation-minting helper.

A collector is a tiny, pure function of (subject, RawRecord) → [Observation],
wrapped in a class that also declares:

  * ``source_kind`` / ``name`` — provenance;
  * ``subject_kinds`` — what it can be asked about (a DNS collector takes a domain,
    an ASN collector takes a host/netblock);
  * ``default_reliability`` — the Admiralty rating its facts carry unless a record
    overrides it;
  * ``tpr`` / ``fpr`` / ``cost`` — planner value-of-information parameters;
  * ``enumerative`` — whether a query returns a COMPLETE list (so a later absence
    is meaningful) or a point answer (so absence proves nothing).

``collect`` is shared: fetch via the transport, bail on a not-ok record, parse.
Subclasses implement ``_query`` (usually the subject key) and ``_parse``.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from ...worldmodel.models import EdgeKind, NodeKind
from ..models import (
    Credibility,
    IntelSourceKind,
    Observation,
    Polarity,
    Reliability,
    SourceReliability,
)
from ..refs import EntityRef, canonicalize
from ..transport import RawRecord, Transport


class Collector:
    """Base class. Subclasses set the class attributes and implement ``_parse``."""

    source_kind: IntelSourceKind
    name: str = "collector"
    subject_kinds: frozenset[NodeKind] = frozenset()
    default_reliability: SourceReliability = SourceReliability(
        reliability=Reliability.B, credibility=Credibility.C2)
    enumerative: bool = False

    # planner value-of-information parameters (see ReconPlanner):
    tpr: float = 0.8    # P(source yields NEW surface | undiscovered surface exists)
    fpr: float = 0.1    # P(source yields new surface | none exists)
    cost: float = 1.0   # relative query cost

    def accepts(self, subject: EntityRef) -> bool:
        return subject.kind in self.subject_kinds

    def query_for(self, subject: EntityRef) -> str:
        return subject.key

    def collect(self, subject: EntityRef, transport: Transport, *, seq: int) -> list[Observation]:
        """Fetch + parse. Returns [] on a not-ok record (source had nothing / was
        unreachable) — a collector never raises on a missing answer."""
        if not self.accepts(subject):
            return []
        rec = transport.fetch(self.source_kind, self.query_for(subject), seq=seq)
        if not rec.ok:
            return []
        return self._parse(subject, rec, seq=seq)

    # -- subclass hook --------------------------------------------------------

    def _parse(self, subject: EntityRef, rec: RawRecord, *, seq: int) -> list[Observation]:
        raise NotImplementedError

    # -- minting helper -------------------------------------------------------

    def _mint(
        self,
        subject: EntityRef,
        *,
        rec: RawRecord,
        seq: int,
        idx: int,
        relation: EdgeKind | None = None,
        obj: EntityRef | None = None,
        confidence: float = 0.9,
        polarity: Polarity = Polarity.AFFIRMS,
        reliability: SourceReliability | None = None,
        attrs: dict | None = None,
    ) -> Observation:
        """Build one Observation with consistent, deterministic provenance. The
        ``obs_id`` is a pure function of (collector, seq, claim) so re-ingesting the
        same record is idempotent."""
        rel = relation.value if relation else "_"
        obj_id = obj.node_id if obj else "_"
        obs_id = f"{self.name}:{seq}:{idx}:{subject.node_id}|{rel}|{obj_id}"
        return Observation(
            obs_id=obs_id, source=self.name, source_kind=self.source_kind,
            collector=self.name, subject=subject, relation=relation, object=obj,
            attrs=attrs or {}, source_reliability=reliability or self.default_reliability,
            confidence=confidence, polarity=polarity, seq=seq,
            raw_ref=rec.ref, evidence=f"{self.source_kind.value} record for {rec.query}",
        )


def collector_for_subject(subject: EntityRef, collectors: list[Collector]) -> list[Collector]:
    """The collectors that can be asked about ``subject`` — deterministic order."""
    return [c for c in collectors if c.accepts(subject)]


# The default passive-recon roster. Constructed lazily to avoid an import cycle
# (each collector module imports this base). Populated at the bottom of the
# collectors package __init__ is avoided — instead we build fresh instances here.
def _default_collectors() -> list["Collector"]:
    from .dns import DnsCollector
    from .cert_transparency import CertTransparencyCollector
    from .rdap import RdapCollector
    from .asn_bgp import AsnBgpCollector
    return [DnsCollector(), CertTransparencyCollector(), RdapCollector(), AsnBgpCollector()]


class _LazyRoster:
    """A list-like that materialises the default collectors on first use, so
    ``DEFAULT_COLLECTORS`` can be imported at package top level without a cycle."""

    def __init__(self) -> None:
        self._cache: list[Collector] | None = None

    def _get(self) -> list[Collector]:
        if self._cache is None:
            self._cache = _default_collectors()
        return self._cache

    def __iter__(self):
        return iter(self._get())

    def __len__(self) -> int:
        return len(self._get())

    def __getitem__(self, i):
        return self._get()[i]


DEFAULT_COLLECTORS = _LazyRoster()
