"""
imports.to_observations — turn parsed third-party findings into intel Observations.

This is the ``intel.from_scan`` pattern generalized to an EXTERNAL tool: each
``ImportedFinding`` mints

  * an ASSET observation — the host/domain the tool referenced exists (a real,
    collected lead), and
  * an ENDPOINT-LEAD observation — the surface the tool flagged, carrying the
    claimed vulnerability in its ``attrs`` as an explicit lead
    (``lead: True, unverified: True, bug_class: ...``), plus a ``HOSTS`` edge from
    the host to the endpoint so the graph stays connected.

Every observation is source-kind WEB_SCANNER (a heuristic third-party match) or
OPERATOR_INGEST (operator-provided), carries a MODEST reliability (a lead, not a
proof), and — once ``intel.project`` writes it with an ``intel:`` provenance —
classifies as GROUNDING_INTEL. It is never a ``FINDING`` node; a FINDING is what a
CRUCIBLE oracle re-verified.

Determinism: no wallclock, no rng. ``obs_id``s are CLAIM+bug-class keyed, so
re-importing the same report yields the same ids and the ingest de-dups it — the
import is idempotent and byte-identical on replay.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from ..intel.models import (
    Credibility,
    IntelSourceKind,
    Observation,
    Reliability,
    SourceReliability,
)
from ..intel.refs import EntityRef, canonicalize
from ..worldmodel.models import EdgeKind, NodeKind
from .models import ImportedFinding

# A third-party heuristic scanner match is a LEAD: reliable enough to graph, far from a
# proof. Modest ratings keep its world-model belief low so it never masquerades as a
# fact — grounding stays INTEL regardless, but honest belief matters too.
_WEB_SCANNER_SR = SourceReliability(reliability=Reliability.C, credibility=Credibility.C3)
# A tool that self-confirms by exploitation (e.g. sqlmap) earns a slightly higher
# credibility — but it is STILL a lead to us until OUR oracle fires.
_WEB_SCANNER_CONFIRMED_SR = SourceReliability(reliability=Reliability.B, credibility=Credibility.C2)
# Operator-provided generic findings: the operator vouches for the source.
_OPERATOR_SR = SourceReliability(reliability=Reliability.C, credibility=Credibility.C2)

# Modest per-datum confidences (before reliability damping in intel.project).
_ASSET_CONF = 0.6      # the host exists — the tool reached it
_LEAD_CONF = 0.55      # the vulnerability CLAIM — a lead, deliberately low


def _host_ref(host: str) -> EntityRef:
    """A DOMAIN ref for a name, a HOST ref for an IP literal (canonicalize does not
    auto-detect the kind, so branch here — mirrors ``intel.from_scan.host_ref``)."""
    h = (host or "").strip()
    try:
        ipaddress.ip_address(h)
        return canonicalize(NodeKind.HOST, h)
    except ValueError:
        return canonicalize(NodeKind.DOMAIN, h)


def _canon_location(location: str) -> str:
    """A stable canonical endpoint key from a location: scheme+host+path (query and
    fragment dropped so the same surface collapses). Falls back to the trimmed raw
    string when it is not a URL."""
    s = (location or "").strip()
    if not s:
        return ""
    if "://" in s:
        u = urlsplit(s)
        host = (u.hostname or "").lower()
        port = f":{u.port}" if u.port else ""
        path = u.path or "/"
        return f"{u.scheme.lower()}://{host}{port}{path}"
    return s.split("?", 1)[0].split("#", 1)[0].lower()


def _source_reliability(source_kind: IntelSourceKind, tool_confirmed: bool) -> SourceReliability:
    if source_kind is IntelSourceKind.OPERATOR_INGEST:
        return _OPERATOR_SR
    return _WEB_SCANNER_CONFIRMED_SR if tool_confirmed else _WEB_SCANNER_SR


def observations_from_imported(
    findings: list[ImportedFinding],
    *,
    source_tool: str,
    source_kind: IntelSourceKind = IntelSourceKind.WEB_SCANNER,
    seq: int = 0,
) -> list[Observation]:
    """Mint intel Observations for a batch of imported findings. Deterministic and
    claim-keyed (idempotent on replay). Every observation is a LEAD — asset-tier,
    GROUNDING_INTEL once projected — never a fact.

    ``source_tool`` labels provenance; ``source_kind`` picks the reliability profile
    (WEB_SCANNER heuristic vs OPERATOR_INGEST). ``seq`` stamps the whole batch at one
    logical time (the monotonic world-model clock, never wallclock)."""
    st = (source_tool or "import").strip() or "import"
    out: list[Observation] = []
    emitted: set[str] = set()  # obs_id de-dup within the batch (idempotent minting)

    def _mint(subject: EntityRef, *, rel=None, obj=None, conf: float,
              sr: SourceReliability, attrs=None, disc: str = "") -> None:
        r = rel.value if rel else "_"
        o = obj.node_id if obj else "_"
        # CLAIM-keyed id (+ optional discriminator so distinct bug classes on one
        # surface stay distinct). No counter, no clock -> stable across replays.
        oid = f"import:{st}:{subject.node_id}|{r}|{o}"
        if disc:
            oid += f"|{disc}"
        if oid in emitted:
            return
        emitted.add(oid)
        out.append(Observation(
            obs_id=oid, source=st, source_kind=source_kind, collector=f"import:{st}",
            subject=subject, relation=rel, object=obj, attrs=attrs or {},
            source_reliability=sr, confidence=conf, seq=seq,
            raw_ref=f"import:{st}", evidence=f"imported from {st}"))

    for f in findings:
        sr = _source_reliability(source_kind, f.tool_confirmed)
        host = (f.host or "").strip()
        host_ref = _host_ref(host) if host else None

        # 1. the asset the tool referenced exists.
        if host_ref is not None:
            _mint(host_ref, conf=_ASSET_CONF, sr=sr)

        # 2. the flagged surface, carrying the claimed vulnerability as a LEAD.
        canon = _canon_location(f.location) or (host if host else "")
        if not canon:
            continue  # nothing to anchor a lead to — skip (never mint an empty node)
        ep_ref = canonicalize(NodeKind.ENDPOINT, canon)
        lead_attrs = {
            "lead": True,
            "unverified": True,
            "bug_class": f.bug_class,
            "tool": st,
            "severity": f.severity,
            "tool_confirmed": bool(f.tool_confirmed),
            "evidence": (f.evidence or "")[:500],
            "location": f.location,
        }
        _mint(ep_ref, conf=_LEAD_CONF, sr=sr, attrs=lead_attrs, disc=f.bug_class)

        # 3. connect the host to the flagged surface.
        if host_ref is not None:
            _mint(host_ref, rel=EdgeKind.HOSTS, obj=ep_ref, conf=_LEAD_CONF, sr=sr,
                  disc=f.bug_class)

    return out
