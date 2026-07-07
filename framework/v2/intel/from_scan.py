"""
intel.from_scan — bridge the scanner's own observations INTO the intel substrate.

The engine's third-party collectors discover assets from the outside (DNS, CT, RDAP,
ASN). But a live engagement ALSO observes the target directly: the scan confirms the
target host exists and fingerprints its stack. This adapter turns that first-party
surface into `Observation`s so it lands in the SAME world-model graph and entity
resolution — closing the loop both ways (collectors discover → scan confirms; scan
confirms → intel graph).

It stays strictly in the ASSET tier (`domain:` / `host:` / `application:` / `service:`),
which is disjoint from the attack tier the chainer projects (`endpoint:*` / `finding:*`),
so scan-confirmed intel never collides with attack-graph facts. It mints nothing about
predicted or unproven surface — only what the scan actually observed — and carries a
high self-observation reliability, because a host we just scanned demonstrably exists.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from ..scanner.campaign import ScanReport
from ..worldmodel.models import EdgeKind, NodeKind
from .models import (
    Credibility,
    IntelSourceKind,
    Observation,
    Reliability,
    SourceReliability,
)
from .refs import EntityRef, canonicalize

# self-observation: we directly reached the host, so it is highly reliable.
_SELF = SourceReliability(reliability=Reliability.A, credibility=Credibility.C1)
_FP = SourceReliability(reliability=Reliability.B, credibility=Credibility.C2)


def host_ref(host: str) -> EntityRef:
    """A domain or host ref — IP literals become HOST, names become DOMAIN
    (canonicalize does not auto-detect, so branch here)."""
    h = (host or "").strip()
    try:
        ipaddress.ip_address(h)
        return canonicalize(NodeKind.HOST, h)
    except ValueError:
        return canonicalize(NodeKind.DOMAIN, h)


def _host_of(url_or_host: str) -> str:
    s = (url_or_host or "").strip()
    if "://" in s:
        return urlsplit(s).hostname or ""
    # bare host or host:port
    return s.split("/")[0].split(":")[0]


def observations_from_report(report: ScanReport, *, seq: int = 0) -> list[Observation]:
    """First-party asset observations from a completed scan: the target host exists,
    its fingerprinted stack RUNS on it, and any distinct hosts seen in findings exist.
    Deterministic obs_ids (mirroring the collectors') so re-ingest is idempotent.

    Strictly asset-tier and strictly OBSERVED — no predicted surface, no attack-tier
    ids. Returns [] rather than raising on a malformed report."""
    out: list[Observation] = []
    idx = 0
    target_host = _host_of(report.target)
    if not target_host:
        return out
    subj = host_ref(target_host)

    def _mint(subject, *, rel=None, obj=None, conf, rel_rating, sk, attrs=None):
        nonlocal idx
        r = rel.value if rel else "_"
        o = obj.node_id if obj else "_"
        oid = f"scan:{seq}:{idx}:{subject.node_id}|{r}|{o}"
        idx += 1
        return Observation(
            obs_id=oid, source="scan", source_kind=sk, collector="scan",
            subject=subject, relation=rel, object=obj, attrs=attrs or {},
            source_reliability=rel_rating, confidence=conf, seq=seq,
            raw_ref=f"scan:{report.target}", evidence=f"scan of {report.target}")

    # the target itself — we reached it, so it demonstrably exists.
    out.append(_mint(subj, conf=1.0, rel_rating=_SELF, sk=IntelSourceKind.SCAN))

    # fingerprinted stack RUNS on the target.
    fp = getattr(report, "fingerprint", None)
    for tm in (getattr(fp, "matches", None) or []):
        name = str(getattr(tm, "name", "")).strip()
        if not name:
            continue
        app = canonicalize(NodeKind.APPLICATION, name)
        cat = str(getattr(tm, "category", ""))
        conf = float(getattr(tm, "confidence", 0.6) or 0.6)
        out.append(_mint(app, conf=conf, rel_rating=_FP, sk=IntelSourceKind.FINGERPRINT,
                         attrs={"category": cat}))
        out.append(_mint(subj, rel=EdgeKind.RUNS, obj=app, conf=conf, rel_rating=_FP,
                         sk=IntelSourceKind.FINGERPRINT))

    # distinct hosts seen in confirmed findings (rarely differ from the target).
    seen = {subj.node_id}
    for f in report.active_findings:
        h = _host_of(getattr(f, "endpoint", "") or "")
        if not h:
            continue
        ref = host_ref(h)
        if ref.node_id in seen:
            continue
        seen.add(ref.node_id)
        out.append(_mint(ref, conf=0.95, rel_rating=_SELF, sk=IntelSourceKind.SCAN))
    return out
