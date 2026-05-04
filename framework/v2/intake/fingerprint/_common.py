"""
intake.fingerprint._common — shared signature engine.

Every detector is a list of `Signature` records plus a one-line
`detect()` that calls `evaluate()`. Splitting them this way keeps
each detector readable and reviewable as a curated rule pack.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Pattern

from ..models import Detection, DetectionResult, HTTPExchange


_RegexLike = "Pattern[str] | str"


@dataclass(frozen=True)
class Signature:
    """One rule. 'where' chooses which slice of the exchange to inspect."""

    label: str                     # canonical token, e.g. "laravel"
    where: str                     # header / cookie / body / url / path / status
    name: str                      # name of header/cookie; ignored for body/url/path
    pattern: Pattern[str] | str    # compiled regex or plain substring
    confidence: float              # 0.0-1.0; capped to 1.0 after aggregation
    evidence: str                  # human-readable line on match
    category: str = ""             # filled by run() from the detector name


def _matches(pattern: Pattern[str] | str, value: str) -> bool:
    if isinstance(pattern, str):
        if pattern == "":
            return bool(value)  # any non-empty value
        return pattern.lower() in value.lower()
    return pattern.search(value) is not None


def _evaluate_signature(sig: Signature, ex: HTTPExchange) -> str | None:
    """Return evidence string if the signature matches `ex`, else None."""
    where = sig.where.lower()

    if where == "header":
        v = ex.header(sig.name)
        if not v:
            return None
        return sig.evidence if _matches(sig.pattern, v) else None

    if where == "cookie":
        if sig.name in ex.cookies:
            v = ex.cookies[sig.name]
            if sig.pattern == "" or _matches(sig.pattern, v):
                return sig.evidence
        # also check Set-Cookie text in case cookies wasn't parsed
        sc = ex.header("Set-Cookie") + ex.header("set-cookie")
        if sig.name + "=" in sc:
            return sig.evidence
        return None

    if where == "body":
        return sig.evidence if _matches(sig.pattern, ex.body_excerpt) else None

    if where == "url":
        return sig.evidence if _matches(sig.pattern, ex.url) else None

    if where == "path":
        # match the path component of the URL
        from urllib.parse import urlparse
        path = urlparse(ex.url).path or "/"
        return sig.evidence if _matches(sig.pattern, path) else None

    if where == "status":
        if isinstance(sig.pattern, str) and sig.pattern.isdigit():
            return sig.evidence if str(ex.status) == sig.pattern else None
        return sig.evidence if _matches(sig.pattern, str(ex.status)) else None

    return None


def evaluate(
    signatures: Iterable[Signature], exchanges: Iterable[HTTPExchange],
) -> dict[str, tuple[float, list[str]]]:
    """Aggregate signature matches per label. Returns label -> (confidence, evidences)."""
    out: dict[str, list[tuple[float, str]]] = {}
    for sig in signatures:
        for ex in exchanges:
            ev = _evaluate_signature(sig, ex)
            if ev is None:
                continue
            cite = f"{ev} (in {ex.method} {ex.url})"
            out.setdefault(sig.label, []).append((sig.confidence, cite))

    aggregated: dict[str, tuple[float, list[str]]] = {}
    for label, hits in out.items():
        # diminishing-returns aggregation: 1 - prod(1 - c_i)
        # bounded to 1.0; multiple weak signals still add up to a strong one.
        prod = 1.0
        for c, _ in hits:
            prod *= max(0.0, 1.0 - c)
        confidence = max(0.0, min(1.0, 1.0 - prod))
        evidences = [e for _, e in hits]
        aggregated[label] = (confidence, evidences)
    return aggregated


def run(
    detector_name: str,
    signatures: Iterable[Signature],
    exchanges: Iterable[HTTPExchange],
    *,
    category: str | None = None,
) -> DetectionResult:
    """Top-level entry point used by every detector module."""
    cat = category or detector_name
    aggregated = evaluate(signatures, exchanges)
    detections = [
        Detection(
            label=label, category=cat,
            confidence=round(conf, 3), evidence=evs,
        )
        for label, (conf, evs) in sorted(
            aggregated.items(), key=lambda kv: kv[1][0], reverse=True,
        )
        if conf > 0
    ]
    return DetectionResult(detector=detector_name, detections=detections)


# convenience constructors
def hdr(label: str, name: str, pattern: str | Pattern[str], conf: float, ev: str) -> Signature:
    return Signature(label=label, where="header", name=name, pattern=pattern,
                     confidence=conf, evidence=ev)


def cookie(label: str, name: str, conf: float, ev: str, pattern: str | Pattern[str] = "") -> Signature:
    return Signature(label=label, where="cookie", name=name, pattern=pattern,
                     confidence=conf, evidence=ev)


def body(label: str, pattern: str | Pattern[str], conf: float, ev: str) -> Signature:
    return Signature(label=label, where="body", name="", pattern=pattern,
                     confidence=conf, evidence=ev)


def path(label: str, pattern: str | Pattern[str], conf: float, ev: str) -> Signature:
    return Signature(label=label, where="path", name="", pattern=pattern,
                     confidence=conf, evidence=ev)


def re_(s: str) -> Pattern[str]:
    return re.compile(s, re.IGNORECASE)
