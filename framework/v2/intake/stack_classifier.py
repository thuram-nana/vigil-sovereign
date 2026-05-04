"""
intake.stack_classifier — pick a stack archetype from a Fingerprint.

Scoring is *confidence-weighted*: each declared "category:label" in
an archetype's required/optional lists contributes its detector
confidence to the archetype's score, not a binary 1.0. This stops a
weak (~0.4 confidence) hint from out-voting a strong (~0.99) match
elsewhere.

    req_part = (sum of detector confidences for required labels) / |required|
    opt_part = (sum of detector confidences for optional labels) / |optional|
    score    = 0.7 * req_part + 0.3 * opt_part

Archetypes with a non-empty required list and *zero* matches above
the threshold are out of the running.  Fallback is `generic-web`
(empty required list, score 0.0).
"""

from __future__ import annotations

from .archetypes import load_all
from .models import Archetype, ArchetypeMatch, Classification, Fingerprint


_FALLBACK_SLUG = "generic-web"


def _label_confidences(fp: Fingerprint, min_confidence: float = 0.5) -> dict[str, float]:
    """Map of "category:label" -> max detector confidence (only entries
    at or above min_confidence)."""
    out: dict[str, float] = {}
    for r in fp.detectors.values():
        for d in r.detections:
            if d.confidence >= min_confidence:
                key = f"{d.category}:{d.label}"
                out[key] = max(out.get(key, 0.0), d.confidence)
    return out


def _score_archetype(arch: Archetype, label_conf: dict[str, float]) -> ArchetypeMatch:
    req = list(arch.fingerprints_required_any)
    opt = list(arch.fingerprints_optional)

    matched_required = [r for r in req if label_conf.get(r, 0.0) > 0.0]
    matched_optional = [o for o in opt if label_conf.get(o, 0.0) > 0.0]

    if req and not matched_required:
        return ArchetypeMatch(
            archetype=arch, score=0.0,
            matched_required=[], matched_optional=matched_optional,
        )

    req_total = sum(label_conf.get(r, 0.0) for r in req)
    opt_total = sum(label_conf.get(o, 0.0) for o in opt)

    req_part = (req_total / len(req)) if req else 0.0
    opt_part = (opt_total / len(opt)) if opt else 0.0
    score = 0.7 * req_part + 0.3 * opt_part
    score = min(1.0, score)
    return ArchetypeMatch(
        archetype=arch, score=score,
        matched_required=matched_required, matched_optional=matched_optional,
    )


def classify(fp: Fingerprint, *, min_confidence: float = 0.5) -> Classification:
    label_conf = _label_confidences(fp, min_confidence)
    archetypes = load_all()

    scored = [_score_archetype(a, label_conf) for a in archetypes]
    # split out the fallback so it never wins over a real match
    fallback = next((m for m in scored if m.archetype.slug == _FALLBACK_SLUG), None)
    contenders = [m for m in scored if m.archetype.slug != _FALLBACK_SLUG and m.score > 0]
    contenders.sort(key=lambda m: m.score, reverse=True)

    if contenders:
        primary = contenders[0]
        runners = contenders[1:5]
    elif fallback is not None:
        primary = fallback
        runners = []
    else:
        # no archetypes loaded at all — synthesise a no-op fallback
        primary = ArchetypeMatch(
            archetype=Archetype(name="(none)", slug="none"),
            score=0.0,
        )
        runners = []

    return Classification(primary=primary, runners_up=runners)
