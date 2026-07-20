"""Ambient change-detection delta (Phase 7, WS-A V-v). The Phase-5 ambient loop escalated on raw
byte-identity (`frame.sha256` inequality), which fires on lighting jitter and misses nothing. This
replaces it with a PERCEPTUAL delta over the already-captured OCR text: two frames differ only if
their salient-token sets diverge beyond a threshold — so re-rendered/jittered frames with the same
on-screen text are NOT a change, and a meaningful text shift IS. Falls back to byte-identity when
neither frame carries OCR text. Cheap, on-box, deterministic. Reuses `consolidate.gate.salient`."""
from __future__ import annotations

from ..consolidate.gate import salient
from .capture import Frame


def changed(prev: Frame, cur: Frame, *, min_token_delta: float = 0.15, min_new_tokens: int = 3) -> bool:
    """True iff `cur` is a meaningful change from `prev`. Identical bytes → never a change. With OCR
    text on either side, fires when the salient-token sets diverge proportionally (Jaccard distance ≥
    threshold) OR when enough NEW tokens appear absolutely (≥ `min_new_tokens`) — so a small but
    salient addition (a new WARNING line) on a text-heavy screen is not drowned out (red-pen BLOCK-3).
    With no text on either side, falls back to byte-identity."""
    if prev is None:
        return True
    if prev.sha256 == cur.sha256:
        return False                          # identical capture → nothing changed
    a, b = salient(prev.text), salient(cur.text)
    if not a and not b:
        return prev.sha256 != cur.sha256      # no text to compare → byte-identity (already differ)
    union = a | b
    if not union:
        return False
    jaccard_distance = 1.0 - (len(a & b) / len(union))
    new_tokens = len(b - a)                    # tokens present now but not before (additive change)
    return jaccard_distance >= min_token_delta or new_tokens >= min_new_tokens
