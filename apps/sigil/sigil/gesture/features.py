"""Landmark features + a from-foundation classifier (Phase 8, WS-F F4). `invariant_features` turns 21
raw keypoints into a TRANSLATION/SCALE/ROTATION-invariant vector: recenter to the wrist (kp0), scale
by the wrist→middle-MCP span (kp9), canonicalize rotation to that axis. Invariance is a hard,
testable property (translate/scale/rotate the same hand → identical features) and is what makes the
classifier robust. `RuleClassifier` is a working baseline over the features (extended-finger counting
+ pinch distance); a trained MLP/TCN over these features (exported ONNX/npz, `train/` offline) is the
documented upgrade behind the same `GestureModel` Protocol."""
from __future__ import annotations

import math
from typing import List

from .types import GestureReading, Hand

_TIPS = (4, 8, 12, 16, 20)
_PIPS = (2, 6, 10, 14, 18)


def _dist(a, b) -> float:
    return math.hypot(a[0] - b[0], a[1] - b[1])


def invariant_features(hand: Hand) -> List[float]:
    pts = [(lm[0], lm[1]) for lm in hand.landmarks]
    if len(pts) < 21:
        return []
    wx, wy = pts[0]
    rel = [(x - wx, y - wy) for x, y in pts]              # translation-invariant (recenter to wrist)
    span = math.hypot(rel[9][0], rel[9][1]) or 1e-6
    rel = [(x / span, y / span) for x, y in rel]          # scale-invariant (wrist→mid-MCP span)
    theta = math.atan2(rel[9][1], rel[9][0])
    cos, sin = math.cos(-theta), math.sin(-theta)
    rot = [(x * cos - y * sin, x * sin + y * cos) for x, y in rel]   # rotation-canonicalized
    out: List[float] = []
    for x, y in rot:
        out += [x, y]
    return out


class RuleClassifier:
    """A working, dependency-free static-pose classifier over the invariant geometry."""
    def classify(self, hands: List[Hand]) -> GestureReading:
        if not hands:
            return GestureReading("neutral", 0.0)
        h = hands[0]
        pts = [(lm[0], lm[1]) for lm in h.landmarks]
        if len(pts) < 21:
            return GestureReading("neutral", 0.0)
        wrist = pts[0]
        span = _dist(pts[0], pts[9]) or 1e-6
        extended = [_dist(pts[t], wrist) > _dist(pts[p], wrist) for t, p in zip(_TIPS, _PIPS)]
        n = sum(extended)
        pinch = _dist(pts[4], pts[8]) < 0.35 * span       # thumb-tip near index-tip
        if pinch and n <= 2:
            return GestureReading("pinch", 0.9, margin=0.5)
        if n == 0:
            return GestureReading("fist", 0.9, margin=0.5)
        if n >= 4:
            return GestureReading("open", 0.9, margin=0.5)
        if extended[1] and n == 1:                        # index only → point (pointer driver)
            return GestureReading("point", 0.9, dx=0.0, dy=0.0, margin=0.4)
        return GestureReading("neutral", 0.3, margin=0.1)
