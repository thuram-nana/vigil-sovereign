"""Gesture value types (Phase 8, WS-F). A `Hand` is a 21-keypoint landmark set; a `GestureReading`
is the classifier's per-frame verdict (label + confidence + top1−top2 margin + pointer kinematics); a
`GestureIntent` is what the FSM decides to DO (still not an injection — the SessionGate authorizes)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple


@dataclass(frozen=True)
class Hand:
    landmarks: Tuple[Tuple[float, float, float], ...]   # 21 (x,y,z), normalized to the frame
    handedness: str = "Right"
    score: float = 1.0


# A HandObservation is a list[Hand] (empty = no hand in frame).


@dataclass(frozen=True)
class GestureReading:
    label: str                 # "point"|"pinch"|"fist"|"open"|"neutral"|"swipe_left"|"swipe_right"|"spread"|...
    confidence: float = 0.0
    dx: float = 0.0            # pointer kinematics (normalized) for the "point" driver
    dy: float = 0.0
    margin: float = 1.0        # top1 − top2 confidence margin (small ⇒ ambiguous ⇒ do nothing)


@dataclass(frozen=True)
class GestureIntent:
    kind: str                  # "move"|"click"|"scroll_left"|"scroll_right"|"drag"|"type"|"launch"|"hand_lost"|"none"
    dx: float = 0.0
    dy: float = 0.0
    arg: str = ""              # e.g. text to type / app to launch (owner-approved before it ever fires)


def empty_observation() -> List[Hand]:
    return []
