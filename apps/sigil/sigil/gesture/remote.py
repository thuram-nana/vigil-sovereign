"""Phone-as-gesture-trackpad landmark stream (Phase 9, W2-I). The PHONE runs its OWN on-device hand-
landmark detection and streams tiny `List[Hand]` batches (landmark DATA, never owner pixels) to the PC
over the owner's own tunnel; the PC feeds them through the EXISTING gesture pipeline. This slice streams
into a LOCAL owner-armed session ONLY — the owner arms at the PC (`run_gesture(auto_arm=False, gate=<armed>)`)
and the phone supplies landmarks. The device-signed REMOTE arm is a SEPARATE, later-authorized slice and
is deliberately NOT built here.

Design (mirrors the on-box components; NO dependency on `sigil/bridge/` — an inbound batch iterable is
INJECTED, so there is no socket/import coupling here):

  • `decode_hand_batch(obj) -> List[Hand]` — parse+VALIDATE the compact wire form; on ANY malformation
    return an HONEST `[]` (never a fabricated hand), exactly as `OnnxHandLandmarker.detect` returns `[]`
    on failure.
  • `RemoteLandmarkSource` — the frame source: wraps the injected inbound feed, drops foreign-session /
    replayed / reordered / stale batches, and yields ONE token (the decoded `List[Hand]`) per ACCEPTED
    batch. It tracks only a single last-accepted `seq` (a bounded int — no unbounded buffer), and because
    `seq` is strictly monotonic an out-of-order (older) batch arriving after a newer one is dropped
    (drop-to-latest).
  • `RemoteLandmarker` — a `LandmarkModel` with `egresses = False` (HONEST: it uploads NO owner pixels;
    the phone already did the inference and sends inbound landmark DATA). `detect(token)` returns the
    token's hands, ignoring any image.
"""
from __future__ import annotations

import math
import time
from typing import Iterable, Iterator, List, Optional, TypeGuard

from .types import Hand

WIRE_TYPE = "hand_batch"
MAX_HANDS = 2
N_LANDMARKS = 21
_COORD_CAP = 8.0          # sane bound: reject NaN/inf/garbage coordinates (normalized hands live near [0,1])


def _is_number(v) -> TypeGuard[float]:
    # a real, finite number — bools are ints in Python, so exclude them explicitly
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(float(v))


def _valid_coord(v) -> bool:
    return _is_number(v) and abs(float(v)) <= _COORD_CAP


def decode_hand_batch(obj) -> List[Hand]:
    """Decode a compact wire batch to `List[Hand]`, VALIDATING strictly. Wire form:

        {"t":"hand_batch","session_id":str,"seq":int,"ts":float,
         "hands":[ {"l":[[x,y,z] × 21], "h":"R"|"L", "s":score}, ... ≤ 2 ]}

    Rules (any violation ⇒ return `[]`, honest-empty — never fabricate):
      • obj is a dict tagged `"t":"hand_batch"`;
      • `hands` is a list of AT MOST 2 hands;
      • each hand has EXACTLY 21 landmarks, each a 3-tuple of finite, sane (|v|≤8) floats;
      • handedness `h` ∈ {"R","L"} (→ "Right"/"Left"), defaulting "R" only when the key is absent;
      • score `s` a finite float in [0,1], defaulting 1.0 only when the key is absent.
    """
    try:
        if not isinstance(obj, dict) or obj.get("t") != WIRE_TYPE:
            return []
        raw_hands = obj.get("hands")
        if not isinstance(raw_hands, list) or len(raw_hands) > MAX_HANDS:
            return []
        out: List[Hand] = []
        for rh in raw_hands:
            if not isinstance(rh, dict):
                return []
            lms = rh.get("l")
            if not isinstance(lms, (list, tuple)) or len(lms) != N_LANDMARKS:
                return []
            pts: List[tuple] = []
            for p in lms:
                if not isinstance(p, (list, tuple)) or len(p) != 3:
                    return []
                if not (_valid_coord(p[0]) and _valid_coord(p[1]) and _valid_coord(p[2])):
                    return []
                pts.append((float(p[0]), float(p[1]), float(p[2])))
            h = rh.get("h", "R")
            if h not in ("R", "L"):
                return []
            handed = "Right" if h == "R" else "Left"
            s = rh.get("s", 1.0)
            if not _is_number(s) or not (0.0 <= float(s) <= 1.0):
                return []
            out.append(Hand(landmarks=tuple(pts), handedness=handed, score=float(s)))
        return out
    except Exception:  # noqa: BLE001 — ANY malformation ⇒ honest empty (mirror OnnxHandLandmarker.detect)
        return []


class ScriptedRemoteSource:
    """Deterministic double — an injected inbound feed of raw wire dicts (no socket, no `bridge`).
    Mirrors `perception.camera_stream.ScriptedFrameSource`: replays a fixed list of batch objects."""

    def __init__(self, batches: Iterable):
        self._batches = list(batches)

    def __iter__(self) -> Iterator:
        return iter(self._batches)


class RemoteLandmarkSource:
    """Frame source over an INJECTED inbound batch feed, bound to the LIVE local session.

    `frames()` yields ONE token (the decoded `List[Hand]`) per ACCEPTED batch. A batch is REJECTED
    (dropped, never fabricated) when its `session_id` ≠ the live session, its `seq` ≤ the last accepted
    `seq` (duplicate / reorder / replay), or — if a freshness window is set — its `ts` is outside it.
    The paired `RemoteLandmarker` returns the yielded token, so the token IS the landmark payload."""

    def __init__(self, inbound: Iterable, session_id: str, *,
                 freshness_seconds: Optional[float] = None, now=time.time):
        self._inbound = inbound
        self.session_id = session_id
        self._freshness = freshness_seconds
        self._now = now
        self._last_seq: Optional[int] = None   # bounded: a single int, never an unbounded accepted-set

    def available(self) -> bool:
        return True

    def _accept(self, obj) -> Optional[List[Hand]]:
        """Return the decoded hands for an ACCEPTED batch, or None if the batch is rejected."""
        if not isinstance(obj, dict) or obj.get("t") != WIRE_TYPE:
            return None
        if obj.get("session_id") != self.session_id:            # foreign session → drop
            return None
        seq = obj.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool):   # seq must be a real int
            return None
        if self._last_seq is not None and seq <= self._last_seq:   # replay / reorder / duplicate → drop
            return None
        if self._freshness is not None:                          # optional freshness window
            ts = obj.get("ts")
            if not _is_number(ts) or abs(self._now() - float(ts)) > self._freshness:
                return None
        hands = decode_hand_batch(obj)   # may be [] (honest) — a valid envelope with malformed hands
        self._last_seq = seq             # advance ONLY once the batch is accepted at the envelope level
        return hands

    def frames(self) -> Iterator[List[Hand]]:
        for obj in self._inbound:
            hands = self._accept(obj)
            if hands is None:            # rejected — note: [] is ACCEPTED (honest no-hand), None is not
                continue
            yield hands


class RemoteLandmarker:
    """A `LandmarkModel` fed by the phone's OWN on-device inference. `egresses = False` is HONEST —
    it uploads NO owner pixels; the inbound stream is landmark DATA over the owner's own tunnel. Because
    `egresses is False`, the Wave-1 fail-closed egress gate in `run_gesture` PASSES it (reconciliation:
    that gate refuses a model that would EGRESS owner imagery; this one egresses nothing)."""

    egresses = False
    source_kind = "remote_device_stream"

    def detect(self, token) -> List[Hand]:
        # `token` is the decoded List[Hand] yielded by RemoteLandmarkSource.frames(); return it as-is,
        # ignoring any image (the phone already produced these landmarks). Honest-empty otherwise.
        if isinstance(token, list):
            return token
        return []
