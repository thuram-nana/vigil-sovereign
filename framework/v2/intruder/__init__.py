"""
intruder — the fuzzing engine (Burp Intruder, driven autonomously).

The scanner's checks place a *fixed* payload per bug class. Intruder is the other
axis: many payloads across marked positions, with the results triaged for the one
anomalous response. Burp leaves that triage to a human eyeballing a table; here an
outlier detector does it, so brute-force, enumeration, and race attacks run
zero-manual.

Three parts, all pure/deterministic except the network `send`:

  * ``generators`` — the payload-set vocabulary (lists, numbers, brute-force,
    null-payloads for race, bit-flipper, case/blocks, dates, runtime file).
  * ``attack`` — the four attack-type combinatorics (sniper / battering-ram /
    pitchfork / cluster-bomb) over marked insertion points.
  * ``engine`` — runs an attack through the injected (gated) ``send``, builds the
    results table, and flags the statistically anomalous rows.

Public surface:

    from framework.v2.intruder import (
        AttackType, IntruderEngine, AttackResult, AttackResultRow,
        detect_outliers, generators,
    )
"""

from __future__ import annotations

from . import generators
from .analysis import detect_outliers
from .attack import AttackType, render_attack
from .engine import AttackResult, AttackResultRow, IntruderEngine

__all__ = [
    "generators",
    "AttackType",
    "render_attack",
    "IntruderEngine",
    "AttackResult",
    "AttackResultRow",
    "detect_outliers",
]
