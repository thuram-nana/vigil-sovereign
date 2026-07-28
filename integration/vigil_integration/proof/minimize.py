"""
proof.minimize — delta-debugging (ddmin) reduction of a reproducing payload (Proof Studio B6, optional).

A minimal reproducer is a better proof: the smallest payload that still fires the oracle isolates the exact
bytes that matter. This is a classic ddmin (Zeller & Hildebrand) over the PAYLOAD BYTES ONLY, kept
deliberately SEPARATE from the mint path — it never mints, signs, or spools; it just shrinks a payload and
hands the reduction back for the mint to re-certify.

Two invariants a kept reduction must satisfy (fail-closed — a candidate that violates either is rejected):

  1. **Still fires** — the caller injects ``still_reproduces(candidate_bytes) -> bool``, which re-captures
     the exchange with the candidate payload and re-checks ``verify.reverify.reverify_context(...).reproduced``.
     A reduction is kept IFF the oracle still fires over it. (The predicate is injected so this module needs
     no ``framework`` import — FATAL-2 clean.)
  2. **Re-passes content-gating** — a shrunk payload is screened through :mod:`proof.content_gate` before it
     is ever tested; a reduction that trips the gate (e.g. collapses into a destructive construct) is NOT a
     valid minimal reproducer and is rejected, so minimization can never launder past the safety layer.

Bounded: a test budget caps oracle re-fires so a pathological input cannot loop unboundedly. Deterministic
given a deterministic predicate (no wallclock/rng here).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .content_gate import screen_poc_content

# Default cap on candidate evaluations (each is a re-capture + reverify by the injected predicate).
_DEFAULT_MAX_TESTS = 512


@dataclass(frozen=True)
class MinimizeResult:
    """The outcome of a minimization run. ``minimized`` is the smallest payload that still satisfied both
    invariants (the original when nothing could be removed). ``reduced`` is True iff it is strictly smaller
    than the input. ``tests`` is how many candidates were evaluated."""

    minimized: bytes
    reduced: bool
    original_len: int
    minimized_len: int
    tests: int
    note: str = ""


def minimize_payload(
    payload: bytes,
    *,
    still_reproduces: Callable[[bytes], bool],
    max_tests: int = _DEFAULT_MAX_TESTS,
    screen: bool = True,
) -> MinimizeResult:
    """Reduce ``payload`` to a ~1-minimal subset that still reproduces. ``still_reproduces`` returns True iff
    the candidate bytes still fire the oracle (the caller wires it to a re-capture + ``reverify_context``).
    Fail-closed: if the ORIGINAL payload does not itself reproduce (or trips the gate), nothing is minimized
    and the original is returned unchanged with ``reduced=False``."""
    original = bytes(payload)
    budget = {"n": 0}

    def _test(candidate: bytes) -> bool:
        if budget["n"] >= max_tests:
            return False
        budget["n"] += 1
        if screen:
            verdict = screen_poc_content(candidate.decode("utf-8", errors="replace"))
            if verdict.denied:
                return False               # a reduction that trips the content gate is never valid
        try:
            return bool(still_reproduces(candidate))
        except Exception:  # noqa: BLE001 — a predicate error is a non-reproducing candidate (fail-closed)
            return False

    if not _test(original):
        return MinimizeResult(
            minimized=original, reduced=False, original_len=len(original),
            minimized_len=len(original), tests=budget["n"],
            note="original payload does not reproduce (or trips the content gate) — nothing to minimize",
        )

    data = original
    n = 2
    # Granularity-increasing ddmin over complements: remove a 1/n slice while the property holds, then
    # refine down to single bytes; a 1-minimal reproducer remains.
    while len(data) >= 2 and budget["n"] < max_tests:
        chunk = max(1, len(data) // n)
        removed_any = False
        for start in range(0, len(data), chunk):
            complement = data[:start] + data[start + chunk:]
            if not complement:
                continue
            if _test(complement):
                data = complement
                n = max(n - 1, 2)
                removed_any = True
                break
        if not removed_any:
            if n >= len(data):
                break                      # already at single-byte granularity — 1-minimal
            n = min(len(data), n * 2)

    return MinimizeResult(
        minimized=data, reduced=len(data) < len(original), original_len=len(original),
        minimized_len=len(data), tests=budget["n"],
        note="minimized to a reproducing subset" if len(data) < len(original)
        else "no smaller reproducing payload found",
    )
