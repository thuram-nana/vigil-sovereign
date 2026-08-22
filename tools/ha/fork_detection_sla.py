"""VIGIL HA — the FORK-DETECTION SLA for the single-writer sovereign spine (W8-2, #468).

Passive fencing in this profile is ADVISORY (a shell guard in ``tools/ha/mirror-sync.sh`` + a ``:ro``
bind in one optional compose profile). Nothing at the storage/orchestration layer PREVENTS a second
concurrent writer, and — per the witnessed-floor doctrine (``docs/architecture/HA-PROFILE.md`` §2, §4) —
a lease/lock that *prevented* one would contradict the product's core trade: a second owner-signed head
is ALWAYS a **detectable fork**, never silently prevented into a false sense of safety. The design
decision to keep prevention out (path (b)) and the SLA below are recorded in
``docs/decisions/W8-2-passive-fencing-detection-sla.md``.

This module states that limitation as a measurable **detection SLA** and gives the pure, testable
predicates the SLA test measures against. It ADDS NO NEW POLICY ENGINE: the actual fork signal is the
audited ``vigil_integration.transparency.is_split`` (same-height, different ``head_hash`` = a fork),
re-exported here under an HA-facing name so callers and tests name the SLA explicitly. The fail-closed
promotion backstop is the audited failover guard (``tools/ha/spine_failover_guard.py``): even if
detection is delayed, a fork can never be silently PROMOTED.

FATAL-2: sovereign/plane-neutral HA tooling. It imports only ``vigil_integration`` (vigil_core-only);
it imports NOTHING from ``sigil`` and MUST NOT be imported by any OFFENSE-plane module.
"""
from __future__ import annotations

from vigil_integration.transparency import Checkpoint, is_split
from vigil_integration.witnessed_anchor import DEFAULT_REFUSE_AFTER_S

# The shipped witness-checkpoint cadence: the scheduled off-box emitter fires every 15 minutes
# (apps/sigil/deploy/systemd/sigil-checkpoint.timer + infra/systemd/vigil-checkpoint.timer). A witness /
# a checkpoint-comparing monitor therefore obtains each live writer's head at most one cadence after that
# head advances.
WITNESS_CHECKPOINT_CADENCE_S = 15 * 60  # 900s — MUST match the shipped timers' OnCalendar cadence.

# THE DETECTION SLA (nominal). Worst case, a second writer that comes up just after a checkpoint tick has
# its divergent head first witnessed at the NEXT tick — one cadence later. So a fork is detected within one
# witness-checkpoint cadence of the second writer advancing the head, once both heads reach a witness.
FORK_DETECTION_SLA_S = WITNESS_CHECKPOINT_CADENCE_S  # 900s.

# THE FAIL-CLOSED CEILING (hard backstop, not the nominal SLA). If the scheduled emitter DEGRADES so that
# detection is delayed, the freshness gate (W7-5, #463) refuses to anchor any promotion off an anchor older
# than this — so a fork is never silently PROMOTED even when nominal detection is late. This is the same
# 24h bound the failover guard enforces; it is imported (not re-declared) so the two cannot drift.
FORK_PROMOTION_REFUSE_CEILING_S = DEFAULT_REFUSE_AFTER_S  # 24h.


def detect_fork(a: Checkpoint, b: Checkpoint) -> bool:
    """True iff ``a`` and ``b`` are two views of the same-height spine with a DIFFERENT head — i.e. a
    second concurrent writer produced a divergent owner-signed head. Delegates to the audited
    :func:`vigil_integration.transparency.is_split`; this is a naming facade, not a second detector."""
    return is_split(a, b)


def worst_case_detection_latency_s(cadence_s: int = WITNESS_CHECKPOINT_CADENCE_S) -> int:
    """The worst-case time from a second writer advancing the head to a witness holding both heads at one
    height (so :func:`detect_fork` fires): one witness-checkpoint cadence."""
    return int(cadence_s)


def detection_within_sla(actual_latency_s: float, *, sla_s: int = FORK_DETECTION_SLA_S) -> bool:
    """Whether a MEASURED fork-detection latency meets the SLA. The SLA test drives a checkpoint-comparing
    monitor over a real timeline and asserts the measured latency satisfies this predicate."""
    return 0 <= float(actual_latency_s) <= float(sla_s)
