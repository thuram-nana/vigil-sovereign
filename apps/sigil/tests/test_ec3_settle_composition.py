"""EC-3 (sovereign side) — a budget-stopped run settles consumed-so-far, never stranded, never a free run.

The engine EC-3 hard stop surfaces a budget-exhausted customer run as a PARTIAL EngagementResult that
``run_engagement`` RETURNS (not raises) — so ``engage_worker`` emits a COMPLETED completion signal and the
sovereign ``CompletionSpoolWatcher`` settles the reservation. This pins the sovereign settle DERIVATION the
engine stop composes with (``completion_spool._consumed``): a COMPLETED run consumes the full reserved units
FLAT-PER-RUN; a FAILED/canceled run consumes 0 (full refund — the FREE-RUN path a budget stop must NOT take).

Because the engine stop fires at/below the ceiling (= ``units_reserved × ENVELOPE_TOKENS_PER_CREDIT``),
consumed ≤ the owner-signed reserved envelope, so ``LaunchGate.settle_launch``'s
``refund = reserved − clamp(consumed, 0, reserved)`` stays ≥ 0 and the ``reserved − refund == consumed``
net-spend invariant holds: the reservation is CLOSED (not a stranded reservation), settled ONCE per the
lease's (slug, nonce) (settle_launch is idempotent — not double-charged). Actual-token settlement
(``consumed`` == metered tokens rather than flat-per-run) is a later EC-4 slice; today consumed-so-far is
the full reservation.

Sovereign-only (imports ``sigil.*``): assert_no_offense() forbids this in any process that has loaded the
offense engine (``framework.*``), so it lives on the sovereign leg, apart from the engine EC-3 tests.
"""
from __future__ import annotations

from sigil.inbound.completion_spool import CompletionSpoolWatcher


def test_completed_run_settles_full_reserved_flat_per_run():
    # A budget-stopped PARTIAL surfaces as COMPLETED → settle the full reserved units (consumed-so-far today).
    assert CompletionSpoolWatcher._consumed("completed", 10) == 10
    assert CompletionSpoolWatcher._consumed("completed", 1) == 1


def test_failed_or_canceled_refunds_fully():
    # The FREE-RUN path: a FAILED/canceled run consumes 0 (full refund). run_engagement must RETURN a partial
    # (→ COMPLETED), never re-raise (→ FAILED), so a budget-stopped customer run is NEVER a free run.
    assert CompletionSpoolWatcher._consumed("failed", 10) == 0
    assert CompletionSpoolWatcher._consumed("canceled", 10) == 0


def test_consumed_never_exceeds_reserved_so_refund_is_non_negative():
    # consumed is clamped to the reserved envelope by construction here (flat-per-run == reserved), so the
    # downstream settle_launch refund (reserved − consumed) can never go negative for a stopped run.
    for reserved in (1, 5, 100):
        consumed = CompletionSpoolWatcher._consumed("completed", reserved)
        assert 0 <= consumed <= reserved
        assert reserved - consumed == 0           # net spend == reserved (flat-per-run), refund 0
