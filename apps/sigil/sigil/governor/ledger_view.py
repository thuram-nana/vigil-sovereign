"""Front C S0d — the cached view of an owner-signed reserve/settle LEDGER (the EC-4/EC-5 cost ledger and the
postpaid arrears ledger), kept in step by the verified fold cache (`spine/fold_cache.py`).

Both ledgers have the same shape: two signals, an UP side (`cost_reserve` / `postpaid_debit`) and a DOWN side
(`cost_settle` / `postpaid_credit`), summed per org, idempotent per `(signal, org_id, entry_id)` through ONE
consumed `seen` set, and an IN-FLIGHT pairing: an UP record under the reserve prefix whose matching DOWN record
under the settle prefix (same `{slug}:{nonce}` suffix, same org) has not landed is a reservation still in flight.

The registry's shared fold step (`_apply_*_record`, the SAME body its unchanged full fold runs) updates the
totals and `seen` and reports each COUNTED record; `PairedLedgerView.pair` then keeps the in-flight pairing in
step, exactly as the full per-org scan (`_in_flight` / `in_flight_reserved`) and the global one-pass scan
(`global_position`) compute it:

  * `reserves[(org, suffix)]` — the amount of a counted UP record under the reserve prefix. Like the full scans
    it holds the LIVE window only: the hard-prune seed carries the totals and `seen`, never per-reserve amounts
    (`stranded_active_*_reserves` refuses a prune that would archive an unsettled reserve);
  * `settled` — the `(org, suffix)` pairs whose DOWN record under the settle prefix has been counted;
  * `in_flight[org]` / `in_flight_total` — Σ `reserves` not in `settled`, per org and across all orgs, moved
    by each counted record instead of re-summed per read;
  * `down_total` — Σ DOWN amounts across all orgs, seeded from the seed's DOWN totals (the cost ledger's
    global committed cost).

Pairs are keyed per org, so a cross-tenant suffix collision never pairs. A record is counted at most once (the
shared step's `seen` check), so `pair` never sees a replay.

FATAL-2: sovereign-side. No framework/strix import.
"""
from __future__ import annotations

from ..reuse import assert_no_offense

assert_no_offense()

__all__ = ["PairedLedgerView"]


class PairedLedgerView:
    """The cached fold of one reserve/settle ledger: the full fold's `(up, down, seen)` plus the in-flight
    pairing (see the module docstring)."""

    __slots__ = ("up", "down", "seen", "reserves", "settled", "in_flight", "in_flight_total", "down_total",
                 "_up_signal", "_reserve_prefix", "_settle_prefix")

    def __init__(self, up: dict, down: dict, seen: set, *, up_signal: str, reserve_prefix: str,
                 settle_prefix: str) -> None:
        self.up, self.down, self.seen = up, down, seen
        self._up_signal, self._reserve_prefix, self._settle_prefix = up_signal, reserve_prefix, settle_prefix
        self.reserves: dict = {}
        self.settled: set = set()
        self.in_flight: dict = {}
        self.in_flight_total = 0
        self.down_total = sum(down.values())

    def pair(self, sig: str, oid: str, eid: str, amount: int) -> None:
        """Keep the in-flight pairing in step with ONE counted record."""
        if sig == self._up_signal:
            if eid.startswith(self._reserve_prefix):
                # each pair key is met at most ONCE per side: entry_id == prefix + suffix, and the shared step
                # counts a (signal, org, entry_id) at most once
                k = (oid, eid[len(self._reserve_prefix):])
                self.reserves[k] = amount
                if k not in self.settled:
                    self._move(oid, amount)
            return
        self.down_total += amount
        if eid.startswith(self._settle_prefix):
            k = (oid, eid[len(self._settle_prefix):])
            self.settled.add(k)
            self._move(oid, -self.reserves.get(k, 0))

    def _move(self, oid: str, delta: int) -> None:
        if not delta:
            return
        n = self.in_flight.get(oid, 0) + delta
        if n:
            self.in_flight[oid] = n
        else:
            self.in_flight.pop(oid, None)
        self.in_flight_total += delta
