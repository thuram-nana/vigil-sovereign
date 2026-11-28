"""aegis.attribution — AS-5b: the gateway DENIAL-SOURCE ATTRIBUTION rollup (deterministic, read-only, address-free).

The GW "capacity & outcomes" chain measures the DENIED-enforcement load from two angles, but neither carries the
SOURCE of that load:
  * AS-5a capacity decides admit/shed per request and is the ONLY plane that holds PER-CALLER state (a token
    bucket + an in-flight counter per client IP) — but its snapshot is address-free *aggregate* only (how many
    callers, total in-flight), so it never says WHICH callers are driving the shedding.
  * AS-5d receipts record every ``allowed``/``shed``/``blocked`` outcome, and AS-5e rolls them up into the DENIED
    ratio + a bounded per-reason breakdown (the "what" of the denied load) — but a receipt is ADDRESS-FREE, so
    AS-5e itself flagged that *per-caller attribution cannot come from the receipt chain alone*.

AS-5b is exactly the missing SOURCE dimension, and nothing more: a deterministic, READ-ONLY rollup that reads the
AS-5a per-caller buckets and reports WHICH sources currently hold the shed/denial pressure — how concentrated the
load is across callers, how many callers are currently over budget, and a bounded top-N of the heaviest sources —
and pairs it with AS-5e's per-reason breakdown (the "what") so an operator reads the denied load's WHO and WHAT
together. It is surfaced read-only on the AS-5c probe snapshot, in the same metadata-only discipline the rest of
the chain serves.

HONEST LIMIT (stated, not papered over): a receipt carries NO caller key, so AS-5b cannot cross-tabulate
who × what — there is no join key between a denied receipt and the caller that caused it. AS-5b therefore reports
the two dimensions SIDE BY SIDE (the live source concentration from the AS-5a buckets, and the denied-reason tally
from AS-5e), which is the most the chain's data honestly supports. It is a per-source LOAD attribution, not a
per-reason-per-source matrix.

ADDRESS-FREE (the charter's "client addresses are not emitted in metrics"): the AS-5a buckets are keyed by the
RAW client IP, but AS-5b NEVER emits one. Every surfaced source is an OPAQUE id — an HMAC of the caller key under
a per-process salt — so an operator can correlate "the same heavy source across consecutive snapshots" and feed a
targeted investigation WITHOUT the probe surface ever carrying an address. The salt is drawn once at construction
(injectable, fixed in tests) solely so the opaque ids are unlinkable across processes and a low-entropy IP cannot
be recovered by brute force; it is NOT part of the aggregation and changes no count or ratio.

Doctrine (non-negotiable, enforced here and tested):
  * A ROLLUP MEASURES, IT NEVER ACTS. Attribution mints no certificate, no verdict, and takes NO response action.
    Naming a heavy source NEVER sheds, blocks, rate-limits, or evicts it — only a fired oracle blocks, and
    shedding rides solely on the AS-5a budget. Attribution is pure after-the-fact telemetry, exactly like the
    AS-5a capacity signal, the AS-5d receipt snapshot and the AS-5e rollup. It is NEVER a cause of, nor an input
    to, any admit/shed/allow/block decision.
  * READ-ONLY OVER ITS SOURCES. The rollup only READS the capacity governor's per-caller loads (via AS-5a's
    read-only :meth:`CapacityGovernor.caller_loads`, which computes effective tokens WITHOUT writing them back)
    and the AS-5e summary; it NEVER mutates a bucket, a receipt, or any chain state. Any number of snapshots
    leave every admit/shed decision byte-identical.
  * DETERMINISM. The aggregation is a pure function of the per-caller loads, the denied-reason tally and the
    salt — no wall-clock and no RNG in the math. Effective-token pressure reuses AS-5a's INJECTED monotonic clock
    (count/closure-based in tests); the per-process salt is a construction input, so under identical inputs (salt
    included) the summary is byte-identical.
  * ADDRESS-FREE + BOUNDED. The summary carries counts, the concentration ratio, a bounded (top-``_MAX_SOURCES``)
    list of OPAQUE source ids with their load, and the AS-5e reason tally — NEVER a raw caller address, NEVER
    request/response bytes, NEVER a secret. The top-N bound means a spray of distinct source IPs cannot bloat the
    operator-facing snapshot.
  * TOTAL + FAIL-SAFE. The rollup is read at probe time only; a rollup fault is contained by the gateway (the
    probe wraps it) and degrades the one field, never the probe and never the data path.

DEFAULT-OFF: nothing here runs unless the strict, fail-closed ``VIGIL_AEGIS_ATTRIBUTION`` flag is set AND its
dependencies are themselves armed — the AS-5a capacity governor (the per-caller SOURCE signal) AND the AS-5e
impact meter (the denied-reason "what"; itself gated on AS-5d receipts). OFF (or any dep off) ⇒ the gateway builds
no meter, computes nothing, and its data path AND the AS-5c probe snapshot are byte-identical to an AS-5e gateway
without the feature.

FATAL-2: engine leg — imports ONLY the stdlib. It reaches the AS-5a capacity and AS-5e impact planes by RELATIVE
import (for types) and consumes their live objects by injection, so it NEVER re-implements the chain verifier (the
``verified`` flag is AS-5e's, which re-verifies the AS-5d chain). No ``vigil_core``, no
``sigil``/``governor``/``strix``/``apps``, nothing on the scan/engage/benchmark gate path. It adds NO OracleKind
and registers NO vocabulary, so the make-gate byte-identity is structurally untouched.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .capacity import CallerLoad, CapacityGovernor
    from .impact_budget import ImpactBudgetMeter

__all__ = [
    "ATTRIBUTION_ENV",
    "AttributionMeter",
    "AttributionSummary",
    "SourceLoad",
    "attribution_enabled",
    "summarize",
]

# The default-OFF switch for the denial-source attribution rollup — strict, fail-closed, read when the gateway is
# built and re-read per snapshot (so a live flip-OFF stops surfacing it at once). Only an explicit affirmative
# token turns it on; anything else (unset, typo, "0", "false") keeps it OFF — mirrors ``capacity.capacity_enabled``
# / ``impact_budget.impact_budget_enabled`` exactly.
ATTRIBUTION_ENV = "VIGIL_AEGIS_ATTRIBUTION"

# Bound the top-N heaviest sources emitted in the snapshot: a spray of distinct source IPs must not be able to
# bloat the operator-facing summary (on top of AS-5a's own bounded caller map).
_MAX_SOURCES = 16

# The length (hex chars) of an opaque source id. 16 hex = 64 bits of the HMAC — ample to tell distinct sources
# apart within a process while staying compact in the snapshot.
_ID_LEN = 16

# Decimal places the surfaced floats (concentration, per-source deficit) are rounded to, so the summary is
# byte-stable under identical inputs (no last-bit float drift across runs).
_PRECISION = 6


def attribution_enabled() -> bool:
    """Is the denial-source attribution rollup armed? Strict, fail-closed, DEFAULT OFF — only an explicit
    affirmative token arms it (mirrors ``capacity.capacity_enabled`` / ``impact_budget.impact_budget_enabled``).
    The gateway still builds a meter only when this is True AND both dependencies (the AS-5a capacity governor and
    the AS-5e impact meter) exist."""
    return (os.environ.get(ATTRIBUTION_ENV) or "").strip().lower() in ("1", "true", "yes", "on")


def _source_id(salt: bytes, caller: str) -> str:
    """The OPAQUE, address-free id for a caller key: a truncated HMAC-SHA256 of the key under the per-process
    salt. Keyed (not a bare hash) so a low-entropy caller key (an IPv4 address is only 32 bits) cannot be
    recovered by brute force without the salt, and so ids are unlinkable across processes. Deterministic given
    the salt, so the same source maps to the same id across consecutive snapshots (the point of an id: stable
    cross-snapshot correlation without an address)."""
    try:
        raw = str(caller).encode("utf-8", "replace")
    except Exception:
        raw = b""
    return hmac.new(salt, raw, hashlib.sha256).hexdigest()[:_ID_LEN]


def _deficit(tokens: float) -> float:
    """A caller's rate-budget DEFICIT: how far its effective token balance is below the one token a request
    needs, in ``[0.0, 1.0]`` (0.0 when it has a whole token, i.e. would not be rate-shed). The persistent
    rate-shed pressure signal (a depleted bucket stays depleted until it refills)."""
    return max(0.0, 1.0 - tokens)


def _pressure(load: "CallerLoad") -> float:
    """A caller's current denial PRESSURE: its concurrency (in-flight slots held) plus its sub-token rate deficit
    (``[0.0, 1.0)``). In-flight dominates (held concurrency is the primary load); the deficit is a persistent
    fine-grained floor so a rate-depleted caller with no live request still ranks above a fully-idle one. A pure
    function of the load — the basis for both the ranking and the concentration ratio."""
    return float(load.inflight) + _deficit(load.tokens)


@dataclass(frozen=True)
class SourceLoad:
    """ONE heavy source's address-free load line. Metadata only — an OPAQUE id, never a raw caller address.

    * ``id``       — the opaque, per-process-stable source id (see :func:`_source_id`).
    * ``inflight`` — concurrent in-flight requests this source currently holds.
    * ``depleted`` — the source's rate bucket is below one token: a request now would be rate-shed.
    * ``deficit``  — the rate-budget deficit in ``[0.0, 1.0]`` (rounded), 0.0 when not depleted."""

    id: str
    inflight: int
    depleted: bool
    deficit: float

    def to_dict(self) -> "dict[str, object]":
        return {"id": self.id, "inflight": self.inflight, "depleted": self.depleted, "deficit": self.deficit}


@dataclass(frozen=True)
class AttributionSummary:
    """ONE immutable, read-only denial-source attribution rollup. Metadata only — no caller address, no secret.

    THE WHO (from the AS-5a per-caller buckets):
    * ``tracked``       — distinct callers the capacity plane is currently tracking (ties to the AS-5a snapshot).
    * ``constrained``   — how many of those callers are CURRENTLY over budget (depleted bucket OR at the
      per-caller concurrency cap), i.e. actively being shed — the count driving the denial pressure.
    * ``inflight``      — total concurrent in-flight requests across all tracked callers.
    * ``concentration`` — the single heaviest source's share of the total current pressure, in ``[0.0, 1.0]``
      (rounded); 0.0 when there is no pressure. High ⇒ one source is driving the denials; low ⇒ it is spread.
    * ``sources``       — a bounded (top-``_MAX_SOURCES``) list of the heaviest sources with pressure > 0, each
      an address-free :class:`SourceLoad`, ranked deterministically (pressure desc, then opaque id asc).

    THE WHAT (consumed from the AS-5e impact rollup — a receipt carries no caller, so this cannot be joined to a
    specific source; it is the independent reason breakdown of the denied load):
    * ``reasons``       — the bounded per-reason tally of the DENIED receipts (shed reasons + blocked
      attack-classes) AS-5e computed over its window.
    * ``verified``      — AS-5e's chain-verified flag (the AS-5d receipt chain re-verified): the ``reasons``
      breakdown is trustworthy only when this is True."""

    tracked: int
    constrained: int
    inflight: int
    concentration: float
    verified: bool
    sources: "tuple[SourceLoad, ...]" = field(default_factory=tuple)
    reasons: "dict[str, int]" = field(default_factory=dict)

    def to_dict(self) -> "dict[str, object]":
        """A plain-dict view for the read-only probe surface / an offline consumer. Metadata only."""
        return {
            "tracked": self.tracked,
            "constrained": self.constrained,
            "inflight": self.inflight,
            "concentration": self.concentration,
            "verified": self.verified,
            "sources": [s.to_dict() for s in self.sources],
            "reasons": dict(self.reasons),
        }


def summarize(loads: "tuple[CallerLoad, ...] | list[CallerLoad]", reasons: "dict[str, int]", *,
              verified: bool, salt: bytes) -> AttributionSummary:
    """Roll per-caller loads + the AS-5e denied-reason tally up into an :class:`AttributionSummary`. PURE and
    DETERMINISTIC: a function of the loads, the reason tally and the salt only — no wall-clock, no RNG. The salt
    makes the surfaced source ids opaque/unlinkable; it is NOT part of any count or ratio.

    The math MEASURES; it never acts. ``concentration`` is a reported statistic, never an enforcement input."""
    tracked = len(loads)
    constrained = sum(1 for cl in loads if cl.depleted or cl.at_cap)
    inflight = sum(int(cl.inflight) for cl in loads)

    pressures = [(_pressure(cl), cl) for cl in loads]
    total_pressure = sum(p for p, _ in pressures)
    top_pressure = max((p for p, _ in pressures), default=0.0)
    concentration = round(top_pressure / total_pressure, _PRECISION) if total_pressure > 0 else 0.0

    # The heaviest sources with real pressure, ranked deterministically: pressure desc, then the opaque id asc
    # (address-free tie-break — never the raw caller key), bounded to the top-N.
    active = [(p, _source_id(salt, cl.caller), cl) for p, cl in pressures if p > 0.0]
    active.sort(key=lambda t: (-t[0], t[1]))
    sources = tuple(
        SourceLoad(id=sid, inflight=int(cl.inflight), depleted=bool(cl.depleted),
                   deficit=round(_deficit(cl.tokens), _PRECISION))
        for _p, sid, cl in active[:_MAX_SOURCES]
    )
    return AttributionSummary(
        tracked=tracked, constrained=constrained, inflight=inflight, concentration=concentration,
        verified=bool(verified), sources=sources, reasons=dict(reasons),
    )


class AttributionMeter:
    """The read-only denial-source attribution rollup, bound to an AS-5a capacity governor (the per-caller SOURCE
    signal) and an AS-5e impact meter (the denied-reason "what"). Holds NO mutable state of its own beyond its
    opaque-id salt — it only READS its two sources and computes a pure summary, so it is inherently thread-safe
    (each source serialises its own reads) and NEVER mutates a bucket, a receipt, or any chain state.

    The meter MEASURES; it never acts: :meth:`snapshot` reports which sources hold the current shed/denial
    pressure and how concentrated it is, paired with AS-5e's reason breakdown. It is surfaced read-only on the
    AS-5c probe snapshot and never touches the gateway data path or any admit/shed/allow/block decision."""

    def __init__(self, governor: "CapacityGovernor", impact_meter: "ImpactBudgetMeter", *,
                 source_salt: "bytes | None" = None) -> None:
        self._governor = governor
        self._impact = impact_meter
        # Drawn ONCE at construction (injectable, fixed in tests). Not part of the aggregation — it only makes the
        # surfaced source ids opaque and unlinkable across processes. A per-process random default is the
        # security-correct choice: a fixed/derivable salt would let a 32-bit IPv4 key be recovered from its id.
        self._salt = source_salt if source_salt is not None else secrets.token_bytes(16)

    def summary(self, *, now: "float | None" = None) -> AttributionSummary:
        """Compute the current attribution rollup. Reads the governor's per-caller loads (read-only; effective
        tokens computed at ``now`` — the injected clock by default — without writeback) and the AS-5e summary
        (its denied-reason tally + chain-verified flag). Read-only throughout; never mutates a source."""
        loads = self._governor.caller_loads(now=now)
        imp = self._impact.summary()
        return summarize(loads, imp.denied_reasons, verified=imp.verified, salt=self._salt)

    def snapshot(self, *, now: "float | None" = None) -> "dict[str, object]":
        """A read-only, metadata-only snapshot of the denial-source attribution: the source concentration + the
        bounded top-N opaque sources (the WHO), paired with the AS-5e denied-reason tally + verified flag (the
        WHAT). Carries NO caller address and NO secret — safe for the AS-5c probe surface, mirroring the AS-5a
        capacity / AS-5d receipts / AS-5e impact snapshots."""
        return self.summary(now=now).to_dict()
