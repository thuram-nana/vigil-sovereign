"""aegis.impact_budget — AS-5e: the gateway IMPACT BUDGET (deterministic read-only rollup over AS-5d receipts).

The AS-5a capacity plane decides admit/shed, the prove-don't-guess gate decides allow/block, and AS-5d minted an
append-only, hash-linked RECEIPT for the OUTCOME of each enforced request (``allowed`` / ``shed`` / ``blocked``).
Every ``shed`` and every ``blocked`` DENIES a request — that denied traffic is the IMPACT the gateway's operation
has on availability. An operator running a firewall in front of their own app needs one number they do not have
yet: *how much is enforcement costing availability right now, and is that cost inside the budget I accept?*

AS-5e answers exactly that, and NOTHING more. It is a deterministic, READ-ONLY ROLLUP over the AS-5d receipt
chain: over a bounded recent window it tallies allowed / shed / blocked, computes the DENIED RATIO
(``(shed + blocked) / considered``), compares it against a configured budget ceiling, and surfaces the result
read-only on the AS-5c probe snapshot — the same address-free, metadata-only discipline AS-5a/AS-5c/AS-5d serve.
It is the availability-SLO counterpart to AS-5d's "what did enforcement do?": "how much did enforcement cost, and
is that inside budget?". It also breaks the impact down by the receipts' machine ``reason`` (shed reason /
blocked attack-class), the per-category tally AS-5b's attribution surface consumes.

Doctrine (non-negotiable, enforced here and tested):
  * A ROLLUP MEASURES, IT NEVER ACTS. Being OVER budget mints no certificate, no verdict, and takes NO response
    action. It can never loosen enforcement (that would weaken security) and can never tighten it (only a fired
    oracle blocks; shedding is always permitted, availability-first). The impact budget is pure after-the-fact
    telemetry — exactly like the AS-5d snapshot and the AS-5a capacity signal. It is NEVER a cause of, nor an
    input to, any admit/shed/allow/block decision.
  * READ-ONLY OVER THE LEDGER. The rollup only READS the receipt ledger (its retained window, its total, its
    head); it NEVER appends, edits, reorders, or drops a receipt. The ledger stays the single append-only source
    of truth; AS-5e holds no mutable ledger state of its own.
  * COMPUTED FROM THE VERIFIED CHAIN. The rollup re-verifies the receipt chain (AS-5d's own ``verify`` / static
    ``verify_chain``) and reports that as a ``verified`` flag: a tampered / reordered / dropped chain is DETECTED
    and the rollup says so, so a consumer never trusts a ratio computed over an edited history.
  * DETERMINISM. The aggregation math is a pure function of the receipt fields and the budget — no wall-clock and
    no RNG. The recent window is defined by COUNT (the last ``window`` receipts), not by a wall-clock interval, so
    the rollup needs no clock at all: the receipts already carry AS-5d's INJECTED monotonic reading. A fixed set
    of receipts over a fixed budget yields a byte-identical summary.
  * METADATA ONLY. The summary carries counts, the ratio, the budget ceiling, the bounded per-reason tally, the
    chain head and the verified flag — NEVER a raw caller address, NEVER request/response bytes, NEVER a secret.
    The per-reason breakdown is bounded (top-``_MAX_REASONS`` by count) so a caller-influenced category string
    cannot bloat the snapshot, on top of AS-5d's own per-reason length bound.
  * TOTAL + FAIL-SAFE. The rollup is read at probe time only; a rollup fault is contained by the gateway (the
    probe wraps it) and degrades the one field, never the probe and never the data path.

DEFAULT-OFF: nothing here runs unless the strict, fail-closed ``VIGIL_AEGIS_IMPACT_BUDGET`` flag is set AND its
underlying dependency — the AS-5d receipt ledger (``VIGIL_AEGIS_RECEIPTS``) — is itself armed (there is no chain
to roll up otherwise). OFF ⇒ the gateway builds no meter, computes nothing, and its data path AND the AS-5c probe
snapshot are byte-identical to an AS-5d gateway without the feature.

FATAL-2: engine leg — imports ONLY the stdlib (plus its sibling AS-5d ``receipts`` plane by RELATIVE import, for
the canonical chain verifier — the single source of truth, never re-implemented). No ``vigil_core`` (nothing here
needs the shared contracts), no ``sigil``/``governor``/``strix``/``apps``, nothing on the scan/engage/benchmark
gate path. It adds NO OracleKind and registers NO vocabulary, so the make-gate byte-identity is structurally
untouched.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from .receipts import Outcome, Receipt, ReceiptLedger

__all__ = [
    "IMPACT_BUDGET_ENV",
    "ImpactBudget",
    "ImpactSummary",
    "ImpactBudgetMeter",
    "impact_budget_enabled",
    "summarize",
]

# The default-OFF switch for the impact-budget rollup — strict, fail-closed, read when the gateway is built and
# re-read per snapshot (so a live flip-OFF stops surfacing it at once). Only an explicit affirmative token turns
# it on; anything else (unset, typo, "0", "false") keeps it OFF — mirrors ``receipts.receipts_enabled`` /
# ``capacity.capacity_enabled`` exactly.
IMPACT_BUDGET_ENV = "VIGIL_AEGIS_IMPACT_BUDGET"

# Default recent-window size (in receipts) and default denied-ratio ceiling. The window is COUNT-based (the last
# N receipts), which needs no clock; it is naturally bounded by the ledger's own retained read-back window.
_DEFAULT_WINDOW = 1024
_DEFAULT_MAX_DENIED_RATIO = 0.5

# Bound the per-reason breakdown emitted in the snapshot (top-N by count): a caller-influenced ``reason`` string
# must not be able to bloat the operator-facing summary, on top of AS-5d's own per-receipt reason length bound.
_MAX_REASONS = 32


def impact_budget_enabled() -> bool:
    """Is the impact-budget rollup armed? Strict, fail-closed, DEFAULT OFF — only an explicit affirmative token
    arms it (mirrors ``receipts.receipts_enabled`` / ``capacity.capacity_enabled``). The gateway still builds a
    meter only when this is True AND the AS-5d receipt ledger (its dependency) was itself built."""
    return (os.environ.get(IMPACT_BUDGET_ENV) or "").strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class ImpactBudget:
    """The configured impact budget a gateway rolls receipts up against.

    * ``max_denied_ratio`` — the ceiling: the largest fraction of recent outcomes that may be DENIED
      (``shed + blocked``) before the gateway is reported OVER budget. In ``[0.0, 1.0]`` (0.0 = any denial is
      over budget; 1.0 = never over budget).
    * ``window``           — the recent window, in receipts: the rollup considers at most the last ``window``
      receipts of the ledger's retained read-back window. ``>= 1``.

    Fail-closed construction: an out-of-range ratio or a non-positive window is a configuration error, not a
    silently-clamped field."""

    max_denied_ratio: float = _DEFAULT_MAX_DENIED_RATIO
    window: int = _DEFAULT_WINDOW

    def __post_init__(self) -> None:
        if not (isinstance(self.max_denied_ratio, (int, float)) and 0.0 <= self.max_denied_ratio <= 1.0):
            raise ValueError("ImpactBudget.max_denied_ratio must be a number in [0.0, 1.0]")
        if not (isinstance(self.window, int) and not isinstance(self.window, bool) and self.window >= 1):
            raise ValueError("ImpactBudget.window must be an integer >= 1")

    @classmethod
    def default(cls) -> "ImpactBudget":
        """The built-in default budget (50% denied-ratio ceiling over the last 1024 receipts)."""
        return cls()

    def to_dict(self) -> "dict[str, object]":
        """A plain-dict view of the budget config (echoed in the snapshot so a reader sees the ceiling in force)."""
        return {"max_denied_ratio": self.max_denied_ratio, "window": self.window}


@dataclass(frozen=True)
class ImpactSummary:
    """ONE immutable, read-only impact rollup over a receipt window. Metadata only — no caller address, no secret.

    * ``considered``     — number of receipts in the window (``<= budget.window`` and ``<= retained``).
    * ``allowed`` / ``shed`` / ``blocked`` / ``other`` — per-disposition tally within the window (``other`` is any
      non-canonical kind, counted honestly, never silently dropped; it is NOT counted as denied).
    * ``denied``         — ``shed + blocked`` (the requests enforcement DENIED in the window).
    * ``denied_ratio``   — ``denied / considered`` (``0.0`` when the window is empty — no traffic, no impact).
    * ``max_denied_ratio`` / ``window`` — the budget ceiling + window in force (echoed).
    * ``within_budget``  — ``denied_ratio <= max_denied_ratio`` (True on an empty window). Its negation is OVER
      budget. A measurement only — it NEVER drives a decision.
    * ``verified``       — did the receipt chain re-verify (AS-5d ``verify_chain`` + tie to the head)? A tampered
      / reordered / dropped chain is DETECTED here; a consumer must not trust the ratio when this is False.
    * ``denied_reasons`` — a bounded (top-``_MAX_REASONS``) tally of the machine ``reason`` of the DENIED receipts
      in the window (shed reasons + blocked attack-classes): the impact breakdown AS-5b attribution consumes.
    * ``total``          — the ledger's lifetime receipt count (ties the window back to the whole history).
    * ``head``           — the chain head the rollup read (the AS-5d commitment over the whole history)."""

    considered: int
    allowed: int
    shed: int
    blocked: int
    other: int
    denied: int
    denied_ratio: float
    max_denied_ratio: float
    window: int
    within_budget: bool
    verified: bool
    total: int
    head: str
    denied_reasons: "dict[str, int]" = field(default_factory=dict)

    def to_dict(self) -> "dict[str, object]":
        """A plain-dict view for the read-only probe surface / an offline consumer. Metadata only."""
        return {
            "considered": self.considered,
            "allowed": self.allowed,
            "shed": self.shed,
            "blocked": self.blocked,
            "other": self.other,
            "denied": self.denied,
            "denied_ratio": self.denied_ratio,
            "max_denied_ratio": self.max_denied_ratio,
            "window": self.window,
            "within_budget": self.within_budget,
            "over_budget": not self.within_budget,
            "verified": self.verified,
            "denied_reasons": dict(self.denied_reasons),
            "total": self.total,
            "head": self.head,
        }


def _bounded_reason_tally(reasons: "dict[str, int]") -> "dict[str, int]":
    """Reduce a full per-reason tally to the top-``_MAX_REASONS`` by count. Deterministic tie-break: descending
    count, then ascending reason — so the emitted breakdown is a pure, reproducible function of the receipts."""
    if len(reasons) <= _MAX_REASONS:
        return dict(reasons)
    top = sorted(reasons.items(), key=lambda kv: (-kv[1], kv[0]))[:_MAX_REASONS]
    return dict(top)


def summarize(receipts: "tuple[Receipt, ...] | list[Receipt]", budget: ImpactBudget, *,
              verified: bool, total: int, head: str) -> ImpactSummary:
    """Roll a receipt window up into an :class:`ImpactSummary`. PURE and DETERMINISTIC: a function of the receipt
    fields and the budget only — no wall-clock, no RNG. The recent window is the LAST ``budget.window`` receipts
    of ``receipts`` (count-based, so no clock is needed). ``verified`` is the chain-verification result the caller
    computed (race-free) over the SAME receipts; it is surfaced as-is so a consumer never trusts a ratio over an
    edited chain. ``total`` / ``head`` are the ledger's lifetime count and current chain head, echoed as
    metadata.

    The math MEASURES; it never acts. ``within_budget`` is a reported comparison, never an enforcement input."""
    window = tuple(receipts[-budget.window:]) if budget.window < len(receipts) else tuple(receipts)
    allowed = shed = blocked = other = 0
    reasons: "dict[str, int]" = {}
    for r in window:
        if r.outcome == Outcome.ALLOWED:
            allowed += 1
        elif r.outcome == Outcome.SHED:
            shed += 1
            reasons[r.reason] = reasons.get(r.reason, 0) + 1
        elif r.outcome == Outcome.BLOCKED:
            blocked += 1
            reasons[r.reason] = reasons.get(r.reason, 0) + 1
        else:
            # A non-canonical kind (the ledger records it honestly under its own key). Counted, but NOT denied —
            # the impact budget is about the canonical enforcement dispositions, and an unknown kind never inflates
            # the denied ratio.
            other += 1
    considered = len(window)
    denied = shed + blocked
    denied_ratio = (denied / considered) if considered else 0.0
    within_budget = denied_ratio <= budget.max_denied_ratio
    return ImpactSummary(
        considered=considered, allowed=allowed, shed=shed, blocked=blocked, other=other,
        denied=denied, denied_ratio=denied_ratio, max_denied_ratio=budget.max_denied_ratio,
        window=budget.window, within_budget=within_budget, verified=bool(verified),
        total=int(total), head=str(head), denied_reasons=_bounded_reason_tally(reasons),
    )


class ImpactBudgetMeter:
    """The read-only impact-budget rollup bound to an AS-5d receipt ledger. Holds NO mutable ledger state — it
    only READS the ledger (its retained window, total, head and integrity) and computes a pure summary, so it is
    inherently thread-safe (the ledger serialises its own reads) and NEVER mutates the append-only chain.

    The meter MEASURES; it never acts: :meth:`snapshot` reports how much enforcement is costing availability and
    whether that is inside budget. It is surfaced read-only on the AS-5c probe snapshot and never touches the
    gateway data path or any admit/shed/allow/block decision."""

    def __init__(self, ledger: ReceiptLedger, budget: "ImpactBudget | None" = None) -> None:
        self._ledger = ledger
        self._budget = budget if budget is not None else ImpactBudget.default()

    @property
    def budget(self) -> ImpactBudget:
        return self._budget

    def summary(self) -> ImpactSummary:
        """Compute the current impact rollup over the ledger's retained window. ``verified`` comes from the
        ledger's own :meth:`ReceiptLedger.verify` (one atomic, race-free read that re-hashes the retained window
        AND ties it to the live head), so a concurrent append between reads can never spuriously flag a tamper;
        the counts come from an atomic snapshot of the same retained window. Read-only throughout."""
        led = self._ledger
        verified = bool(led.verify())        # atomic in the ledger: retained window re-hashed + tied to head
        receipts = led.receipts()            # atomic snapshot copy of the retained window (frozen receipts)
        return summarize(receipts, self._budget, verified=verified, total=led.count, head=led.head)

    def snapshot(self) -> "dict[str, object]":
        """A read-only, metadata-only snapshot of the impact rollup: the window tally, the denied ratio, the
        budget ceiling in force, the within/over-budget verdict, the bounded per-reason breakdown, the chain head
        and the verified flag. Carries NO caller address and NO secret — safe for the AS-5c probe surface,
        mirroring the AS-5a capacity / AS-5d receipts snapshots. The budget config is echoed under ``budget``."""
        snap = self.summary().to_dict()
        snap["budget"] = self._budget.to_dict()
        return snap
