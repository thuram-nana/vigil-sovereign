"""Per-agent daily budgets (SIGIL §5) — action, interrupt, and provider TOKEN + COST caps, enforced
FAIL-CLOSED (at/over cap → deny). The spine IS the ledger: every dimension is derived by scanning an
agent's own records for the UTC day, so there is no separate counter to drift or forge. Tokens and
cost live in the action record's payload (`payload["usage"]`), stamped at dispatch WHEN a provider
call supplied them — so `spent()` derives them exactly as it derives actions/interrupts. Caps default
to None (uncapped) → every dimension is opt-in and the default dispatch behavior is byte-identical
until a cap is set; a configured cap is hard-enforced.

Cost is FROZEN INTO THE RECORD at stamp time (from the price table below, or an explicit `cost_usd`),
never re-derived at read time: the immutable spine is authoritative, so editing the price table never
rewrites history. Token/cost were the documented seam in the action/interrupt-only version — this
closes it without introducing a mutable counter. Tokens (input+output) are ALWAYS derivable from the
datum; cost is best-effort (an unpriced model with no explicit `cost_usd` contributes 0 to the COST
meter — its tokens still meter), so `daily_tokens` is the hard metering dimension and `daily_cost_usd`
is enforced against whatever cost the record froze."""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Optional, Tuple

from ..spine.snapshot import SnapshotState

# Default per-model prices in USD per 1,000,000 tokens, as (input, output). DATA, not policy — override
# or extend via ~/.sigil/prices.json or the SIGIL_MODEL_PRICES env (JSON), both merged OVER these. Keyed
# by model id and provider-agnostic (add any vendor's models the same way). The Anthropic rows are the
# published list prices as of 2026-06-24; `local` (Ollama / any fully-offline model) is $0. A model with
# no row (and no explicit cost_usd on its Usage) contributes 0 to the COST meter — its TOKENS still meter.
DEFAULT_PRICES: dict[str, tuple[float, float]] = {
    "claude-fable-5": (10.0, 50.0),
    "claude-opus-4-8": (5.0, 25.0),
    "claude-opus-4-7": (5.0, 25.0),
    "claude-sonnet-5": (3.0, 15.0),
    "claude-sonnet-4-6": (3.0, 15.0),
    "claude-haiku-4-5": (1.0, 5.0),
    "local": (0.0, 0.0),
}


def _coerce_rate(v: object) -> Optional[tuple[float, float]]:
    """A price-table row → an (input, output) per-MTok tuple. Accepts `[in, out]` / `(in, out)` or
    `{"input": in, "output": out}`; a malformed row is ignored (returns None) so a bad override file
    never silently zeroes a known model or crashes the gate."""
    try:
        if isinstance(v, dict):
            return float(v["input"]), float(v["output"])
        if isinstance(v, (list, tuple)) and len(v) == 2:
            return float(v[0]), float(v[1])
    except (TypeError, ValueError, KeyError):
        return None
    return None


def _merge_prices(dst: dict[str, tuple[float, float]], src: object) -> None:
    if not isinstance(src, dict):
        return
    for model, row in src.items():
        rate = _coerce_rate(row)
        if rate is not None and isinstance(model, str):
            dst[model] = rate


def load_prices() -> dict[str, tuple[float, float]]:
    """The active price table: DEFAULT_PRICES overlaid with ~/.sigil/prices.json and then the
    SIGIL_MODEL_PRICES env var (JSON), each a {model: [input_per_mtok, output_per_mtok]} map. Absent or
    malformed sources are ignored (prices are opt-in refinements; a bad file never crashes the gate or
    silently zeroes a known model)."""
    prices = dict(DEFAULT_PRICES)
    import json
    import os
    try:
        from ..config import SIGIL_HOME
        f = SIGIL_HOME / "prices.json"
        if f.exists():
            _merge_prices(prices, json.loads(f.read_text(encoding="utf-8")))
    except (OSError, ValueError, TypeError):
        pass
    raw = os.environ.get("SIGIL_MODEL_PRICES")
    if raw:
        try:
            _merge_prices(prices, json.loads(raw))
        except ValueError:
            pass
    return prices


@dataclass(frozen=True)
class Usage:
    """Provider token usage for ONE action, provider-agnostic. `cost_usd`, when None, is derived at
    stamp time from the price table for `model` (input+output × per-MTok rate); pass an explicit
    `cost_usd` to override (e.g. a metered invoice figure). `to_payload()` produces the datum recorded
    on the spine — the ONLY place token/cost live, so the ledger cannot be forged apart from the log.
    No secrets: only counts, a model id, and a number ever enter the payload."""
    input_tokens: int = 0
    output_tokens: int = 0
    model: str = ""
    cost_usd: Optional[float] = None

    def compute_cost(self, prices: Optional[dict[str, tuple[float, float]]] = None) -> float:
        """USD cost of this action. An explicit `cost_usd` wins; otherwise price `model` from the table
        (input+output tokens × per-MTok rate). An unpriced model → 0.0 (tokens still meter)."""
        if self.cost_usd is not None:
            return float(self.cost_usd)
        table = prices if prices is not None else load_prices()
        rate = table.get(self.model)
        if rate is None:
            return 0.0
        in_rate, out_rate = rate
        return (self.input_tokens / 1_000_000.0) * in_rate + (self.output_tokens / 1_000_000.0) * out_rate

    def to_payload(self, prices: Optional[dict[str, tuple[float, float]]] = None) -> dict:
        """The immutable metering datum stamped into the action record's payload. Cost is frozen HERE,
        so a later price-table edit never rewrites past spend."""
        return {
            "input_tokens": int(self.input_tokens),
            "output_tokens": int(self.output_tokens),
            "model": self.model,
            "cost_usd": round(self.compute_cost(prices), 6),
        }


@dataclass(frozen=True)
class Spend:
    """What an agent has spent today, every field derived from the spine (never a stored counter).
    `tokens` is input+output summed; `cost_usd` is the sum of the frozen per-record costs."""
    actions: int = 0
    interrupts: int = 0
    tokens: int = 0
    cost_usd: float = 0.0


@dataclass(frozen=True)
class BudgetCaps:
    daily_actions: Optional[int] = None       # max records an agent may write per UTC day
    daily_interrupts: Optional[int] = None    # max A1 events/alerts (the noise budget) per UTC day
    daily_tokens: Optional[int] = None        # max provider tokens (input+output) per UTC day
    daily_cost_usd: Optional[float] = None    # max provider spend in USD per UTC day


def _as_int(v: object) -> int:
    """Defensive coercion for a usage value read off the spine — a forged/hand-written datum must not
    crash the enforcement path (mirrors the spine reader's skip-malformed posture) NOR evade the cap.
    CLAMPED to >= 0: a NEGATIVE token count must not CANCEL real spend — `spent()` sums the signed
    per-record values, so a negative would zero the meter (fail-OPEN, a full cap bypass). Junk / a
    too-large int (OverflowError) → 0."""
    if isinstance(v, (int, float, str)):
        try:
            return max(0, int(v))
        except (TypeError, ValueError, OverflowError):
            return 0
    return 0


def _as_float(v: object) -> float:
    """As `_as_int`, CLAMPED to >= 0.0 (a negative cost must not cancel spend — fail-open), and mapping a
    non-finite value (NaN/±inf) to 0.0 (a forged NaN cost would sum to NaN and slip the `cost >= cap`
    check). Catches OverflowError too: a forged huge-INTEGER cost (a 400-digit JSON int, which json.loads
    returns as a Python int, not inf) would otherwise raise `float()`→OverflowError and CRASH the gate —
    bricking the agent's dispatch for the whole UTC day and crashing `sigil budget`."""
    if isinstance(v, (int, float, str)):
        try:
            f = float(v)
        except (TypeError, ValueError, OverflowError):
            return 0.0
        if not math.isfinite(f) or f < 0.0:
            return 0.0
        return f
    return 0.0


class BudgetLedger:
    def __init__(self, store, caps: Optional[BudgetCaps] = None):
        self.store = store
        self.caps = caps or BudgetCaps()

    def spent(self, agent: str, day_iso: str) -> Spend:
        """Today's spend for `agent`: actions, interrupt events, tokens (input+output), and USD cost —
        all counted from the agent's own records for the UTC date `day_iso` (the ts is informational,
        so bucketing is by wallclock date). Token/cost come from `payload["usage"]`, derived the SAME
        way as actions so there is nothing separate to drift or forge.

        Hard-prune (NO-FOLD bearer): budget keeps NO snapshot sub-state — it seeds from the ZERO (identity)
        Spend and windows to the LIVE records `[st.base_seq..T]`. This is EXACT for the enforced current-day
        query because the prune's RETENTION INVARIANT keeps the current UTC day live: every pruned record
        (seq < base_seq) bears a `ts` strictly BEFORE today, so it would fail the `startswith(day_iso)` filter
        regardless — the pruned prefix contributes ZERO to a current-day count, so there is nothing to fold.
        Under the empty (Slice-C) snapshot base_seq==0 => since_seq=-1 => the current full genesis scan, and
        the ZERO seed is the current init => BYTE-IDENTICAL to today's behavior. (A caller passing a PAST
        day_iso — e.g. report() — may under-count post-prune: the accepted live-meter semantic.)"""
        st = SnapshotState.load(self.store)
        # Retention invariant (Slice D/E prune): the current UTC day stays live, so no pruned record bears
        # today's date; over_budget() only ever calls spent() with the CURRENT day, so this windowed live
        # scan is EXACT for enforcement. Seed ZERO (budget has no sub-state) + window at base_seq-1; under
        # the empty snapshot base_seq==0 => since_seq=-1 == the current full scan (byte-identical).
        actions = interrupts = tokens = 0
        cost = 0.0
        for r in self.store.iter_records(since_seq=st.base_seq - 1):
            if r.source != "agent" or r.actor != agent:
                continue
            if not (r.ts or "").startswith(day_iso):
                continue
            # count only actions actually TAKEN (auto/queued) — a denial consumes no budget, so a flood
            # of denied attempts can't self-reinforce the cap. A denied record carries no `usage` (the
            # refusal record has none), so this same gate keeps token/cost fail-closed too.
            if r.payload.get("decision") not in ("auto", "queued"):
                continue
            actions += 1
            if r.kind == "event":
                interrupts += 1
            u = r.payload.get("usage")
            if isinstance(u, dict):
                tokens += _as_int(u.get("input_tokens")) + _as_int(u.get("output_tokens"))
                cost += _as_float(u.get("cost_usd"))
        return Spend(actions=actions, interrupts=interrupts, tokens=tokens, cost_usd=cost)

    def over_budget(self, agent: str, day_iso: str) -> Tuple[bool, str]:
        """Fail-closed: at/over ANY configured cap → (True, reason). All caps None → never over (opt-in;
        default dispatch unchanged). A denied action wrote no `usage`, so it never advances the meter."""
        caps = self.caps
        if (caps.daily_actions is None and caps.daily_interrupts is None
                and caps.daily_tokens is None and caps.daily_cost_usd is None):
            return False, ""
        s = self.spent(agent, day_iso)
        if caps.daily_actions is not None and s.actions >= caps.daily_actions:
            return True, f"daily action cap ({caps.daily_actions}) reached for {agent}"
        if caps.daily_interrupts is not None and s.interrupts >= caps.daily_interrupts:
            return True, f"daily interrupt cap ({caps.daily_interrupts}) reached for {agent}"
        if caps.daily_tokens is not None and s.tokens >= caps.daily_tokens:
            return True, f"daily token cap ({caps.daily_tokens}) reached for {agent}"
        if caps.daily_cost_usd is not None and s.cost_usd >= caps.daily_cost_usd:
            return True, f"daily cost cap (${caps.daily_cost_usd:g}) reached for {agent}"
        return False, ""

    def report(self, day_iso: str) -> dict[str, dict]:
        """Per-agent {actions, interrupts, tokens, cost_usd} for `day_iso` (UTC date prefix) — the
        read-only view behind `sigil budget`. Single spine scan; counts only actions actually TAKEN
        (auto/queued), mirroring the enforced ledger, so a denial never inflates the report.

        Hard-prune note: this is a live-meter view, so post-prune a report for a PAST day_iso may UNDER-COUNT
        — the records for a pruned past day are physically gone and budget keeps no folded per-day sub-state
        to recover them (the accepted live-meter semantic). The CURRENT-day report stays exact: the prune's
        retention invariant keeps today's records live, so `iter_records()` still sees every one of them."""
        out: dict[str, dict] = {}
        for r in self.store.iter_records():
            if r.source != "agent":
                continue
            if not (r.ts or "").startswith(day_iso):
                continue
            if r.payload.get("decision") not in ("auto", "queued"):
                continue
            a = out.setdefault(r.actor, {"actions": 0, "interrupts": 0, "tokens": 0, "cost_usd": 0.0})
            a["actions"] += 1
            if r.kind == "event":
                a["interrupts"] += 1
            u = r.payload.get("usage")
            if isinstance(u, dict):
                a["tokens"] += _as_int(u.get("input_tokens")) + _as_int(u.get("output_tokens"))
                a["cost_usd"] += _as_float(u.get("cost_usd"))
        for a in out.values():
            a["cost_usd"] = round(a["cost_usd"], 6)
        return out
