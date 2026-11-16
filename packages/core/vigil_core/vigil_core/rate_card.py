"""The published usage RATE CARD — what each billable unit costs a customer, in credits (pricing design §0.2).

VIGIL bills prepaid credits by measured consumption (design §0, the owner's decision of 2026-11-16). Every customer
charge is a line on this card: a quantity of one billable unit times its published rate. The card is in CREDITS only
(``$1 = 100 credits``); no customer-facing amount is ever a computed money cost, and nothing here estimates, predicts
or quotes what an assessment will cost (design §0.9).

Precision is exact to **0.001 credit** (a *milli-credit*, ``mc``): every rate and every amount is an integer number of
milli-credits, and a line's amount is ``ceil(quantity × rate / per)`` — rounded up only below 0.001 credit, never to a
whole credit. A rate finer than 0.001 credit per its unit is refused, never rounded.

The defaults below are the published rates. The owner changes them without a release through ``VIGIL_RATE_CARD``
(inline JSON, every rate a decimal string of credits); a malformed override raises :class:`RateCardError` and is
never partly applied.

Internal provider cost (``model_metering.cost_nano_usd``) is a separate account kept for SIGIL's own books; it never
feeds this card. stdlib only.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Mapping, Optional

from .model_metering import Usage

__all__ = [
    "MC_PER_CREDIT", "RATE_CARD_ENV", "RateCardError", "Rate", "ChargeLine", "RateCard", "DEFAULT_RATE_CARD",
    "rate_card", "format_credits", "AI_UNITS",
]

#: One credit in milli-credits: amounts are exact to 0.001 credit.
MC_PER_CREDIT = 1000
RATE_CARD_ENV = "VIGIL_RATE_CARD"
_MAX_QUANTITY = 10 ** 15            # bounds a hostile / corrupt quantity far above any real one


class RateCardError(ValueError):
    """A malformed rate, rate card or quantity."""


def _mc(credits: Any, *, what: str) -> int:
    """A decimal number of credits (a string or an int) → integer milli-credits, exactly. A bool, a float, a negative,
    a non-finite value or a value finer than 0.001 credit is refused."""
    if isinstance(credits, (bool, float)):
        raise RateCardError(f"{what}: give the rate as a string or an int of credits, got {credits!r}")
    try:
        d = Decimal(str(credits).strip())
    except (InvalidOperation, ValueError):
        raise RateCardError(f"{what}: not a number: {credits!r}") from None
    if not d.is_finite() or d < 0:
        raise RateCardError(f"{what}: a rate must be a finite non-negative number of credits, got {credits!r}")
    mc = d * MC_PER_CREDIT
    if mc != mc.to_integral_value():
        raise RateCardError(f"{what}: {credits!r} credits is finer than 0.001 credit")
    return int(mc)


def format_credits(mc: int) -> str:
    """Milli-credits as a credit amount with three decimals (``1234`` → ``"1.234"``). Display only."""
    if isinstance(mc, bool) or not isinstance(mc, int):
        raise RateCardError(f"an amount must be an integer number of milli-credits, got {mc!r}")
    sign = "-" if mc < 0 else ""
    mc = abs(mc)
    return f"{sign}{mc // MC_PER_CREDIT}.{mc % MC_PER_CREDIT:03d}"


@dataclass(frozen=True)
class Rate:
    """One published rate: ``mc`` milli-credits per ``per`` units of ``unit`` (e.g. 1,250,000 mc per 1,000,000 input
    tokens)."""

    unit: str
    mc: int
    per: int
    label: str

    def amount(self, quantity: int) -> int:
        """``ceil(quantity × mc / per)`` milli-credits — exact to 0.001 credit."""
        if isinstance(quantity, bool) or not isinstance(quantity, int) or not 0 <= quantity <= _MAX_QUANTITY:
            raise RateCardError(f"{self.unit}: a quantity must be a non-negative integer, got {quantity!r}")
        return -(-quantity * self.mc // self.per)

    def published(self) -> "dict[str, Any]":
        return {"unit": self.unit, "label": self.label, "credits": format_credits(self.mc), "per": self.per}


@dataclass(frozen=True)
class ChargeLine:
    """One billable line: ``quantity`` of ``unit`` at ``rate`` → ``amount_mc``."""

    unit: str
    label: str
    quantity: int
    rate: Rate
    amount_mc: int

    def as_dict(self) -> "dict[str, Any]":
        return {"unit": self.unit, "label": self.label, "quantity": self.quantity,
                "rate": format_credits(self.rate.mc), "rate_per": self.rate.per,
                "credits": format_credits(self.amount_mc), "amount_mc": self.amount_mc}


#: The AI units, in the order a statement lists them: (unit, ``Usage`` field, label, per).
AI_UNITS = (
    ("input_tokens", "input_tokens", "AI input tokens", 1_000_000),
    ("output_tokens", "output_tokens", "AI output tokens", 1_000_000),
    ("cache_read_tokens", "cache_read_tokens", "AI cache reads", 1_000_000),
    ("cache_write_5m_tokens", "cache_write_5m_tokens", "AI cache writes (5 minutes)", 1_000_000),
    ("cache_write_1h_tokens", "cache_write_1h_tokens", "AI cache writes (1 hour)", 1_000_000),
    ("web_searches", "web_search_requests", "Web searches", 1),
)
_WORKER = ("worker_minutes", "Scan-worker time", 1)


@dataclass(frozen=True)
class RateCard:
    """The effective card: the AI rates, the scan-worker rate and any premium external API / tool rates."""

    ai: "Mapping[str, Rate]"
    worker: Rate
    premium: "Mapping[str, Rate]"

    def ai_lines(self, usage: Usage) -> "list[ChargeLine]":
        """The charge lines of one metered model response (or a sum of them): one line per AI unit used."""
        if not isinstance(usage, Usage):
            raise RateCardError(f"usage must be a Usage, got {type(usage).__name__}")
        lines = []
        for unit, field, _label, _per in AI_UNITS:
            q = int(getattr(usage, field))
            if q:
                r = self.ai[unit]
                lines.append(ChargeLine(unit, r.label, q, r, r.amount(q)))
        return lines

    def worker_line(self, seconds: int) -> ChargeLine:
        """Scan-worker time: the rate is per minute, charged by the second (``ceil(seconds × rate / 60)``)."""
        if isinstance(seconds, bool) or not isinstance(seconds, int) or seconds < 0:
            raise RateCardError(f"worker seconds must be a non-negative integer, got {seconds!r}")
        per_second = Rate(self.worker.unit, self.worker.mc, self.worker.per * 60, self.worker.label)
        return ChargeLine(self.worker.unit, self.worker.label, seconds, per_second, per_second.amount(seconds))

    def premium_line(self, name: str, calls: int) -> ChargeLine:
        """``calls`` calls to the premium external API / tool ``name``. An unpriced one raises: a billable call is
        never charged at zero, and never made without a published rate."""
        r = self.premium.get(name)
        if r is None:
            raise RateCardError(f"no published rate for premium API {name!r}")
        return ChargeLine(r.unit, r.label, calls, r, r.amount(calls))

    def published(self) -> "dict[str, Any]":
        """The card as customers see it: every rate in credits, nothing in money."""
        return {"currency": "credits", "credits_per_usd": 100,
                "ai": [self.ai[u].published() for u, *_ in AI_UNITS],
                "worker": {**self.worker.published(), "per": "minute"},
                "premium": [r.published() for r in sorted(self.premium.values(), key=lambda r: r.unit)]}


def _ai(rates_credits: "Mapping[str, Any]", *, what: str) -> "dict[str, Rate]":
    out = {}
    for unit, _field, label, per in AI_UNITS:
        if unit not in rates_credits:
            raise RateCardError(f"{what}: missing the {unit} rate")
        out[unit] = Rate(unit, _mc(rates_credits[unit], what=f"{what}.{unit}"), per, label)
    for unit in ("input_tokens", "output_tokens", "cache_write_5m_tokens", "cache_write_1h_tokens"):
        if out[unit].mc <= 0:      # a free token is a typo: it would let a run spend AI without paying for it
            raise RateCardError(f"{what}.{unit}: the rate must be greater than zero")
    return out


def _card(doc: "Mapping[str, Any]", *, what: str) -> RateCard:
    if not isinstance(doc, Mapping) or set(doc) - {"ai", "worker_minute", "premium"}:
        raise RateCardError(f"{what} must be an object with the keys ai, worker_minute and (optionally) premium")
    ai = doc.get("ai")
    if not isinstance(ai, Mapping) or set(ai) != {u for u, *_ in AI_UNITS}:
        raise RateCardError(f"{what}.ai must have exactly the keys {', '.join(u for u, *_ in AI_UNITS)}")
    worker_mc = _mc(doc.get("worker_minute"), what=f"{what}.worker_minute")
    if worker_mc <= 0:
        raise RateCardError(f"{what}.worker_minute must be greater than zero")
    premium_doc = doc.get("premium", {})
    if not isinstance(premium_doc, Mapping):
        raise RateCardError(f"{what}.premium must be an object of name -> {{credits, per, label}}")
    premium = {}
    for name, row in premium_doc.items():
        if not isinstance(name, str) or not name.strip() or not isinstance(row, Mapping):
            raise RateCardError(f"{what}.premium: each entry is a named object")
        per = row.get("per", 1)
        if isinstance(per, bool) or not isinstance(per, int) or per <= 0:
            raise RateCardError(f"{what}.premium[{name!r}].per must be a positive integer")
        mc = _mc(row.get("credits"), what=f"{what}.premium[{name!r}].credits")
        if mc <= 0:
            raise RateCardError(f"{what}.premium[{name!r}]: a billable call needs a rate greater than zero")
        premium[name.strip()] = Rate(name.strip(), mc, per, str(row.get("label") or name).strip()[:80])
    return RateCard(_ai(ai, what=f"{what}.ai"), Rate(_WORKER[0], worker_mc, _WORKER[2], _WORKER[1]), premium)


#: The published default rates (credits; $1 = 100 credits). The owner's decision of 2026-11-16 (design §0.2).
DEFAULT_RATE_CARD = _card({
    "ai": {"input_tokens": "1250", "output_tokens": "6250", "cache_read_tokens": "125",
           "cache_write_5m_tokens": "1563", "cache_write_1h_tokens": "2500", "web_searches": "2.5"},
    "worker_minute": "1",
}, what="default rate card")


def rate_card(env: Optional[Mapping[str, str]] = None) -> RateCard:
    """The effective card: :data:`DEFAULT_RATE_CARD`, or the owner's full replacement from ``VIGIL_RATE_CARD``."""
    env = os.environ if env is None else env
    raw = env.get(RATE_CARD_ENV)
    if raw is None or not raw.strip():
        return DEFAULT_RATE_CARD
    try:
        doc = json.loads(raw)
    except ValueError:
        raise RateCardError(f"{RATE_CARD_ENV} is not valid JSON") from None
    return _card(doc, what=RATE_CARD_ENV)
