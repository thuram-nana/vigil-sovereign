"""vigil_core.model_metering — the cost table and the exact cost / credit arithmetic of a metered run (PRICING M1a).

`docs/decisions/PRICING-RED-PEN-DESIGN.md` §2: a customer run is charged

    charge_credits = min(reservation, max(FLOOR, ceil(cost_usd / (1 − target_margin) × 100)))

where ``cost_usd`` is what the run's model requests cost VIGIL, priced from the usage Anthropic reports on each
response, and ``target_margin`` is the owner's margin over that METERED AI cost only (the model requests the
gateway meters; payment fees, hosting and every other cost are outside it, so the all-in margin is lower). It is set
at DEPLOY time (``VIGIL_BILLING_TARGET_MARGIN``), is the ONLY pricing input, and is deliberately never committed:
there is no default, and while it is unset every metered price raises, so metered billing cannot run on a guessed
margin. A retired pricing setting (:data:`OBSOLETE_PRICING_ENVS`) still present in the environment is refused the
same way, so no second pricing knob can sit next to the margin unnoticed. This module is that arithmetic and nothing else: the price table, parsing a response's ``usage`` (a
non-streamed body or a stream's ``message_start`` / ``message_delta`` events), the cost, the credits, and the USD
cap a reservation buys. The sovereign model gateway meters with it; the offense-side runtime caps (M2) price with
the same table, so both planes price a token identically.

Money is integers, never floats:
  * a price is published in USD per million tokens and held as **nano-USD per token** (USD/MTok × 1000, exactly:
    $5/MTok = 5,000 nUSD per token). A price finer than $0.001/MTok is refused rather than rounded;
  * a cost is an integer number of nano-USD (1e-9 USD);
  * one credit is $0.01 = :data:`CREDIT_NANO_USD` nano-USD;
  * the markup ``1 / (1 − target_margin)`` is an exact :class:`fractions.Fraction`.

Fail-closed: a malformed usage object, an unknown model, a bad price override or a missing / bad margin raises
:class:`MeteringError`. A caller that cannot price a run must not run it (the gateway refuses to forward), and
must never fall back to a guessed number.

Pure stdlib; imports no ``framework.*`` / ``strix.*`` / ``sigil.*`` (FATAL-2), like the rest of ``vigil_core``.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from fractions import Fraction
from typing import Any, Mapping, Optional

__all__ = [
    "CREDIT_NANO_USD", "DEFAULT_PRICES", "MeteringError", "PriceRow", "StreamMeter", "Usage",
    "CANCEL_ENV", "CANCEL_POLICIES", "DEFAULT_RUN_MODEL", "MARGIN_ENV", "OBSOLETE_PRICING_ENVS", "RUN_MODEL_ENV",
    "billing_markup", "cancel_settlement", "cost_nano_usd", "run_model", "credits_for_cost", "format_usd",
    "obsolete_pricing_settings", "obsolete_setting_refusal", "price_table", "run_floor_credits", "target_margin",
    "usage_from_api", "usd_cap_nano_for_credits",
]

#: One credit is $0.01 at list (100 credits per $1).
CREDIT_NANO_USD = 10_000_000

PRICES_ENV = "VIGIL_MODEL_PRICES"
MARGIN_ENV = "VIGIL_BILLING_TARGET_MARGIN"
FLOOR_ENV = "VIGIL_RUN_FLOOR_CREDITS"
CANCEL_ENV = "VIGIL_BILLING_CANCEL_SETTLEMENT"
DEFAULT_CANCEL_SETTLEMENT = "metered"   # owner decision 2026-11-13: a cancelled scan pays for what it used
RUN_MODEL_ENV = "VIGIL_RUN_MODEL"
DEFAULT_RUN_MODEL = "claude-opus-4-8"
CANCEL_POLICIES = ("metered", "refund")
#: Pricing settings an earlier design read. None is read now: the margin is the one pricing input, so a deploy that
#: still carries one of these is refused rather than silently ignored.
OBSOLETE_PRICING_ENVS = ("VIGIL_BILLING_MARKUP_K", "VIGIL_MARGIN_MULTIPLIER_K")
DEFAULT_FLOOR_CREDITS = 25
_MAX_MARKUP = Fraction(100)               # a sanity bound: the margin is at most 0.99, so the markup at most 100
_MAX_TOKENS_PER_FIELD = 10 ** 12          # far above any real response; bounds a hostile / corrupt count


class MeteringError(ValueError):
    """A run cannot be priced: malformed usage, an unknown model, or bad pricing configuration."""


# ---------------------------------------------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Usage:
    """Token counts of one model response (or the sum of many). Cache writes are split by TTL because a 1-hour
    write costs more than a 5-minute one. Web searches are billed per request, on top of tokens."""

    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_5m_tokens: int = 0
    cache_write_1h_tokens: int = 0
    web_search_requests: int = 0

    def __add__(self, other: "Usage") -> "Usage":
        if not isinstance(other, Usage):
            return NotImplemented
        return Usage(*(a + b for a, b in zip(self.as_tuple(), other.as_tuple())))

    def as_tuple(self) -> "tuple[int, int, int, int, int, int]":
        return (self.input_tokens, self.output_tokens, self.cache_read_tokens, self.cache_write_5m_tokens,
                self.cache_write_1h_tokens, self.web_search_requests)

    def as_dict(self) -> "dict[str, int]":
        return {"input_tokens": self.input_tokens, "output_tokens": self.output_tokens,
                "cache_read_tokens": self.cache_read_tokens, "cache_write_5m_tokens": self.cache_write_5m_tokens,
                "cache_write_1h_tokens": self.cache_write_1h_tokens, "web_search_requests": self.web_search_requests}

    @property
    def total_tokens(self) -> int:
        return sum(self.as_tuple()[:5])


def _count(obj: Mapping[str, Any], key: str, *, where: str) -> Optional[int]:
    """A token count from ``obj[key]``: absent or ``None`` → ``None``; a non-negative int → it; anything else
    (a bool, a float, a string, a negative, an absurd value) → :class:`MeteringError`."""
    if key not in obj or obj[key] is None:
        return None
    v = obj[key]
    if isinstance(v, bool) or not isinstance(v, int) or v < 0 or v > _MAX_TOKENS_PER_FIELD:
        raise MeteringError(f"{where}.{key} must be a non-negative integer token count, got {v!r}")
    return v


def _cache_writes(obj: Mapping[str, Any], *, where: str) -> "tuple[Optional[int], Optional[int]]":
    """``(5m, 1h)`` cache-write tokens. Anthropic reports the total as ``cache_creation_input_tokens`` and the
    split by TTL under ``cache_creation``. When the split is present it is used (and must not exceed the total);
    a total with no split is all 5-minute writes, the default TTL."""
    total = _count(obj, "cache_creation_input_tokens", where=where)
    split = obj.get("cache_creation")
    if split is None:
        return total, (0 if total is not None else None)
    if not isinstance(split, Mapping):
        raise MeteringError(f"{where}.cache_creation must be an object, got {type(split).__name__}")
    w5 = _count(split, "ephemeral_5m_input_tokens", where=f"{where}.cache_creation") or 0
    w1 = _count(split, "ephemeral_1h_input_tokens", where=f"{where}.cache_creation") or 0
    if total is not None and w5 + w1 > total:
        raise MeteringError(f"{where}: the cache-write split ({w5} + {w1}) exceeds cache_creation_input_tokens "
                            f"({total})")
    if total is not None and w5 + w1 < total:
        w5 += total - (w5 + w1)                 # an unsplit remainder is a default-TTL (5-minute) write
    return w5, w1


#: ``server_tool_use`` counters the price table covers: web search is priced per request; web fetch has no fee beyond
#: its tokens. Any OTHER non-zero counter is a server tool this table does not price — refused, never metered at zero.
_PRICED_SERVER_TOOLS = ("web_search_requests",)
_FREE_SERVER_TOOLS = ("web_fetch_requests",)


def _web_searches(obj: Mapping[str, Any], *, where: str) -> Optional[int]:
    """``server_tool_use.web_search_requests``, or ``None`` when the response reports no server tool use. A non-zero
    counter for a server tool the price table does not cover raises (an unpriced tool is never metered as free)."""
    stu = obj.get("server_tool_use")
    if stu is None:
        return None
    if not isinstance(stu, Mapping):
        raise MeteringError(f"{where}.server_tool_use must be an object, got {type(stu).__name__}")
    for key, v in stu.items():
        if key in _PRICED_SERVER_TOOLS or key in _FREE_SERVER_TOOLS:
            continue
        if v not in (None, 0) or isinstance(v, bool):
            raise MeteringError(f"{where}.server_tool_use.{key} = {v!r}: this server tool has no price")
    return _count(stu, "web_search_requests", where=f"{where}.server_tool_use")


def _refuse_unpriced(obj: Mapping[str, Any], *, where: str) -> None:
    """Refuse a ``usage`` object that reports spend the top-level counts do not carry or the price table does not
    cover. Anthropic itemises server-side steps (a compaction pass, an advisor's sub-inference on ANOTHER model, a
    fallback model's attempt) under ``usage.iterations``, billed in addition to — or at different rates from — the
    top-level counts; the priority tier, fast mode and US-only inference bill the same tokens at a premium. The model gateway never
    lets a request ask for any of them; if a response reports one anyway, the meter must not price it as a plain
    response. Exactly one ``message`` iteration (the response itself) is the only shape accepted."""
    its = obj.get("iterations")
    if its is not None:
        if not isinstance(its, list):
            raise MeteringError(f"{where}.iterations must be a list, got {type(its).__name__}")
        if len(its) > 1 or any(not isinstance(i, Mapping) or i.get("type") != "message" for i in its):
            raise MeteringError(f"{where}.iterations reports server-side steps the price table does not cover")
    if obj.get("service_tier") == "priority":
        raise MeteringError(f"{where}.service_tier is 'priority': the priority tier is not priced")
    if obj.get("speed") == "fast":
        raise MeteringError(f"{where}.speed is 'fast': fast mode is not priced")
    if obj.get("inference_geo") == "us":
        raise MeteringError(f"{where}.inference_geo is 'us': US-only inference (a premium) is not priced")


def usage_from_api(obj: Any, *, where: str = "usage") -> Usage:
    """A :class:`Usage` from an Anthropic ``usage`` object (a non-streamed response body's ``usage``, or a
    stream's ``message_start.message.usage``). Missing counts are 0; keys that carry no price are ignored; a usage
    that reports UNPRICED spend (:func:`_refuse_unpriced`, an unpriced server tool) raises."""
    if not isinstance(obj, Mapping):
        raise MeteringError(f"{where} must be an object, got {type(obj).__name__}")
    _refuse_unpriced(obj, where=where)
    w5, w1 = _cache_writes(obj, where=where)
    return Usage(
        input_tokens=_count(obj, "input_tokens", where=where) or 0,
        output_tokens=_count(obj, "output_tokens", where=where) or 0,
        cache_read_tokens=_count(obj, "cache_read_input_tokens", where=where) or 0,
        cache_write_5m_tokens=w5 or 0,
        cache_write_1h_tokens=w1 or 0,
        web_search_requests=_web_searches(obj, where=where) or 0,
    )


class StreamMeter:
    """The usage of ONE streamed response, from its server-sent events.

    ``message_start`` carries the starting usage (input and cache counts, and an initial ``output_tokens``).
    Each ``message_delta`` may carry a ``usage`` whose counts are CUMULATIVE for the message, so a count present
    in a delta replaces the earlier value (it is never added). Every other event is ignored. Feed the decoded
    JSON of each event's ``data`` with :meth:`feed`; read :attr:`usage` at the end, or at any point for a live
    meter."""

    def __init__(self) -> None:
        self._started = False
        self._fields: "dict[str, int]" = {}

    def feed(self, event: Any) -> None:
        if not isinstance(event, Mapping):
            raise MeteringError(f"a stream event must be an object, got {type(event).__name__}")
        kind = event.get("type")
        if kind == "message_start":
            message = event.get("message")
            if not isinstance(message, Mapping):
                raise MeteringError("message_start.message must be an object")
            self._merge(usage_from_api(message.get("usage") or {}, where="message_start.message.usage"),
                        message.get("usage") or {})
            self._started = True
        elif kind == "message_delta":
            usage = event.get("usage")
            if usage is None:
                return
            if not isinstance(usage, Mapping):
                raise MeteringError("message_delta.usage must be an object")
            self._merge(usage_from_api(usage, where="message_delta.usage"), usage)

    def _merge(self, parsed: Usage, raw: Mapping[str, Any]) -> None:
        """Replace exactly the counts ``raw`` carries (cumulative semantics)."""
        present = {
            "input_tokens": "input_tokens" in raw and raw["input_tokens"] is not None,
            "output_tokens": "output_tokens" in raw and raw["output_tokens"] is not None,
            "cache_read_tokens": raw.get("cache_read_input_tokens") is not None,
            "cache_write": (raw.get("cache_creation_input_tokens") is not None
                            or raw.get("cache_creation") is not None),
            "web_search_requests": (isinstance(raw.get("server_tool_use"), Mapping)
                                    and raw["server_tool_use"].get("web_search_requests") is not None),
        }
        d = parsed.as_dict()
        for name in ("input_tokens", "output_tokens", "cache_read_tokens", "web_search_requests"):
            if present[name]:
                self._fields[name] = d[name]
        if raw.get("cache_creation") is not None:
            self._fields["cache_write_5m_tokens"] = d["cache_write_5m_tokens"]
            self._fields["cache_write_1h_tokens"] = d["cache_write_1h_tokens"]
        elif present["cache_write"]:
            # a TOTAL with no TTL split (the documented ``message_delta`` shape): it must never re-price the split
            # ``message_start`` reported. Equal to the stored total => keep the split. Larger => the extra tokens
            # are priced at the 1-hour rate (the dearer one: a meter that guards a cap never guesses low). Smaller
            # => the stream contradicts itself: refused (the gateway then charges at least the reservation).
            total = d["cache_write_5m_tokens"] + d["cache_write_1h_tokens"]
            w5 = self._fields.get("cache_write_5m_tokens")
            w1 = self._fields.get("cache_write_1h_tokens")
            if w5 is None and w1 is None:
                self._fields["cache_write_5m_tokens"], self._fields["cache_write_1h_tokens"] = total, 0
            else:
                have = (w5 or 0) + (w1 or 0)
                if total < have:
                    raise MeteringError(f"a stream's cache-write total went down ({have} -> {total})")
                self._fields["cache_write_1h_tokens"] = (w1 or 0) + (total - have)

    @property
    def started(self) -> bool:
        return self._started

    @property
    def usage(self) -> Usage:
        return Usage(**self._fields)


# ---------------------------------------------------------------------------------------------------------------
# Prices
# ---------------------------------------------------------------------------------------------------------------

def _nano_per_token(usd_per_mtok: Any, *, what: str) -> int:
    """USD per million tokens → integer nano-USD per token, exactly. A bool / float / NaN / negative / price
    finer than $0.001 per million tokens is refused (no silent rounding on a price)."""
    if isinstance(usd_per_mtok, bool) or isinstance(usd_per_mtok, float):
        raise MeteringError(f"{what}: give the price as a string or an int (USD per million tokens), "
                            f"got {usd_per_mtok!r}")
    try:
        d = Decimal(str(usd_per_mtok).strip())
    except (InvalidOperation, ValueError):
        raise MeteringError(f"{what}: not a number: {usd_per_mtok!r}") from None
    if not d.is_finite() or d < 0:
        raise MeteringError(f"{what}: a price must be a finite non-negative number, got {usd_per_mtok!r}")
    nano = d * 1000
    if nano != nano.to_integral_value():
        raise MeteringError(f"{what}: {usd_per_mtok!r} USD/MTok is finer than $0.001 per million tokens")
    return int(nano)


@dataclass(frozen=True)
class PriceRow:
    """One model's prices: nano-USD per token, and nano-USD per web search request."""

    input: int
    output: int
    cache_read: int
    cache_write_5m: int
    cache_write_1h: int
    web_search: int

    @classmethod
    def from_usd(cls, input: Any, output: Any, cache_read: Any, cache_write_5m: Any, cache_write_1h: Any,
                 web_search_per_1k: Any, *, model: str = "") -> "PriceRow":
        """Token prices in USD per million tokens; web search in USD per 1,000 searches (both as published)."""
        w = f"price for {model or 'model'}"
        row = cls(_nano_per_token(input, what=f"{w}.input"), _nano_per_token(output, what=f"{w}.output"),
                   _nano_per_token(cache_read, what=f"{w}.cache_read"),
                   _nano_per_token(cache_write_5m, what=f"{w}.cache_write_5m"),
                   _nano_per_token(cache_write_1h, what=f"{w}.cache_write_1h"),
                   # USD per 1,000 searches -> nano-USD per search is USD/1k x 1e6, the same exactness rule x1000
                   _nano_per_token(web_search_per_1k, what=f"{w}.web_search_per_1k") * 1000)
        # a zero token price is a typo, never a price: the gateway's cap divides by the output price, and a free
        # input or output token would switch the run's budget off
        if row.input <= 0 or row.output <= 0 or row.cache_write_5m <= 0 or row.cache_write_1h <= 0:
            raise MeteringError(f"{w}: the input, output and cache-write prices must be greater than zero")
        return row


#: Anthropic's published Claude Opus 4.8 prices: per million tokens, input $5, output $25, cache read $0.50,
#: 5-minute cache write $6.25 (1.25x input), 1-hour cache write $10 (2x input); web search $10 per 1,000 searches.
#: The owner updates them, without a release, through ``VIGIL_MODEL_PRICES`` when Anthropic changes a price.
DEFAULT_PRICES: "Mapping[str, PriceRow]" = {
    "claude-opus-4-8": PriceRow.from_usd("5", "25", "0.50", "6.25", "10", "10", model="claude-opus-4-8"),
}

_ROW_KEYS = ("input", "output", "cache_read", "cache_write_5m", "cache_write_1h", "web_search_per_1k")


def price_table(env: Optional[Mapping[str, str]] = None) -> "dict[str, PriceRow]":
    """The effective price table: :data:`DEFAULT_PRICES`, with any rows from ``VIGIL_MODEL_PRICES`` replacing
    or adding models. The override is inline JSON (token prices in USD per million tokens, web search in USD per
    1,000 searches), every price a string or an int::

        {"claude-opus-4-8": {"input": "5", "output": "25", "cache_read": "0.50", "cache_write_5m": "6.25",
                             "cache_write_1h": "10", "web_search_per_1k": "10"}}

    A malformed override raises :class:`MeteringError` (it is never partly applied)."""
    env = os.environ if env is None else env
    table = dict(DEFAULT_PRICES)
    raw = env.get(PRICES_ENV)
    if raw is None or not raw.strip():
        return table
    try:
        doc = json.loads(raw)
    except ValueError:
        raise MeteringError(f"{PRICES_ENV} is not valid JSON") from None
    if not isinstance(doc, dict) or not doc:
        raise MeteringError(f"{PRICES_ENV} must be a non-empty JSON object of model -> prices")
    parsed = {}
    for model, row in doc.items():
        if not isinstance(model, str) or not model.strip():
            raise MeteringError(f"{PRICES_ENV}: a model id must be a non-empty string")
        if not isinstance(row, dict) or set(row) != set(_ROW_KEYS):
            raise MeteringError(f"{PRICES_ENV}[{model!r}] must have exactly the keys {', '.join(_ROW_KEYS)}")
        parsed[model.strip()] = PriceRow.from_usd(*(row[k] for k in _ROW_KEYS), model=model)
    table.update(parsed)
    return table


def cost_nano_usd(usage: Usage, model: str, prices: "Optional[Mapping[str, PriceRow]]" = None) -> int:
    """What ``usage`` on ``model`` costs, in nano-USD. An unpriced model raises — never priced at zero."""
    if not isinstance(usage, Usage):
        raise MeteringError(f"usage must be a Usage, got {type(usage).__name__}")
    table = price_table() if prices is None else prices
    row = table.get(model)
    if row is None:
        raise MeteringError(f"no price for model {model!r}; add it to {PRICES_ENV} before running it")
    return (usage.input_tokens * row.input + usage.output_tokens * row.output
            + usage.cache_read_tokens * row.cache_read + usage.cache_write_5m_tokens * row.cache_write_5m
            + usage.cache_write_1h_tokens * row.cache_write_1h + usage.web_search_requests * row.web_search)


# ---------------------------------------------------------------------------------------------------------------
# Credits
# ---------------------------------------------------------------------------------------------------------------

def obsolete_pricing_settings(env: Optional[Mapping[str, str]] = None) -> "tuple[str, ...]":
    """The retired pricing settings (:data:`OBSOLETE_PRICING_ENVS`) present in ``env``, set to anything at all
    (an empty value is still a stale line in the deploy). Doctor reports each as a hard issue."""
    env = os.environ if env is None else env
    return tuple(name for name in OBSOLETE_PRICING_ENVS if name in env)


def obsolete_setting_refusal(name: str) -> str:
    """The one sentence every refusal of a retired pricing setting uses (billing and doctor alike)."""
    return f"{name} is set: remove it; the only pricing input is {MARGIN_ENV}"


def target_margin(env: Optional[Mapping[str, str]] = None) -> Fraction:
    """The owner's target margin (``VIGIL_BILLING_TARGET_MARGIN``) as an exact fraction: a decimal strictly between 0
    and 1, at most 0.99. It is the margin over the run's METERED AI cost only — the model requests the gateway
    meters, priced from the table here. Payment fees, hosting and every other cost are not in it, so the all-in
    margin is lower than this number. It is the only pricing input. It has NO default — the value is the owner's
    and is set at deploy, never in this repository — so an unset, empty or malformed value RAISES, and every metered
    price (and the launch that would need one) is refused. A retired pricing setting still present
    (:func:`obsolete_pricing_settings`) raises too. Never falls back to a guess."""
    env = os.environ if env is None else env
    for name in obsolete_pricing_settings(env):
        raise MeteringError(obsolete_setting_refusal(name))
    raw = env.get(MARGIN_ENV)
    if raw is None or not raw.strip():
        raise MeteringError(f"{MARGIN_ENV} is not set: metered pricing stays off until the deploy sets the owner's "
                            f"target margin")
    try:
        d = Decimal(raw.strip())
    except (InvalidOperation, ValueError):
        raise MeteringError(f"{MARGIN_ENV} is not a decimal number") from None
    if not d.is_finite():
        raise MeteringError(f"{MARGIN_ENV} must be a finite decimal")
    m = Fraction(d)
    if not 0 < m < 1 or 1 / (1 - m) > _MAX_MARKUP:
        raise MeteringError(f"{MARGIN_ENV} must be a decimal strictly between 0 and 1 (at most 0.99)")
    return m


def billing_markup(env: Optional[Mapping[str, str]] = None) -> Fraction:
    """The markup ``1 / (1 − target_margin)`` as an exact fraction (> 1): credits charged = metered AI cost × markup ×
    100. Raises when the margin is unset or invalid (:func:`target_margin`)."""
    return 1 / (1 - target_margin(env))


def run_model(env: Optional[Mapping[str, str]] = None) -> str:
    """The one model every metered customer run uses (``VIGIL_RUN_MODEL``; default ``claude-opus-4-8``, the owner's
    decision). A run can only be metered if this model has a row in :func:`price_table`."""
    env = os.environ if env is None else env
    return (env.get(RUN_MODEL_ENV) or "").strip() or DEFAULT_RUN_MODEL


def cancel_settlement(env: Optional[Mapping[str, str]] = None) -> str:
    """How a metered run the customer cancels settles (``VIGIL_BILLING_CANCEL_SETTLEMENT``): ``metered`` (charged
    for what it used, at least the floor, never more than the reservation) or ``refund`` (charged nothing). Unset
    means ``metered`` (the owner's decision of 2026-11-13: a cancelled scan pays for what it already used). An
    unrecognised value RAISES, so a typo never silently picks a policy; metered billing then refuses to launch or
    settle until it is fixed."""
    env = os.environ if env is None else env
    raw = (env.get(CANCEL_ENV) or "").strip().lower()
    if not raw:
        return DEFAULT_CANCEL_SETTLEMENT
    if raw not in CANCEL_POLICIES:
        raise MeteringError(f"{CANCEL_ENV} must be one of {', '.join(CANCEL_POLICIES)} (unset means "
                            f"{DEFAULT_CANCEL_SETTLEMENT})")
    return raw


def run_floor_credits(env: Optional[Mapping[str, str]] = None) -> int:
    """The per-run minimum charge in credits (``VIGIL_RUN_FLOOR_CREDITS``, default 25 = $0.25)."""
    env = os.environ if env is None else env
    raw = env.get(FLOOR_ENV)
    if raw is None or not raw.strip():
        return DEFAULT_FLOOR_CREDITS
    try:
        v = int(raw.strip())
    except ValueError:
        raise MeteringError(f"{FLOOR_ENV} must be a whole number of credits, got {raw!r}") from None
    if v < 0:
        raise MeteringError(f"{FLOOR_ENV} must not be negative, got {raw!r}")
    return v


def _check_int(name: str, v: Any) -> int:
    if isinstance(v, bool) or not isinstance(v, int) or v < 0:
        raise MeteringError(f"{name} must be a non-negative integer, got {v!r}")
    return v


def credits_for_cost(cost_nano: int, *, markup: Fraction, floor: int, cap: int) -> int:
    """``min(cap, max(floor, ceil(cost × markup / $0.01)))`` — the credits a run that cost ``cost_nano`` is
    charged, never more than ``cap`` (the reservation the customer approved)."""
    _check_int("cost_nano", cost_nano)
    _check_int("floor", floor)
    _check_int("cap", cap)
    if not isinstance(markup, Fraction) or markup < 1:
        raise MeteringError(f"markup must be a Fraction >= 1, got {markup!r}")
    num = cost_nano * markup.numerator
    den = CREDIT_NANO_USD * markup.denominator
    raw = -(-num // den)                                    # exact integer ceil(num / den)
    return min(cap, max(floor, raw))


def usd_cap_nano_for_credits(credits: int, *, markup: Fraction) -> int:
    """The largest AI spend (nano-USD) whose marked-up charge still fits in ``credits``:
    ``floor(credits × $0.01 / markup)``. The model gateway refuses requests once a run's spend reaches it."""
    _check_int("credits", credits)
    if not isinstance(markup, Fraction) or markup < 1:
        raise MeteringError(f"markup must be a Fraction >= 1, got {markup!r}")
    return (credits * CREDIT_NANO_USD * markup.denominator) // markup.numerator


def format_usd(cost_nano: int) -> str:
    """``cost_nano`` as dollars to the cent, rounded up (``$0.09`` for 88,750,000 nano-USD), for display only."""
    _check_int("cost_nano", cost_nano)
    cents = -(-cost_nano // CREDIT_NANO_USD)              # one cent is one credit
    return f"${cents // 100}.{cents % 100:02d}"
