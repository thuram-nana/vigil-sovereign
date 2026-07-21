"""
llm_intake — hardened LLM proposal intake: transient-retry, param self-heal, fail-closed parse
(VIGIL-FUSION F1).

The transient/permanent classifier and the once-only param self-heal are adapted from redamon's
``agentic/orchestrator_helpers/llm_retry.py`` (MIT; see NOTICE). The retry wrapper is re-shaped to be
**Claude-native and framework-agnostic**: it retries a caller-supplied zero-arg async callable rather
than a LangChain ``llm.ainvoke`` — VIGIL is Claude-everywhere and does not adopt the multi-provider
dispatcher. The fail-closed JSON→typed-proposal boundary turns a raw LLM response into a validated,
**non-authoritative** proposal; on any parse failure it returns a caller-supplied fail-closed default
(e.g. the safest action) instead of crashing or executing garbage.

Doctrine: everything here concerns getting a well-formed PROPOSAL out of the LLM. Nothing here makes
anything true — a proposal becomes a fact only when the deterministic oracle confirms it, and an
action only when the conjunctive gate authorizes it.

Pure stdlib + ``json``. Import-clean (no ``framework.*``/``strix.*``, no LLM SDK, no pydantic at
import time — a validator is injected).
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any, Awaitable, Callable, Optional, TypeVar

logger = logging.getLogger("vigil.safety.llm_intake")

T = TypeVar("T")

# --- transient / permanent classification (verbatim-adapted, MIT) -------------------------------

# SDK class names (anthropic/openai/httpx) that indicate a transient failure. Matched against
# ``type(exc).__mro__`` so subclasses are caught even when only the parent name is enumerated.
_TRANSIENT_EXC_NAMES = frozenset({
    "APIConnectionError", "APITimeoutError", "RateLimitError", "InternalServerError",
    "ServiceUnavailableError", "OverloadedError", "ConnectError", "ConnectTimeout", "ReadTimeout",
    "WriteTimeout", "PoolTimeout", "TimeoutException", "RemoteProtocolError",
})

# Phrase fallback for wrapped/unenumerated exceptions. Lowercased substring match on ``str(exc)``.
_TRANSIENT_KEYWORDS = (
    "connection", "timeout", "timed out", "overloaded", "rate_limit", "rate limit",
    "apiconnectionerror", "service unavailable", "bad gateway", "gateway timeout",
    "internal server error", "server_error",
)

# Bare HTTP status codes with WORD BOUNDARIES so "500" does NOT fire on "50000" (a permanent
# ``max_tokens: 50000 exceeded`` must not be classified transient). 429 included (rate-limit).
_TRANSIENT_STATUS_RE = re.compile(r"\b(429|500|502|503|504|529)\b")

# Hints that a permanent-400 is actually an auto-recoverable "unsupported param" (drop + retry once).
_UNSUPPORTED_HINTS = ("deprecated", "unsupported", "not supported", "does not support")


def is_transient_llm_error(exc: BaseException) -> bool:
    """True iff the exception is worth retrying. Order: type-MRO match (cheapest, most specific),
    then message substring, then bare HTTP status code regex."""
    for base in type(exc).__mro__:
        if base.__name__ in _TRANSIENT_EXC_NAMES:
            return True
    err = str(exc).lower()
    if any(k in err for k in _TRANSIENT_KEYWORDS):
        return True
    return bool(_TRANSIENT_STATUS_RE.search(err))


def is_param_unsupported_error(exc: BaseException, param: str) -> bool:
    """True iff ``exc`` is a permanent-400 rejecting ``param`` (e.g. 'temperature',
    'reasoning_effort'/'thinking') — not transient, but auto-recoverable by dropping the param."""
    s = str(exc).lower()
    return param.lower() in s and any(h in s for h in _UNSUPPORTED_HINTS)


async def retry_call(
    call: Callable[[], Awaitable[T]],
    *,
    max_attempts: int = 3,
    label: str = "llm",
    param_self_heal: Optional[Callable[[BaseException], Optional[Callable[[], Awaitable[T]]]]] = None,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> T:
    """Await ``call()`` with transient-error retry + optional once-only param self-heal.

    ``call`` is a zero-arg async callable that performs one Claude request (framework-agnostic). On a
    transient error → exponential backoff ``min(2**attempt, 8)`` (no sleep after the final attempt);
    on a non-transient error → re-raise immediately; on exhaustion → re-raise the last exception
    unchanged. ``param_self_heal(exc)`` may return a NEW ``call`` (e.g. one built without the offending
    param); it is invoked at most once, before the transient decision, so a model that rejects an
    unsupported param recovers without a per-model allowlist."""
    if max_attempts < 1:
        raise ValueError("max_attempts must be >= 1")
    last_exc: Optional[BaseException] = None
    healed = False
    for attempt in range(max_attempts):
        try:
            return await call()
        except Exception as exc:  # noqa: BLE001 — classify below; non-transient is re-raised
            last_exc = exc
            if (not healed) and param_self_heal is not None:
                try:
                    healed_call = param_self_heal(exc)
                except Exception:  # a broken self-heal must not mask the original error
                    healed_call = None
                if healed_call is not None:
                    healed = True
                    call = healed_call
                    logger.warning("[%s] retrying once after param self-heal (%s)", label, type(exc).__name__)
                    try:
                        return await call()
                    except Exception as exc2:  # noqa: BLE001
                        last_exc = exc2
                        exc = exc2
            transient = is_transient_llm_error(exc)
            logger.warning("[%s] attempt %d/%d error (transient=%s, type=%s): %s",
                           label, attempt + 1, max_attempts, transient, type(exc).__name__, exc)
            if not transient:
                raise
            if attempt < max_attempts - 1:
                await sleep(min(2 ** attempt, 8))
    assert last_exc is not None  # pragma: no cover — loop body always assigns on failure
    raise last_exc


# --- fail-closed JSON → typed proposal boundary -------------------------------------------------


class ProposalParseError(ValueError):
    """The LLM response could not be parsed into a valid typed proposal and no fail-closed default
    was supplied."""


_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL | re.IGNORECASE)


def _balanced_span(text: str, open_ch: str, close_ch: str) -> Optional[str]:
    """Return the first balanced ``open_ch``…``close_ch`` span, respecting JSON strings/escapes."""
    start = text.find(open_ch)
    if start < 0:
        return None
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        c = text[i]
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            continue
        if c == '"':
            in_str = True
        elif c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return None  # unbalanced (unclosed) — caller may attempt repair


def _repair_json(fragment: str) -> str:
    """Best-effort repair of common LLM JSON glitches: strip trailing commas before } or ], and
    close any unclosed braces/brackets (respecting strings)."""
    s = re.sub(r",\s*([}\]])", r"\1", fragment)  # trailing commas
    depth_obj = depth_arr = 0
    in_str = False
    esc = False
    for c in s:
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            continue
        if c == '"':
            in_str = True
        elif c == "{":
            depth_obj += 1
        elif c == "}":
            depth_obj -= 1
        elif c == "[":
            depth_arr += 1
        elif c == "]":
            depth_arr -= 1
    if in_str:
        s += '"'
    s += "]" * max(0, depth_arr) + "}" * max(0, depth_obj)
    return s


def extract_json(text: str) -> Optional[Any]:
    """Extract the first JSON value from a possibly fenced / prose-wrapped LLM response. Tries, in
    order: a ```json fenced block, a balanced object, a balanced array — each parsed directly then,
    on failure, with :func:`_repair_json`. Returns the decoded value or ``None``."""
    if not isinstance(text, str) or not text.strip():
        return None
    candidates: list[str] = []
    m = _FENCE_RE.search(text)
    if m:
        candidates.append(m.group(1))
    for open_ch, close_ch in (("{", "}"), ("[", "]")):
        start = text.find(open_ch)
        if start < 0:
            continue
        span = _balanced_span(text, open_ch, close_ch)
        # a balanced span parses directly; an UNBALANCED (unclosed) tail from the first opener is
        # handed to _repair_json below so a truncated LLM response can still be recovered.
        candidates.append(span if span is not None else text[start:])
    for frag in candidates:
        for attempt in (frag, _repair_json(frag)):
            try:
                return json.loads(attempt)
            except (ValueError, TypeError):
                continue
    return None


def parse_proposal(
    text: str,
    validator: Callable[[Any], T],
    *,
    default: Optional[T] = None,
    _no_default: object = object(),
) -> T:
    """Extract JSON from an LLM ``text`` response and validate it into a typed PROPOSAL via
    ``validator`` (e.g. ``MyModel.model_validate`` or any callable that raises on invalid input).

    **Fail-closed:** on any extraction/validation failure, return ``default`` if one was supplied
    (the safest fallback — e.g. a downgraded action), else raise :class:`ProposalParseError`. The
    returned object is a non-authoritative proposal; the caller is responsible for treating it as
    such (it becomes a fact only via the oracle, an action only via the gate)."""
    obj = extract_json(text)
    if obj is not None:
        try:
            return validator(obj)
        except Exception as exc:  # noqa: BLE001 — any validator error is a parse failure → fail closed
            logger.warning("proposal validation failed (%s): %s", type(exc).__name__, exc)
    if default is not None:
        return default
    raise ProposalParseError("could not parse a valid typed proposal from the LLM response")
