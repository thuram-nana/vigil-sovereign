"""Bounded SDK retries for the anthropic-SDK clients VIGIL builds (both planes).

The anthropic SDK retries a failed request itself (``max_retries``, default 2). SDK 0.x honoured a server's
``Retry-After`` only when it was in (0, 60] seconds and otherwise slept its own capped exponential backoff (at most
8 s). SDK 2.x honours ANY positive ``Retry-After`` (up to about 49 days), so one 429 / 529 that carries
``retry-after: 7200`` — from a misbehaving upstream, a proxy behind ``ANTHROPIC_BASE_URL``, or a Bedrock / Vertex
endpoint — stalls a call for two hours inside the SDK before VIGIL sees an error.

:func:`bounded_http_client` restores the 0.x rule for a client built with it: :func:`cap_retry_after`, a response
hook, removes a ``retry-after-ms`` / ``retry-after`` header whose delay is not in (0, :data:`MAX_RETRY_AFTER_S`]
seconds (an HTTP-date value by the same rule; an unparseable one is removed too), so the SDK falls back to its own
bounded backoff. A delay inside the bound is kept and honoured as before. The engine's ``AnthropicBackend`` disables
SDK retries outright (``max_retries=0``) and runs its own capped loop; this helper is for every other client.

Stdlib only at import (both planes import ``vigil_core``); the SDK is imported only inside
:func:`bounded_http_client`, by the caller that is about to build an SDK client anyway.
"""
from __future__ import annotations

import email.utils
import math
import time
from datetime import timezone
from typing import Any, Optional

#: The longest server-advised wait an SDK retry may honour (SDK 0.x's own bound).
MAX_RETRY_AFTER_S = 60.0
_RETRY_HEADERS = ("retry-after-ms", "retry-after")


def _delay_seconds(name: str, raw: Any, *, now: Optional[float] = None) -> Optional[float]:
    """The wait a ``name`` header with value ``raw`` asks for, in seconds, or None when it is unparseable."""
    text = str(raw).strip()
    try:
        value = float(text)
    except ValueError:
        value = math.nan
    if math.isfinite(value):
        return value / 1000.0 if name == "retry-after-ms" else value
    if name == "retry-after":
        try:
            when = email.utils.parsedate_to_datetime(text)
        except (TypeError, ValueError, IndexError, OverflowError):
            return None
        if when is None:
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return when.timestamp() - (time.time() if now is None else now)
    return None


def cap_retry_after(response: Any) -> None:
    """Response hook: drop a ``retry-after-ms`` / ``retry-after`` header whose delay is not in (0, 60] seconds (or
    cannot be read), so the SDK's retry falls back to its own bounded backoff. Never raises."""
    headers = getattr(response, "headers", None)
    if headers is None:
        return
    for name in _RETRY_HEADERS:
        try:
            raw = headers.get(name)
            if raw is None:
                continue
            delay = _delay_seconds(name, raw)
            if delay is None or not (0.0 < delay <= MAX_RETRY_AFTER_S):
                del headers[name]
        except Exception:  # noqa: BLE001 — a hook must never break the response it inspects
            continue


def bounded_http_client(**kwargs: Any) -> Any:
    """``anthropic.DefaultHttpxClient(**kwargs)`` with :func:`cap_retry_after` added to its response hooks — pass it
    as ``http_client=`` to ``Anthropic`` / ``AnthropicBedrock`` / ``AnthropicVertex``. The SDK keeps its own defaults
    (timeouts, limits, TLS) and its ``max_retries``; only an out-of-bound ``Retry-After`` is ignored.

    Returns None (the SDK then builds its own default client) when the installed ``anthropic`` has no
    ``DefaultHttpxClient`` — only a test double lacks it; every SDK this repo supports (0.x and 2.x) has it, and the
    real-SDK test in ``tests/test_sdk_retry.py`` fails if a future one does not."""
    import anthropic  # lazy: only a caller about to build an SDK client reaches here

    factory = getattr(anthropic, "DefaultHttpxClient", None)
    if factory is None:
        return None
    hooks = dict(kwargs.pop("event_hooks", None) or {})
    hooks["response"] = [*hooks.get("response", ()), cap_retry_after]
    return factory(event_hooks=hooks, **kwargs)
