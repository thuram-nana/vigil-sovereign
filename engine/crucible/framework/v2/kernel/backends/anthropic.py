"""
AnthropicBackend — live LLM via the Anthropic Messages API.

Activates when:
  - the `anthropic` package is importable, AND
  - ANTHROPIC_API_KEY is set in env.

Default model: claude-sonnet-4-6 (override via CRUCIBLE_ANTHROPIC_MODEL).
Default max_tokens: 4096 (override on the Prompt).

ZDR variant (Session 8):
  Anthropic offers Enterprise / zero-data-retention contracts where
  prompts and completions are not retained beyond the request.
  Setting `CRUCIBLE_ANTHROPIC_ZDR=1` produces an `AnthropicBackend`
  whose `name` is `anthropic-zdr`, which the sovereignty policy
  classifies as `trusted_cloud` (permitted under TIER_TRUSTED_CLOUD)
  rather than `cloud_only` (permitted only under TIER_PERMISSIVE).

  ZDR enrolment is an organisational contract with Anthropic, not a
  per-request flag. CRUCIBLE has no programmatic way to verify that
  the configured API key belongs to a ZDR-enabled org. Setting
  `CRUCIBLE_ANTHROPIC_ZDR=1` is therefore an *operator attestation*
  that the org is ZDR-enrolled. Misuse is the operator's
  responsibility — see SECURITY.md § 'Operator attestations'.

The structured-output strategy is the simplest one that works
robustly across schemas: instruct the model to emit a single JSON
object validating the schema, peel any markdown fence, validate via
Pydantic. On parse failure, retry once with the error attached.
"""

from __future__ import annotations

import json
import os
import random
import time

from ...common import logging as v2log
from ...common.errors import BackendError, BackendOverloaded, BackendUnavailable
from ..llm import LLMBackend, LLMResult, Prompt, make_call_trace, parse_json_response


_log = v2log.get_logger(__name__)
_DEFAULT_MODEL = "claude-sonnet-4-6"

# X4 — transient-failure backoff. On a rate-limit / overload / 5xx / connection error we retry
# in-backend with exponential backoff + full jitter (honouring a Retry-After header when the
# server sends one); after this many attempts we raise BackendOverloaded so the dispatch layer
# fails over to the next permitted backend. The anthropic client's own retries are disabled
# (max_retries=0) so this is the single, explicit, provider-agnostic backoff policy.
_RETRYABLE_STATUS = frozenset({408, 409, 429, 500, 502, 503, 504, 529})
_MAX_API_ATTEMPTS = 4
_BASE_BACKOFF_S = 0.5
_MAX_BACKOFF_S = 20.0
# A hostile / misconfigured server can send an enormous Retry-After (e.g. 999999s ≈ 11 days);
# honouring it verbatim would hang the call. Cap the per-attempt wait — a backend that wants
# longer simply gets retried after the cap and, if still failing, exhausts to a failover.
_MAX_RETRY_AFTER_S = _MAX_BACKOFF_S
_JITTER = random.Random()   # non-deterministic jitter (anti-thundering-herd); off the replay path


def _retry_after_seconds(exc: Exception) -> float | None:
    """The server-advised Retry-After delay in seconds, if present + numeric. An HTTP-date
    form is ignored (we fall back to computed backoff), never raising."""
    resp = getattr(exc, "response", None)
    headers = getattr(resp, "headers", None)
    if headers is None:
        return None
    try:
        val = headers.get("retry-after")
    except Exception:
        return None
    if not val:
        return None
    try:
        # cap to bound the per-attempt wait — never honour an absurd/hostile Retry-After.
        return min(_MAX_RETRY_AFTER_S, max(0.0, float(val)))
    except (TypeError, ValueError):
        return None


def _classify_transient(exc: Exception) -> tuple[bool, float | None]:
    """(is_transient, retry_after_seconds). Transient = a retryable HTTP status or a
    connection/timeout/overload class — the failures worth backing off + failing over on."""
    status = getattr(exc, "status_code", None)
    name = type(exc).__name__.lower()
    transient = (
        (isinstance(status, int) and status in _RETRYABLE_STATUS)
        or "overloaded" in name or "ratelimit" in name
        or "timeout" in name or "connection" in name
    )
    return transient, (_retry_after_seconds(exc) if transient else None)


def _backoff_delay(attempt: int) -> float:
    """Exponential backoff with full jitter, capped at _MAX_BACKOFF_S."""
    ceiling = min(_MAX_BACKOFF_S, _BASE_BACKOFF_S * (2 ** (attempt - 1)))
    return _JITTER.uniform(0.0, ceiling)


class AnthropicBackend(LLMBackend):
    """Live Anthropic backend. The ZDR variant differs only in `name`
    (which the sovereignty policy uses for tier classification) and
    in a structured-log marker; the API call shape is identical."""

    name = "anthropic"

    def __init__(self, *, zdr: bool | None = None) -> None:
        try:
            import anthropic  # noqa: F401
        except ImportError as e:
            raise BackendUnavailable(f"anthropic SDK not installed: {e}") from e
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise BackendUnavailable("ANTHROPIC_API_KEY not set")
        # construct lazily on first use to avoid network on import
        self._client: object | None = None
        self.model = os.environ.get("CRUCIBLE_ANTHROPIC_MODEL", _DEFAULT_MODEL)
        # ZDR flag: explicit constructor arg wins; otherwise read env.
        env_zdr = os.environ.get("CRUCIBLE_ANTHROPIC_ZDR", "").strip() in (
            "1", "true", "yes", "on",
        )
        self.zdr = bool(zdr) if zdr is not None else env_zdr
        if self.zdr:
            # The sovereignty policy classifies by name; rebrand this
            # instance so the policy gate places it under trusted_cloud.
            self.name = "anthropic-zdr"

    def is_available(self) -> tuple[bool, str]:
        try:
            import anthropic  # noqa: F401
        except ImportError:
            return False, "anthropic SDK not installed"
        if not os.environ.get("ANTHROPIC_API_KEY"):
            return False, "ANTHROPIC_API_KEY not set"
        zdr_marker = " [ZDR]" if self.zdr else ""
        return True, f"ready (model={self.model}){zdr_marker}"

    def _client_obj(self) -> object:
        if self._client is None:
            import anthropic
            # max_retries=0: the SDK's internal retry/backoff is disabled so `_create_with_backoff`
            # below is the single, explicit, testable backoff policy (X4).
            self._client = anthropic.Anthropic(max_retries=0)
        return self._client

    def _create_with_backoff(self, client: object, sys_prompt: str, user_msg: str,
                             prompt: Prompt) -> object:
        """Issue one Messages API call, retrying transient failures (429/overload/5xx/
        connection) with backoff + jitter, honouring Retry-After. Raises BackendOverloaded when
        the transient failure persists (so dispatch fails over) or BackendError for a permanent
        failure (e.g. a 400/401 — failing over would not help)."""
        last: Exception | None = None
        for api_attempt in range(1, _MAX_API_ATTEMPTS + 1):
            try:
                return client.messages.create(  # type: ignore[attr-defined]
                    model=self.model,
                    system=sys_prompt,
                    messages=[{"role": "user", "content": user_msg}],
                    temperature=prompt.temperature,
                    max_tokens=prompt.max_tokens,
                )
            except Exception as e:  # noqa: BLE001 — classify below; never leak a raw SDK error
                last = e
                transient, retry_after = _classify_transient(e)
                if transient and api_attempt < _MAX_API_ATTEMPTS:
                    delay = retry_after if retry_after is not None else _backoff_delay(api_attempt)
                    _log.warning("kernel.anthropic.backoff", attempt=api_attempt,
                                 delay_s=round(delay, 2), error=str(e)[:150])
                    time.sleep(delay)
                    continue
                if transient:
                    raise BackendOverloaded(
                        f"Anthropic transient failure after {api_attempt} attempts: {e}") from e
                raise BackendError(f"Anthropic API error: {e}") from e
        raise BackendOverloaded(f"Anthropic unreachable: {last}")   # unreachable in practice

    def _build_system(self, prompt: Prompt) -> str:
        schema_json = json.dumps(prompt.schema.model_json_schema(), indent=2)
        return (
            f"{prompt.system}\n\n"
            "## Output contract\n\n"
            f"Respond with a single JSON object validating the following "
            f"JSON Schema. No prose outside the JSON. No markdown fence. "
            f"No comments. The JSON must be parseable as-is.\n\n"
            f"```json\n{schema_json}\n```"
        )

    def complete(self, prompt: Prompt) -> LLMResult:
        client = self._client_obj()

        sys_prompt = self._build_system(prompt)
        user_msg = prompt.user

        last_error: Exception | None = None
        for attempt in (1, 2):
            t0 = time.perf_counter()
            # transient failures (429/overload/5xx/connection) are retried with backoff inside
            # here; a persistent transient raises BackendOverloaded for the dispatch failover (X4).
            rsp = self._create_with_backoff(client, sys_prompt, user_msg, prompt)
            latency = (time.perf_counter() - t0) * 1000.0

            text_parts = [
                getattr(b, "text", "") for b in rsp.content
                if getattr(b, "type", "") == "text"
            ]
            raw = "".join(text_parts).strip()

            try:
                parsed = parse_json_response(raw, prompt.schema)
            except BackendError as e:
                last_error = e
                _log.warning(
                    "kernel.anthropic.parse_retry",
                    schema=prompt.schema_name, attempt=attempt, error=str(e)[:200],
                )
                if attempt == 1:
                    user_msg = (
                        f"{prompt.user}\n\n"
                        f"[Your previous response could not be parsed: "
                        f"{str(e)[:300]}.  Return only valid JSON.]"
                    )
                    continue
                raise

            tokens_in = getattr(rsp.usage, "input_tokens", 0) if hasattr(rsp, "usage") else 0
            tokens_out = getattr(rsp.usage, "output_tokens", 0) if hasattr(rsp, "usage") else 0

            trace = make_call_trace(
                backend=self.name,
                is_dryrun=False,
                cognitive_doc=prompt.cognitive_doc,
                cognitive_sections=prompt.cognitive_sections,
                tokens_in=tokens_in,
                tokens_out=tokens_out,
                latency_ms=latency,
            )
            _log.info(
                "kernel.anthropic.complete",
                schema=prompt.schema_name,
                model=self.model,
                tokens_in=tokens_in, tokens_out=tokens_out,
                latency_ms=int(latency),
            )
            return LLMResult(parsed=parsed, trace=trace, raw_response=raw)

        # the loop above either returns or raises; this is unreachable
        raise BackendError(f"unreachable: {last_error}")
