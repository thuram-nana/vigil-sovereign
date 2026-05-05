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
import time

from ...common import logging as v2log
from ...common.errors import BackendError, BackendUnavailable
from ..llm import LLMBackend, LLMResult, Prompt, make_call_trace, parse_json_response


_log = v2log.get_logger(__name__)
_DEFAULT_MODEL = "claude-sonnet-4-6"


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
            self._client = anthropic.Anthropic()
        return self._client

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
            try:
                rsp = client.messages.create(  # type: ignore[attr-defined]
                    model=self.model,
                    system=sys_prompt,
                    messages=[{"role": "user", "content": user_msg}],
                    temperature=prompt.temperature,
                    max_tokens=prompt.max_tokens,
                )
            except Exception as e:
                raise BackendError(f"Anthropic API error: {e}") from e
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
