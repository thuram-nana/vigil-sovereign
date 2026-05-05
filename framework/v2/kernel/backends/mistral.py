"""
MistralBackend — Mistral La Plateforme (EU-sovereign cloud).

Sovereign-cloud tier. Issues HTTPS POST to Mistral's chat-completions
endpoint with manual JSON construction (no SDK dependency, so this
backend adds zero new packages to requirements.in).

Why this backend exists:
  Mistral fills a specific niche in the substrate ladder: EU-
  jurisdictional cloud where the operator wants neither Anthropic
  nor a US-headquartered hyperscaler in the trust path. La Plateforme
  is operated by Mistral AI (French company) on EU infrastructure.

Honest framing on quality:
  Mistral models are different from Claude. On the demanding URK
  bindings (especially `critique` and `threat_model`), reasoning
  quality is generally below Claude. The `permitted_preference()`
  ordering reflects this — under TIER_SOVEREIGN_CLOUD the auto-
  selection picks Bedrock first (Claude on AWS-EU), Vertex second
  (Claude on GCP-EU), Mistral third. Mistral becomes the chosen
  backend when the operator explicitly forces it via
  `CRUCIBLE_LLM_BACKEND=mistral` or when AWS/GCP trust isn't
  acceptable to the deployment context.

Required environment / setup:
  - `MISTRAL_API_KEY` set.
  - Optional: `CRUCIBLE_MISTRAL_MODEL` (default `mistral-large-latest`).
  - Optional: `CRUCIBLE_MISTRAL_ENDPOINT` (default
    `https://api.mistral.ai/v1`). Override only if you have a
    dedicated Mistral endpoint; the public default is EU-resident.

Live verification:
  Session 8 ships this backend code-complete; live verification
  requires `MISTRAL_API_KEY` which the operator may not have
  configured.
"""

from __future__ import annotations

import json
import os
import time

import httpx

from ...common import logging as v2log
from ...common.errors import BackendError, BackendUnavailable
from ..llm import LLMBackend, LLMResult, Prompt, make_call_trace, parse_json_response


_log = v2log.get_logger(__name__)


_DEFAULT_ENDPOINT = "https://api.mistral.ai/v1"
_DEFAULT_MODEL    = "mistral-large-latest"
_PROBE_TIMEOUT    = 5.0
_CALL_TIMEOUT     = 120.0


class MistralBackend(LLMBackend):
    name = "mistral"

    def __init__(self) -> None:
        api_key = os.environ.get("MISTRAL_API_KEY", "").strip()
        if not api_key:
            raise BackendUnavailable("MISTRAL_API_KEY not set")
        self._api_key = api_key
        self.endpoint = os.environ.get(
            "CRUCIBLE_MISTRAL_ENDPOINT", _DEFAULT_ENDPOINT,
        ).rstrip("/")
        self.model = os.environ.get("CRUCIBLE_MISTRAL_MODEL", _DEFAULT_MODEL)

    def is_available(self) -> tuple[bool, str]:
        if not self._api_key:
            return False, "MISTRAL_API_KEY not set"
        return True, f"ready (endpoint={self.endpoint}, model={self.model})"

    def _build_system(self, prompt: Prompt) -> str:
        schema_json = json.dumps(prompt.schema.model_json_schema(), indent=2)
        return (
            f"{prompt.system}\n\n"
            "## Output contract\n\n"
            "Respond with a single JSON object validating the following "
            "JSON Schema. No prose outside the JSON. No markdown fence. "
            "No comments. The JSON must be parseable as-is.\n\n"
            f"```json\n{schema_json}\n```"
        )

    def complete(self, prompt: Prompt) -> LLMResult:
        sys_prompt = self._build_system(prompt)
        user_msg = prompt.user

        last_error: Exception | None = None
        for attempt in (1, 2):
            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": sys_prompt},
                    {"role": "user", "content": user_msg},
                ],
                "temperature": prompt.temperature,
                "max_tokens": prompt.max_tokens,
                # Hint the API to emit JSON; behaviour and field name
                # are stable on La Plateforme as of 2026-01.
                "response_format": {"type": "json_object"},
            }
            headers = {
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            }
            t0 = time.perf_counter()
            try:
                with httpx.Client(timeout=_CALL_TIMEOUT) as client:
                    r = client.post(
                        f"{self.endpoint}/chat/completions",
                        headers=headers,
                        content=json.dumps(payload).encode("utf-8"),
                    )
            except httpx.HTTPError as e:
                raise BackendError(f"Mistral HTTP error: {e}") from e
            latency = (time.perf_counter() - t0) * 1000.0

            if r.status_code != 200:
                raise BackendError(
                    f"Mistral API returned {r.status_code}: "
                    f"{r.text[:300]}"
                )

            try:
                envelope = r.json()
            except json.JSONDecodeError as e:
                raise BackendError(f"Mistral envelope is not JSON: {e}") from e

            try:
                raw = envelope["choices"][0]["message"]["content"]
            except (KeyError, IndexError, TypeError) as e:
                raise BackendError(
                    f"Mistral response missing expected fields: {e}; "
                    f"envelope keys: {list(envelope.keys())[:5]}"
                ) from e

            try:
                parsed = parse_json_response(raw, prompt.schema)
            except BackendError as e:
                last_error = e
                _log.warning(
                    "kernel.mistral.parse_retry",
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

            usage = envelope.get("usage", {}) or {}
            tokens_in = int(usage.get("prompt_tokens", 0))
            tokens_out = int(usage.get("completion_tokens", 0))

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
                "kernel.mistral.complete",
                schema=prompt.schema_name,
                model=self.model, endpoint=self.endpoint,
                tokens_in=tokens_in, tokens_out=tokens_out,
                latency_ms=int(latency),
            )
            return LLMResult(parsed=parsed, trace=trace, raw_response=raw)

        raise BackendError(f"unreachable: {last_error}")
