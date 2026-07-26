"""
SelfHostedOpenAIBackend — bring-your-own self-hosted, OpenAI-compatible model server.

Covers the sovereignty-declared-but-previously-unconstructible local backends `vllm`, `llama-cpp`, and
`tgi` — all of which expose the OpenAI `/v1/chat/completions` shape. One backend serves all three names
(they differ only by the operator's endpoint). Classified `local` (permitted at every sovereignty tier,
including AIR_GAPPED) — this is the operator's OWN infrastructure, so the endpoint is intentionally
arbitrary (typically `http://localhost:8000/v1`); an api-key is optional (many local servers need none).

Manual HTTPS/HTTP POST via httpx — no SDK, zero new packages.

Environment:
  - `CRUCIBLE_SELFHOSTED_ENDPOINT` (or `LLM_API_BASE`)   the OpenAI-compatible base, e.g.
    `http://localhost:8000/v1`. REQUIRED — there is no sensible default host.
  - `CRUCIBLE_SELFHOSTED_MODEL`    the served model name (default `local-model`).
  - optional `CRUCIBLE_SELFHOSTED_API_KEY` (or `LLM_API_KEY`)   sent as `Authorization: Bearer` if present.
"""
from __future__ import annotations

import json
import os
import time
from urllib.parse import urlparse

import httpx

from ...common import logging as v2log
from ...common.errors import BackendError, BackendUnavailable
from ..llm import LLMBackend, LLMResult, Prompt, make_call_trace, parse_json_response

_log = v2log.get_logger(__name__)

_DEFAULT_MODEL = "local-model"
_CALL_TIMEOUT = 120.0


def _validated_base(endpoint: str) -> str:
    """A well-formed http(s) base URL for the operator's own server. Local http is normal, so https is not
    required; but the URL must be a real http(s) URL with a host (no `file:`/`javascript:`/hostless)."""
    ep = str(endpoint or "").strip().rstrip("/")
    try:
        u = urlparse(ep)
        host = u.hostname
        _ = u.port                          # validate the port too (raises ValueError on a bad port / [::1)
    except ValueError as e:
        raise BackendUnavailable(f"CRUCIBLE_SELFHOSTED_ENDPOINT is malformed: {e}") from e
    if u.scheme not in ("http", "https") or not host:
        raise BackendUnavailable(
            "CRUCIBLE_SELFHOSTED_ENDPOINT must be an http(s) URL, e.g. http://localhost:8000/v1")
    return ep


class SelfHostedOpenAIBackend(LLMBackend):
    name = "self-hosted"

    def __init__(self, *, backend_name: str = "self-hosted") -> None:
        self.name = backend_name                      # so traces/status show vllm/llama-cpp/tgi if forced
        endpoint = (os.environ.get("CRUCIBLE_SELFHOSTED_ENDPOINT", "").strip()
                    or os.environ.get("LLM_API_BASE", "").strip())
        if not endpoint:
            raise BackendUnavailable("CRUCIBLE_SELFHOSTED_ENDPOINT (or LLM_API_BASE) not set")
        self.base = _validated_base(endpoint)
        self.model = os.environ.get("CRUCIBLE_SELFHOSTED_MODEL", _DEFAULT_MODEL).strip() or _DEFAULT_MODEL
        # optional — many local servers accept any/no key
        self._api_key = (os.environ.get("CRUCIBLE_SELFHOSTED_API_KEY", "").strip()
                         or os.environ.get("LLM_API_KEY", "").strip())

    def is_available(self) -> tuple[bool, str]:
        return True, f"ready (endpoint={self.base}, model={self.model})"

    def _build_system(self, prompt: Prompt) -> str:
        schema_json = json.dumps(prompt.schema.model_json_schema(), indent=2)
        return (f"{prompt.system}\n\n## Output contract\n\n"
                "Respond with a single JSON object validating the following JSON Schema. No prose outside "
                "the JSON. No markdown fence. No comments. The JSON must be parseable as-is.\n\n"
                f"```json\n{schema_json}\n```")

    def complete(self, prompt: Prompt) -> LLMResult:
        sys_prompt = self._build_system(prompt)
        user_msg = prompt.user
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        last_error: Exception | None = None
        for attempt in (1, 2):
            payload = {
                "model": self.model,
                "messages": [{"role": "system", "content": sys_prompt},
                             {"role": "user", "content": user_msg}],
                "temperature": prompt.temperature,
                "max_tokens": prompt.max_tokens,
                "response_format": {"type": "json_object"},
            }
            t0 = time.perf_counter()
            try:
                with httpx.Client(timeout=_CALL_TIMEOUT) as client:
                    r = client.post(f"{self.base}/chat/completions", headers=headers,
                                    content=json.dumps(payload).encode("utf-8"))
            except httpx.HTTPError as e:
                raise BackendError(f"self-hosted HTTP error: {e}") from e
            latency = (time.perf_counter() - t0) * 1000.0
            if r.status_code != 200:
                raise BackendError(f"self-hosted API returned {r.status_code}: {r.text[:300]}")
            try:
                envelope = r.json()
                raw = envelope["choices"][0]["message"]["content"]
            except (json.JSONDecodeError, KeyError, IndexError, TypeError) as e:
                raise BackendError(f"self-hosted response missing expected fields: {e}") from e
            try:
                parsed = parse_json_response(raw, prompt.schema)
            except BackendError as e:
                last_error = e
                _log.warning("kernel.self_hosted.parse_retry", schema=prompt.schema_name,
                             attempt=attempt, error=str(e)[:200])
                if attempt == 1:
                    user_msg = (f"{prompt.user}\n\n[Your previous response could not be parsed: "
                                f"{str(e)[:300]}.  Return only valid JSON.]")
                    continue
                raise
            usage = envelope.get("usage", {}) or {}
            tokens_in, tokens_out = int(usage.get("prompt_tokens", 0)), int(usage.get("completion_tokens", 0))
            trace = make_call_trace(backend=self.name, is_dryrun=False, cognitive_doc=prompt.cognitive_doc,
                                    cognitive_sections=prompt.cognitive_sections, tokens_in=tokens_in,
                                    tokens_out=tokens_out, latency_ms=latency)
            _log.info("kernel.self_hosted.complete", schema=prompt.schema_name, model=self.model,
                      tokens_in=tokens_in, tokens_out=tokens_out, latency_ms=int(latency))
            return LLMResult(parsed=parsed, trace=trace, raw_response=raw)
        raise BackendError(f"unreachable: {last_error}")
