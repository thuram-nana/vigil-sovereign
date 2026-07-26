"""
AzureOpenAIBackend — Claude-free bring-your-own-model via Azure OpenAI.

Azure OpenAI exposes the OpenAI chat-completions shape at a per-resource endpoint
(`https://<resource>.openai.azure.com`) addressed by a *deployment* name, with an
`api-key:` header (not `Authorization: Bearer`). Like MistralBackend this issues a
manual HTTPS POST via httpx — no SDK, zero new packages.

Classified `cloud_only` in sovereignty: permitted at PERMISSIVE (the dev default) or when the
operator explicitly forces `CRUCIBLE_LLM_BACKEND=azure_openai`; refused under the sovereign tiers
(an operator who needs a sovereign deployment would not route through Azure). The endpoint is
operator-supplied, so it is HOST-VALIDATED here (https + `*.openai.azure.com`, no userinfo) — the
api-key is only ever sent to a real Azure host, never a look-alike (mirrors the settings health probe).

Required environment:
  - `AZURE_OPENAI_API_KEY`
  - `AZURE_OPENAI_ENDPOINT`               (e.g. https://my-res.openai.azure.com)
  - `CRUCIBLE_AZURE_OPENAI_DEPLOYMENT`    (the deployment name; the model id you deployed)
  - optional `CRUCIBLE_AZURE_OPENAI_API_VERSION` (default 2024-06-01)
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

_DEFAULT_API_VERSION = "2024-06-01"
_CALL_TIMEOUT = 120.0


def _validated_azure_base(endpoint: str) -> str:
    """Return the scheme+host base of a real Azure OpenAI endpoint, or raise. Parses the HOST (not a
    substring) so `https://evil/.openai.azure.com`, `https://x.openai.azure.com.evil`, and userinfo tricks
    are all refused — the api-key never reaches a look-alike host."""
    ep = str(endpoint or "").strip().rstrip("/")
    u = urlparse(ep)
    host = (u.hostname or "").lower()
    if u.scheme != "https" or u.username or u.password or "@" in ep or not host.endswith(".openai.azure.com"):
        raise BackendUnavailable(
            "AZURE_OPENAI_ENDPOINT must be https://<resource>.openai.azure.com")
    return f"https://{host}" + (f":{u.port}" if u.port else "")


class AzureOpenAIBackend(LLMBackend):
    name = "azure_openai"

    def __init__(self) -> None:
        api_key = os.environ.get("AZURE_OPENAI_API_KEY", "").strip()
        if not api_key:
            raise BackendUnavailable("AZURE_OPENAI_API_KEY not set")
        endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT", "").strip()
        if not endpoint:
            raise BackendUnavailable("AZURE_OPENAI_ENDPOINT not set")
        self._api_key = api_key
        self.base = _validated_azure_base(endpoint)          # raises on a non-Azure host
        self.deployment = os.environ.get("CRUCIBLE_AZURE_OPENAI_DEPLOYMENT", "").strip()
        if not self.deployment:
            raise BackendUnavailable("CRUCIBLE_AZURE_OPENAI_DEPLOYMENT (the deployment name) not set")
        self.api_version = os.environ.get("CRUCIBLE_AZURE_OPENAI_API_VERSION", _DEFAULT_API_VERSION).strip()
        self.model = self.deployment                          # for traces/status

    def is_available(self) -> tuple[bool, str]:
        return True, f"ready (endpoint={self.base}, deployment={self.deployment})"

    def _build_system(self, prompt: Prompt) -> str:
        schema_json = json.dumps(prompt.schema.model_json_schema(), indent=2)
        return (f"{prompt.system}\n\n## Output contract\n\n"
                "Respond with a single JSON object validating the following JSON Schema. No prose outside "
                "the JSON. No markdown fence. No comments. The JSON must be parseable as-is.\n\n"
                f"```json\n{schema_json}\n```")

    def complete(self, prompt: Prompt) -> LLMResult:
        sys_prompt = self._build_system(prompt)
        user_msg = prompt.user
        url = (f"{self.base}/openai/deployments/{self.deployment}/chat/completions"
               f"?api-version={self.api_version}")
        headers = {"api-key": self._api_key, "Content-Type": "application/json"}
        last_error: Exception | None = None
        for attempt in (1, 2):
            payload = {
                "messages": [{"role": "system", "content": sys_prompt},
                             {"role": "user", "content": user_msg}],
                "temperature": prompt.temperature,
                "max_tokens": prompt.max_tokens,
                "response_format": {"type": "json_object"},
            }
            t0 = time.perf_counter()
            try:
                with httpx.Client(timeout=_CALL_TIMEOUT) as client:
                    r = client.post(url, headers=headers, content=json.dumps(payload).encode("utf-8"))
            except httpx.HTTPError as e:
                raise BackendError(f"Azure OpenAI HTTP error: {e}") from e
            latency = (time.perf_counter() - t0) * 1000.0
            if r.status_code != 200:
                raise BackendError(f"Azure OpenAI API returned {r.status_code}: {r.text[:300]}")
            try:
                envelope = r.json()
                raw = envelope["choices"][0]["message"]["content"]
            except (json.JSONDecodeError, KeyError, IndexError, TypeError) as e:
                raise BackendError(f"Azure OpenAI response missing expected fields: {e}") from e
            try:
                parsed = parse_json_response(raw, prompt.schema)
            except BackendError as e:
                last_error = e
                _log.warning("kernel.azure_openai.parse_retry", schema=prompt.schema_name,
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
            _log.info("kernel.azure_openai.complete", schema=prompt.schema_name, deployment=self.deployment,
                      tokens_in=tokens_in, tokens_out=tokens_out, latency_ms=int(latency))
            return LLMResult(parsed=parsed, trace=trace, raw_response=raw)
        raise BackendError(f"unreachable: {last_error}")
