"""
OllamaBackend — local Ollama daemon over HTTP.

Activates when http://localhost:11434/api/version answers within a
small probe timeout. Default model is qwen2.5-coder:32b (override via
CRUCIBLE_OLLAMA_MODEL).

Per FORGE PROTOCOL § 8.5, no data leaves the operator's host. Ollama
runs locally; this backend never reaches an external endpoint.
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
_DEFAULT_HOST = "http://localhost:11434"
_DEFAULT_MODEL = "qwen2.5-coder:32b"
_PROBE_TIMEOUT = 1.5
_CALL_TIMEOUT = 120.0


class OllamaBackend(LLMBackend):
    name = "ollama"

    def __init__(self) -> None:
        self.host = os.environ.get("CRUCIBLE_OLLAMA_HOST", _DEFAULT_HOST).rstrip("/")
        self.model = os.environ.get("CRUCIBLE_OLLAMA_MODEL", _DEFAULT_MODEL)
        ok, note = self.is_available()
        if not ok:
            raise BackendUnavailable(f"Ollama not reachable: {note}")

    def is_available(self) -> tuple[bool, str]:
        try:
            r = httpx.get(f"{self.host}/api/version", timeout=_PROBE_TIMEOUT)
            if r.status_code != 200:
                return False, f"GET /api/version returned {r.status_code}"
            v = r.json().get("version", "?")
            # also confirm the model is pulled
            tags = httpx.get(f"{self.host}/api/tags", timeout=_PROBE_TIMEOUT)
            pulled = [m["name"] for m in tags.json().get("models", [])]
            if not any(self.model in name for name in pulled):
                return False, (
                    f"daemon ok (v{v}) but model {self.model!r} not pulled. "
                    f"Try: ollama pull {self.model}"
                )
            return True, f"ready (v{v}, model={self.model})"
        except (httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError) as e:
            return False, f"daemon unreachable at {self.host}: {e.__class__.__name__}"
        except Exception as e:
            return False, f"probe error: {e.__class__.__name__}: {e}"

    def _build_system(self, prompt: Prompt) -> str:
        schema_json = json.dumps(prompt.schema.model_json_schema(), indent=2)
        return (
            f"{prompt.system}\n\n"
            "## Output contract\n\n"
            "Respond with a single JSON object validating the following JSON "
            "Schema. No prose outside the JSON. No markdown fence. No "
            "comments. The JSON must be parseable as-is.\n\n"
            f"```json\n{schema_json}\n```"
        )

    def complete(self, prompt: Prompt) -> LLMResult:
        sys_prompt = self._build_system(prompt)
        user_msg = prompt.user

        last_error: Exception | None = None
        for attempt in (1, 2):
            t0 = time.perf_counter()
            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": sys_prompt},
                    {"role": "user", "content": user_msg},
                ],
                "options": {"temperature": prompt.temperature},
                "stream": False,
                "format": "json",  # ollama enforces JSON output server-side
            }
            try:
                r = httpx.post(
                    f"{self.host}/api/chat", json=payload, timeout=_CALL_TIMEOUT,
                )
                r.raise_for_status()
                data = r.json()
            except (httpx.HTTPError, json.JSONDecodeError) as e:
                raise BackendError(f"Ollama call failed: {e}") from e
            latency = (time.perf_counter() - t0) * 1000.0

            raw = data.get("message", {}).get("content", "").strip()
            try:
                parsed = parse_json_response(raw, prompt.schema)
            except BackendError as e:
                last_error = e
                _log.warning(
                    "kernel.ollama.parse_retry",
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

            tokens_in = data.get("prompt_eval_count", 0) or 0
            tokens_out = data.get("eval_count", 0) or 0

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
                "kernel.ollama.complete",
                schema=prompt.schema_name,
                model=self.model,
                tokens_in=tokens_in, tokens_out=tokens_out,
                latency_ms=int(latency),
            )
            return LLMResult(parsed=parsed, trace=trace, raw_response=raw)

        raise BackendError(f"unreachable: {last_error}")
