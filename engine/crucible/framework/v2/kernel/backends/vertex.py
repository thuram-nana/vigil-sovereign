"""
VertexBackend — Claude on Google Vertex AI with regional restriction.

Sovereign-cloud tier. Wraps `anthropic.AnthropicVertex` (a
first-party Anthropic SDK client that issues requests to Google
Vertex AI's Anthropic offering via google-auth). Same Pydantic-
validated structured output as the regular `AnthropicBackend`;
URK bindings are unchanged.

Why this backend exists:
  Same rationale as Bedrock: jurisdictional sovereignty without
  giving up frontier reasoning quality. Vertex hosts Claude in
  multiple regions including europe-west4 (Netherlands),
  asia-northeast1 (Tokyo), us-central1, europe-west9 (Paris).

Required environment / setup:
  - GCP credentials: `GOOGLE_APPLICATION_CREDENTIALS` pointing to a
    service-account JSON, or workload identity / metadata server
    in a GCE / GKE / Cloud Run context.
  - `google-auth` package installed.
  - `CRUCIBLE_VERTEX_PROJECT` set to the GCP project ID.
  - `CRUCIBLE_VERTEX_REGION` set to a region in the allowlist.
  - The configured Claude model must be enabled in the project and
    region.

Region allowlist:
  Default starters: us-central1, us-east5, europe-west4 (NL),
  europe-west9 (Paris), asia-northeast1 (Tokyo). Verify the chosen
  region currently hosts the configured Claude model before live
  use; Anthropic's published Vertex region list evolves. Override
  via `CRUCIBLE_VERTEX_REGION_ALLOWLIST`.

Live verification:
  Session 8 ships this backend code-complete; live verification
  requires GCP credentials and a Claude-enabled Vertex project.
"""

from __future__ import annotations

import json
import os
import time

from ...common import logging as v2log
from ...common.errors import BackendError, BackendUnavailable
from ..llm import LLMBackend, LLMResult, Prompt, make_call_trace, parse_json_response


_log = v2log.get_logger(__name__)


# Default region allowlist. Verify regional model availability against
# https://docs.anthropic.com/en/api/claude-on-vertex-ai before live
# deployment — the list evolves.
_DEFAULT_REGION_ALLOWLIST = (
    "us-central1", "us-east5",
    "europe-west4",   # Netherlands
    "europe-west9",   # Paris
    "asia-northeast1",  # Tokyo
)


# Default model id. Vertex prefixes Claude IDs with `claude-` and
# uses `@` for version pinning. Operator overrides via
# CRUCIBLE_VERTEX_MODEL.
_DEFAULT_MODEL = "claude-3-5-sonnet-v2@20241022"


def _region_allowlist() -> tuple[str, ...]:
    raw = os.environ.get("CRUCIBLE_VERTEX_REGION_ALLOWLIST", "").strip()
    if not raw:
        return _DEFAULT_REGION_ALLOWLIST
    return tuple(r.strip() for r in raw.split(",") if r.strip())


class VertexBackend(LLMBackend):
    name = "vertex"

    def __init__(self) -> None:
        try:
            import anthropic  # noqa: F401
        except ImportError as e:
            raise BackendUnavailable(f"anthropic SDK not installed: {e}") from e
        try:
            import google.auth  # noqa: F401
        except ImportError as e:
            raise BackendUnavailable(
                f"google-auth not installed; required for Vertex backend: {e}"
            ) from e

        # Project + region.
        project = os.environ.get("CRUCIBLE_VERTEX_PROJECT", "").strip()
        if not project:
            raise BackendUnavailable(
                "CRUCIBLE_VERTEX_PROJECT not set; Vertex requires a "
                "GCP project ID."
            )
        self.project = project

        region = os.environ.get("CRUCIBLE_VERTEX_REGION", "").strip()
        if not region:
            raise BackendUnavailable(
                "CRUCIBLE_VERTEX_REGION not set; Vertex requires an "
                "explicit region."
            )
        allowlist = _region_allowlist()
        if region not in allowlist:
            raise BackendUnavailable(
                f"region {region!r} is not in the sovereign-friendly "
                f"allowlist {allowlist}. Override via "
                f"CRUCIBLE_VERTEX_REGION_ALLOWLIST if you've vetted a "
                f"different region for your deployment context."
            )
        self.region = region

        # Credentials. google-auth resolves via GOOGLE_APPLICATION_CREDENTIALS,
        # workload identity, or metadata server. We do a lightweight
        # env-presence check here; real auth happens at first call.
        if not (
            os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
            or os.environ.get("GOOGLE_CLOUD_PROJECT")
            or os.path.exists(os.path.expanduser("~/.config/gcloud"))
        ):
            raise BackendUnavailable(
                "no GCP credentials found (GOOGLE_APPLICATION_CREDENTIALS, "
                "default project, or ~/.config/gcloud). Vertex requires "
                "authenticated access."
            )

        self.model = os.environ.get("CRUCIBLE_VERTEX_MODEL", _DEFAULT_MODEL)
        self._client: object | None = None

    def is_available(self) -> tuple[bool, str]:
        try:
            import anthropic  # noqa: F401
        except ImportError:
            return False, "anthropic SDK not installed"
        try:
            import google.auth  # noqa: F401
        except ImportError:
            return False, "google-auth not installed"
        return True, f"ready (project={self.project}, region={self.region})"

    def _client_obj(self) -> object:
        if self._client is None:
            from anthropic import AnthropicVertex
            self._client = AnthropicVertex(
                project_id=self.project, region=self.region,
            )
        return self._client

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
                raise BackendError(f"Vertex API error: {e}") from e
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
                    "kernel.vertex.parse_retry",
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
                "kernel.vertex.complete",
                schema=prompt.schema_name,
                model=self.model, region=self.region, project=self.project,
                tokens_in=tokens_in, tokens_out=tokens_out,
                latency_ms=int(latency),
            )
            return LLMResult(parsed=parsed, trace=trace, raw_response=raw)

        raise BackendError(f"unreachable: {last_error}")
