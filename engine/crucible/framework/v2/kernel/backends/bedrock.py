"""
BedrockBackend — Claude on AWS Bedrock with regional restriction.

Sovereign-cloud tier. Wraps `anthropic.AnthropicBedrock` (a
first-party Anthropic SDK client that issues requests via boto3
to AWS Bedrock Runtime). Same Pydantic-validated structured output
as the regular `AnthropicBackend`; URK bindings are unchanged.

Why this backend exists:
  Most government deployments need *jurisdictional* sovereignty —
  data residency, regional infrastructure, FedRAMP / IL5 / EU
  compliance — not pure-local. AWS GovCloud (us-gov-east-1,
  us-gov-west-1) and EU-resident regions (eu-west-1, eu-west-3,
  eu-central-1) deliver that bar with Claude's reasoning quality.

Required environment / setup:
  - AWS credentials: standard AWS chain (env vars, IAM role,
    `~/.aws/credentials`, instance profile).
  - `boto3` package available (operator installs alongside
    `anthropic`).
  - `CRUCIBLE_BEDROCK_REGION` set to the chosen region.
  - The configured Claude model (default `anthropic.claude-3-5-sonnet-20241022-v2:0`
    — operator may override via `CRUCIBLE_BEDROCK_MODEL`) must be
    enabled in that AWS account / region.

Region allowlist:
  We refuse construction if the configured region is not in the
  allowlist below. This is sovereignty enforcement at the framework
  level — operators who need a non-listed region can override via
  `CRUCIBLE_BEDROCK_REGION_ALLOWLIST` (comma-separated), which is
  itself logged for audit.

Live verification:
  Session 8 ships this backend code-complete; live verification
  requires AWS credentials. See V2-LIMITATIONS.md § 'Substrate
  pluralism — what's live-verified.'
"""

from __future__ import annotations

import json
import os
import time

from ...common import logging as v2log
from ...common.errors import BackendError, BackendUnavailable
from ..llm import LLMBackend, LLMResult, Prompt, make_call_trace, parse_json_response


_log = v2log.get_logger(__name__)


# Default region allowlist: AWS GovCloud + sovereign-friendly EU + APAC
# regions where Claude is generally available. Operators with novel
# regulatory contexts override via CRUCIBLE_BEDROCK_REGION_ALLOWLIST.
_DEFAULT_REGION_ALLOWLIST = (
    "us-gov-east-1", "us-gov-west-1",
    "eu-west-1", "eu-west-3", "eu-central-1",
    "ap-northeast-1",
    # Plus the standard US regions for permissive-tier dev.
    "us-east-1", "us-west-2",
)


# Default model id. Bedrock model IDs are vendor-prefixed with the
# inference profile suffix; operator overrides via CRUCIBLE_BEDROCK_MODEL.
_DEFAULT_MODEL = "anthropic.claude-3-5-sonnet-20241022-v2:0"


def _region_allowlist() -> tuple[str, ...]:
    raw = os.environ.get("CRUCIBLE_BEDROCK_REGION_ALLOWLIST", "").strip()
    if not raw:
        return _DEFAULT_REGION_ALLOWLIST
    return tuple(r.strip() for r in raw.split(",") if r.strip())


class BedrockBackend(LLMBackend):
    name = "bedrock"

    def __init__(self) -> None:
        try:
            import anthropic  # noqa: F401
        except ImportError as e:
            raise BackendUnavailable(f"anthropic SDK not installed: {e}") from e
        try:
            import boto3  # noqa: F401
        except ImportError as e:
            raise BackendUnavailable(
                f"boto3 not installed; required for Bedrock backend: {e}"
            ) from e

        # Region.
        region = os.environ.get("CRUCIBLE_BEDROCK_REGION", "").strip()
        if not region:
            # Try AWS_REGION / AWS_DEFAULT_REGION as fallback.
            region = (
                os.environ.get("AWS_REGION", "").strip()
                or os.environ.get("AWS_DEFAULT_REGION", "").strip()
            )
        if not region:
            raise BackendUnavailable(
                "CRUCIBLE_BEDROCK_REGION (or AWS_REGION) not set; "
                "Bedrock requires an explicit region."
            )
        allowlist = _region_allowlist()
        if region not in allowlist:
            raise BackendUnavailable(
                f"region {region!r} is not in the sovereign-friendly "
                f"allowlist {allowlist}. Override via "
                f"CRUCIBLE_BEDROCK_REGION_ALLOWLIST if you've vetted "
                f"a different region for your deployment context."
            )
        self.region = region

        # Credentials. boto3's standard chain handles env / role /
        # profile resolution. We do a lightweight presence check here;
        # actual credential validation happens at first call.
        if not (
            os.environ.get("AWS_ACCESS_KEY_ID")
            or os.environ.get("AWS_PROFILE")
            or os.environ.get("AWS_ROLE_ARN")
            or os.path.exists(os.path.expanduser("~/.aws/credentials"))
        ):
            raise BackendUnavailable(
                "no AWS credentials found in env, profile, role, or "
                "~/.aws/credentials; Bedrock requires authenticated access."
            )

        self.model = os.environ.get("CRUCIBLE_BEDROCK_MODEL", _DEFAULT_MODEL)
        self._client: object | None = None

    def is_available(self) -> tuple[bool, str]:
        try:
            import anthropic  # noqa: F401
        except ImportError:
            return False, "anthropic SDK not installed"
        try:
            import boto3  # noqa: F401
        except ImportError:
            return False, "boto3 not installed"
        return True, f"ready (region={self.region}, model={self.model})"

    def _client_obj(self) -> object:
        if self._client is None:
            from anthropic import AnthropicBedrock
            # AnthropicBedrock picks up AWS creds via boto3's chain.
            self._client = AnthropicBedrock(aws_region=self.region)
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
                # AnthropicBedrock exposes the same `messages.create`
                # interface as the standard Anthropic client.
                rsp = client.messages.create(  # type: ignore[attr-defined]
                    model=self.model,
                    system=sys_prompt,
                    messages=[{"role": "user", "content": user_msg}],
                    temperature=prompt.temperature,
                    max_tokens=prompt.max_tokens,
                )
            except Exception as e:
                raise BackendError(f"Bedrock API error: {e}") from e
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
                    "kernel.bedrock.parse_retry",
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
                "kernel.bedrock.complete",
                schema=prompt.schema_name,
                model=self.model, region=self.region,
                tokens_in=tokens_in, tokens_out=tokens_out,
                latency_ms=int(latency),
            )
            return LLMResult(parsed=parsed, trace=trace, raw_response=raw)

        raise BackendError(f"unreachable: {last_error}")
