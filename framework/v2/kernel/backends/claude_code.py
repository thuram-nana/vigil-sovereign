"""
ClaudeCodeBackend — routes URK calls through the operator's local
Claude Code installation via `claude -p`.

Why this backend exists:
  - Operators with a Claude Max subscription have `claude` already
    authenticated via OAuth in `~/.claude/.credentials.json`.  No
    API key handling, no env var, no key-leak risk.
  - The `claude` CLI supports `--json-schema` for server-side
    structured-output validation, which is more robust than the
    AnthropicBackend's prose-instruction-plus-retry strategy.
  - It supports `--max-budget-usd` for a hard per-call cost cap.

Approach:
  1. spawn `claude -p` as a subprocess from a clean temp directory
     so Claude Code does not auto-discover CLAUDE.md.
  2. `--system-prompt` REPLACES the default Claude Code system prompt
     (the default loads tool definitions and adds ~22k cache tokens
     per call which is wasted on URK).
  3. `--model haiku` (default) — cheap; URK tasks are short
     structured-output reasoning, well within Haiku's range.
  4. `--json-schema` — Claude Code validates the model's output
     against the URK schema before returning.
  5. `--output-format json` — returns a wrapper envelope with the
     model's `result` text plus cost / token telemetry we record
     into the CallTrace.
  6. `--max-budget-usd` per-call hard cap (default $0.05) — fail-
     closed; the envelope reports `is_error=true` if exceeded.

This backend is parallel to `AnthropicBackend`; both stay in tree.
Selection order is anthropic > claude-code > ollama > dryrun.

This file is exercised live in Session 3 of the FORGE PROTOCOL.
See `V2-LIMITATIONS.md` § 0 for the verification checklist.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from ...common import logging as v2log
from ...common.errors import BackendError, BackendUnavailable
from ..llm import LLMBackend, LLMResult, Prompt, make_call_trace, parse_json_response


_log = v2log.get_logger(__name__)


_DEFAULT_MODEL = "haiku"
# Default agent loads ~28k cache tokens before our prompt arrives, so the
# floor cost is ~$0.04 per call (haiku-4-5 cache creation).  Heavier
# bindings like threat_model() request max_tokens=8000 and need room for
# the full structured output to land.  $0.20 fits comfortably inside a
# session-level $5 cap (~25 calls headroom).
_DEFAULT_PER_CALL_BUDGET_USD = 0.20
_DEFAULT_TIMEOUT_S = 360.0   # threat_model takes ~3-4 min on haiku; observed up to 250s

# Disabling every built-in tool keeps the agent from spawning tool_use
# turns for trivia like "look up the file". URK calls are pure
# reasoning; tools are wasted overhead.
_DISALLOWED_TOOLS = (
    "Bash", "Edit", "Read", "Write", "Grep", "Glob", "Task",
    "TodoWrite", "WebFetch", "WebSearch", "NotebookEdit",
    "Agent", "ToolSearch", "Skill", "MultiEdit",
    "ListAllowedDirs", "FindCommonDirectories",
)


class ClaudeCodeBackend(LLMBackend):
    name = "claude-code"

    def __init__(self) -> None:
        self.binary = shutil.which("claude")
        if not self.binary:
            raise BackendUnavailable("`claude` CLI not found in PATH")
        self.model = os.environ.get("CRUCIBLE_CLAUDE_CODE_MODEL", _DEFAULT_MODEL)
        self.per_call_budget_usd = float(
            os.environ.get(
                "CRUCIBLE_CLAUDE_CODE_BUDGET", str(_DEFAULT_PER_CALL_BUDGET_USD),
            )
        )
        self.timeout_s = float(
            os.environ.get(
                "CRUCIBLE_CLAUDE_CODE_TIMEOUT", str(_DEFAULT_TIMEOUT_S),
            )
        )

    def is_available(self) -> tuple[bool, str]:
        if not self.binary:
            return False, "`claude` CLI not in PATH"
        creds = Path.home() / ".claude" / ".credentials.json"
        if not creds.is_file() and not os.environ.get("ANTHROPIC_API_KEY"):
            return False, (
                "no `~/.claude/.credentials.json` and no ANTHROPIC_API_KEY; "
                "log in with `claude` once or set the env var"
            )
        return True, (
            f"ready (binary={self.binary}, model={self.model}, "
            f"per-call cap=${self.per_call_budget_usd:.2f})"
        )

    # ------------------------------------------------------------------
    # complete()
    # ------------------------------------------------------------------

    def _build_system(self, prompt: Prompt) -> str:
        # `--json-schema` enforces the schema server-side, so we don't
        # repeat the JSON Schema in the system prompt — Claude Code is
        # already showing it to the model. We just remind the model
        # that JSON-only is the contract; the schema does the rest.
        return (
            f"{prompt.system}\n\n"
            "## Output contract\n\n"
            "Respond with a single JSON object that validates the supplied schema. "
            "No prose, no markdown fence, no commentary outside the JSON. "
            "Populate every required field with substantive, non-empty content."
        )

    def complete(self, prompt: Prompt) -> LLMResult:
        sys_prompt = self._build_system(prompt)
        schema_dict = prompt.schema.model_json_schema()

        with tempfile.TemporaryDirectory(prefix="crucible-cc-") as tmpdir:
            cmd = [
                str(self.binary),
                "-p", prompt.user,
                "--system-prompt", sys_prompt,
                "--output-format", "json",
                "--model", self.model,
                "--json-schema", json.dumps(schema_dict),
                "--max-budget-usd", f"{self.per_call_budget_usd:.4f}",
                "--disallowed-tools", " ".join(_DISALLOWED_TOOLS),
                "--disable-slash-commands",
                "--exclude-dynamic-system-prompt-sections",
            ]
            t0 = time.perf_counter()
            try:
                rsp = subprocess.run(
                    cmd, cwd=tmpdir, capture_output=True, text=True,
                    timeout=self.timeout_s,
                )
            except subprocess.TimeoutExpired as e:
                raise BackendError(
                    f"claude -p timed out after {self.timeout_s}s; "
                    f"schema={prompt.schema_name}"
                ) from e
            latency_ms = (time.perf_counter() - t0) * 1000.0

        # Process exit non-zero is a real failure, but Claude Code can also
        # return a 0 exit with `is_error: true` in the envelope when budget
        # is exceeded. Handle both.
        if rsp.returncode != 0:
            raise BackendError(
                f"claude -p exited {rsp.returncode}; "
                f"stderr={rsp.stderr[:500]!r}; stdout_head={rsp.stdout[:200]!r}"
            )

        envelope = self._parse_envelope(rsp.stdout)
        if envelope.get("is_error"):
            errs = envelope.get("errors") or [envelope.get("subtype", "unknown_error")]
            raise BackendError(
                f"claude -p error envelope: {errs}; "
                f"cost so far ${envelope.get('total_cost_usd', 0):.4f}"
            )

        # Two paths:
        #   1. envelope.structured_output — already a validated dict (the
        #      CLI ran the schema check and returned the parsed object).
        #      Pydantic-revalidate to apply URK's stricter Literal/range
        #      constraints, but we don't need to JSON-parse text.
        #   2. fall back to envelope.result text (older CLI versions or
        #      when --json-schema is absent).
        struct = envelope.get("structured_output")
        result_text = self._extract_result_text(envelope)

        if isinstance(struct, dict) and struct:
            try:
                parsed = prompt.schema.model_validate(struct)
                # raw_response: round-trip the dict to a string for audit
                raw = json.dumps(struct, ensure_ascii=False)
            except Exception as e:
                raise BackendError(
                    f"structured_output failed Pydantic validation against "
                    f"{prompt.schema_name}: {e}; struct={struct!r}"
                ) from e
        elif result_text:
            parsed = parse_json_response(result_text, prompt.schema)
            raw = result_text
        else:
            raise BackendError(
                f"claude -p returned no structured_output and no result text "
                f"for schema={prompt.schema_name}; envelope keys: "
                f"{list(envelope.keys())}"
            )

        def _as_int(v: object) -> int:
            if isinstance(v, (int, float)):
                return int(v)
            if isinstance(v, str) and v.isdigit():
                return int(v)
            return 0

        def _as_float(v: object) -> float:
            if isinstance(v, (int, float)):
                return float(v)
            return 0.0

        usage_raw = envelope.get("usage", {})
        usage: dict[str, object] = usage_raw if isinstance(usage_raw, dict) else {}
        tokens_in = (
            _as_int(usage.get("input_tokens", 0))
            + _as_int(usage.get("cache_read_input_tokens", 0))
            + _as_int(usage.get("cache_creation_input_tokens", 0))
        )
        tokens_out = _as_int(usage.get("output_tokens", 0))
        cost_usd = _as_float(envelope.get("total_cost_usd", 0.0))

        trace = make_call_trace(
            backend=self.name,
            is_dryrun=False,
            cognitive_doc=prompt.cognitive_doc,
            cognitive_sections=prompt.cognitive_sections,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            latency_ms=latency_ms,
        )

        _log.info(
            "kernel.claude_code.complete",
            schema=prompt.schema_name,
            model=self.model,
            tokens_in=tokens_in, tokens_out=tokens_out,
            cost_usd=round(cost_usd, 5),
            latency_ms=int(latency_ms),
            session_id=envelope.get("session_id", ""),
        )
        return LLMResult(parsed=parsed, trace=trace, raw_response=raw)

    # ------------------------------------------------------------------
    # parsing helpers
    # ------------------------------------------------------------------

    def _parse_envelope(self, stdout: str) -> dict[str, object]:
        """Claude Code's `--output-format json` returns one JSON object."""
        s = stdout.strip()
        if not s:
            raise BackendError("claude -p returned empty stdout")
        try:
            return json.loads(s)  # type: ignore[no-any-return]
        except json.JSONDecodeError:
            # Some versions stream a leading whitespace / log line — try
            # the last line as JSON (the envelope is always a one-liner).
            for line in reversed(s.splitlines()):
                line = line.strip()
                if line.startswith("{") and line.endswith("}"):
                    try:
                        return json.loads(line)  # type: ignore[no-any-return]
                    except json.JSONDecodeError:
                        continue
            raise BackendError(
                f"could not parse claude -p envelope; raw stdout (head): {s[:500]!r}"
            )

    def _extract_result_text(self, envelope: dict[str, object]) -> str:
        """The model's response lives in `result` for `--output-format json`.

        Be defensive: try a couple of plausible field names so a CLI
        version bump doesn't quietly break URK.
        """
        for key in ("result", "content", "output", "text", "message"):
            v = envelope.get(key)
            if isinstance(v, str) and v.strip():
                return v
            if isinstance(v, list):
                # message-shaped: list of {type, text}
                for piece in v:
                    if isinstance(piece, dict) and piece.get("type") == "text":
                        t = piece.get("text", "")
                        if isinstance(t, str) and t.strip():
                            return t
        return ""
