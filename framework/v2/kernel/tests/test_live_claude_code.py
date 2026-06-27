"""
Live URK reasoning over the Claude Code backend — no API key required.

The framework can use the operator's Claude Code CLI (`claude -p`, e.g. a
Max subscription) as the reasoning backend instead of ANTHROPIC_API_KEY.
This test exercises that path for real: it runs a URK `critique` binding
live and asserts the call did NOT fall back to DryRun.

Opt-in and gated, because it spends subscription tokens and needs the
`claude` CLI:
    CRUCIBLE_LIVE_LLM=1 pytest framework/v2/kernel/tests/test_live_claude_code.py
Skipped otherwise (and in CI).

This is the substrate for the "reasoning over deep analysis" loop: a real
DAA taint finding (e.g. an SSRF source->sink flow) becomes a claim that
URK critique confirms or refutes — verified end-to-end on 2026-06-27 in
the Claude Code remote environment (critique returned decision=confirm).
"""

from __future__ import annotations

import os
import shutil

import pytest

from ..critique import critique
from ..llm import reset_cache

_LIVE = os.environ.get("CRUCIBLE_LIVE_LLM") == "1" and shutil.which("claude") is not None

requires_live_claude = pytest.mark.skipif(
    not _LIVE,
    reason="set CRUCIBLE_LIVE_LLM=1 and have the `claude` CLI to run the live URK test",
)


@requires_live_claude
def test_critique_runs_live_over_claude_code(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CRUCIBLE_LLM_BACKEND", "claude-code")
    reset_cache()
    try:
        result, trace = critique(
            claim="SSRF: the 'url' request parameter flows unvalidated into "
            "requests.get(), enabling server-side request forgery.",
            evidence="DAA semgrep taint finding: source request.args.get('url') "
            "reaches sink requests.get(); CWE-918; the sanitized constant-URL "
            "variant produced zero taint findings (real dataflow, not regex).",
            context="Flask app, source review",
        )
    finally:
        reset_cache()

    # The call must have actually reasoned, not fallen back to DryRun.
    assert trace.is_dryrun is False
    assert trace.backend == "claude-code"
    assert trace.tokens_out > 0
    # A real critique returns a decision; we don't constrain which one.
    assert isinstance(result.decision, str) and result.decision
