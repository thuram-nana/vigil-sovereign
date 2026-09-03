"""Richer tool-call cards: the timeline shows each tool call as a real command/output card (Claude-Code
style), and the engine surfaces the REDACTED command + a bounded, already-redacted output excerpt on the
tool_result spine event — never the raw output.

WHY THIS TEST EXISTS. Tool calls were one-line summaries whose click dumped raw payload JSON, and the spine
event carried no command/output (length-only). This slice enriches the tool_result event from the executor's
signed, F3-REDACTED record (`record.argv` / `record.stdout`) — the raw `exec_res.stdout` is used only for a
byte COUNT — and renders a paired command/output card in the (resizable) drawer.

Reads files only (docs-only CI job). Behaviour (redaction on the event; pairing + card render) is verified by
`integration/tests/test_tool_result_card_redaction.py` (both CI legs) and a headless jsdom harness; this is the
wiring drift guard.
"""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
APPJS = (REPO / "packages" / "vigil-ui" / "app.js").read_text(encoding="utf-8")
ENGINE = (REPO / "integration" / "vigil_integration" / "live" / "engine.py").read_text(encoding="utf-8")


def test_engine_enriches_tool_result_from_the_redacted_record_not_raw_stdout():
    # the card fields come from the executor's REDACTED record; raw stdout is only counted.
    assert 'getattr(_rec, "stdout", "")' in ENGINE, "output excerpt must come from the redacted record.stdout"
    assert 'getattr(_rec, "argv", None)' in ENGINE, "command must come from the redacted record.argv"
    assert '"output_excerpt": _out[:_CARD_EXCERPT_CAP]' in ENGINE, "output excerpt must be bounded"
    assert '"output_bytes": len(str(getattr(exec_res, "stdout"' in ENGINE, "raw stdout is used only for the byte count"
    assert "_CARD_EXCERPT_CAP" in ENGINE
    # the enrichment is guarded by _ran so a refused call carries no fabricated command/output
    assert "if _ran:" in ENGINE and '"exit_code": getattr(exec_res, "exit_code"' in ENGINE


def test_ui_renders_a_paired_command_output_card():
    assert "function toolPairFor(e)" in APPJS and "function toolCardBody(call, result)" in APPJS
    # tool_call / tool_result open the card, not the raw-JSON dump
    assert 'if (e.kind === "tool_call" || e.kind === "tool_result")' in APPJS
    assert 'openDrawer("Tool call", toolCardBody(' in APPJS
    # the card has a command block, an output block, and badges
    assert '"COMMAND"' in APPJS and '"OUTPUT"' in APPJS
    assert "rp.output_excerpt" in APPJS and "rp.argv" in APPJS


def test_inline_row_shows_exit_and_output_size_at_a_glance():
    assert 'p.exit_code != null ? " · exit " + p.exit_code' in APPJS
    assert 'p.output_bytes ? " · " + p.output_bytes + " B"' in APPJS
