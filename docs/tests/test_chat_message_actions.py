"""S3 — per-message actions in chat (copy / edit-&-resend / regenerate), a hover row on plain text bubbles,
like Claude Code. All reuse existing primitives and the normal send path (no new endpoint).

Reads files only (docs-only CI job). copyText + input.value/doSend are already covered by other tests; this
guards that the message-actions row is wired to them.
"""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
APPJS = (REPO / "packages" / "vigil-ui" / "app.js").read_text(encoding="utf-8")
CSS = (REPO / "packages" / "vigil-ui" / "components.css").read_text(encoding="utf-8")


def test_actions_row_present_on_text_bubbles():
    assert 'h("div.msg-actions"' in APPJS, "the per-message actions row is gone"
    # only plain text bubbles (user messages + model 'lead' answers), not engine-kind bubbles
    assert "if (isUser || isLead) {" in APPJS


def test_copy_edit_regenerate_wired_to_existing_primitives():
    assert 'onClick: function () { copyText(text); }' in APPJS, "Copy must reuse copyText"
    assert 'input.value = text;' in APPJS, "Edit & resend must repopulate the composer"
    # regenerate scans back for the preceding user turn and re-sends via the normal path
    assert 'arr[j].role === "user"' in APPJS and "input.value = prev; doSend();" in APPJS


def test_actions_have_hover_css():
    assert ".msg-actions" in CSS and "opacity: 0" in CSS and ".msg-act:hover" in CSS
