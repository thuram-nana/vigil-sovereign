"""Process-box UX (operator asks): (1) a pending offense approval is ACTIONABLE + unmissable in the chat
box, (2) the box is RESIZABLE to a preferred size (+ maximize), (3) the model's reasoning shows in PLAIN
WORDS like Claude Code. Reads files only (docs-only CI leg); the render logic is exercised live.
"""
from __future__ import annotations
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
APP = (REPO / "packages" / "vigil-ui" / "app.js").read_text(encoding="utf-8")
CSS = (REPO / "packages" / "vigil-ui" / "components.css").read_text(encoding="utf-8")


def test_approval_is_actionable_and_auto_opens_the_box():
    # the Approve/Deny card renders in the box, wired to the route-via-sovereign handler
    assert "PBOX.offenseApprovals.map(pboxOffenseCard)" in APP
    assert "offenseApprove(p, refresh)" in APP
    # a NEW pending un-hides + opens the box so the card can't be missed
    assert "PBOX.ui.dismissed = false" in APP and "PBOX.ui.open = true" in APP
    assert "un-hides + opens the process box" in APP


def test_process_box_is_resizable_and_maximizable():
    assert "function pboxStartResize" in APP and "function pboxToggleMax" in APP
    assert 'g.addEventListener("pointerdown", pboxStartResize)' in APP
    assert "PBOX.ui.w" in APP and "PBOX.ui.h" in APP and "PBOX.ui.max" in APP  # persisted size + maximized
    assert ".pb-grip" in CSS and ".pb-card.pb-max" in CSS


def test_thinking_shows_the_models_plain_words_reasoning():
    # the Decision/Thinking row surfaces the model's rationale (not just question->choice), and it WRAPS
    assert 'label: "Thinking"' in APP
    assert "p.rationale" in APP
    assert "pb-think-row" in APP
    assert ".pb-row.pb-think-row .pb-m { white-space: normal;" in CSS
