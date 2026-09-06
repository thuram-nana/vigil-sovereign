"""Wave 8 — a signed-approval pause is surfaced in the chat transcript, and the offense approval popup
offers Deny & redirect (not only Approve / Deny). Docs-only drift guard (reads files)."""
from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
APPJS = (REPO / "packages" / "vigil-ui" / "app.js").read_text(encoding="utf-8")
CHAT = (REPO / "engine" / "crucible" / "framework" / "v2" / "console" / "chat.py").read_text(encoding="utf-8")
ACTIONS = (REPO / "engine" / "crucible" / "framework" / "v2" / "console" / "actions.py").read_text(encoding="utf-8")


def test_backend_surfaces_awaiting_approval_in_the_transcript():
    assert "def post_engine_notice(" in CHAT
    assert 'kind="awaiting_approval"' in ACTIONS
    # ENH1: _maybe_surface now branches on BOTH pause reasons off one read.
    assert '_paused in ("awaiting_approval", "approval_rejected")' in ACTIONS


def test_backend_surfaces_approval_rejected_distinctly():
    # ENH1: a FOUND-but-rejected (expired / already-used) approval posts a DISTINCT notice telling the
    # operator to approve AGAIN, not the generic awaiting_approval invisible loop.
    assert 'kind="approval_rejected"' in ACTIONS
    assert 'm.kind === "approval_rejected"' in APPJS, "the approval_rejected bubble render is gone"
    assert "approval_rejected: 1" in APPJS, "approval_rejected must be an engine kind (not tagged a Lead)"


def test_ui_renders_the_awaiting_approval_bubble_as_an_engine_kind():
    assert "awaiting_approval: 1" in APPJS, "awaiting_approval must be an engine kind (not tagged a Lead)"
    assert 'm.kind === "awaiting_approval"' in APPJS, "the awaiting_approval bubble render is gone"
    assert "Paused — awaiting your approval" in APPJS


def test_offense_approval_popup_offers_deny_and_redirect():
    # the offense modal (pboxOffensePop) now mirrors the sovereign deny-&-redirect: a note steers the run
    assert APPJS.count('"Deny & redirect"') >= 2, "the offense approval modal must offer Deny & redirect"
    # it steers via injectIntoRun on the followed run's slug, then denies the exact action
    assert 'injectIntoRun((PBOX.run && PBOX.run.slug) || "", redirect);' in APPJS
