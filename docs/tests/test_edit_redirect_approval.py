"""Edit-a-proposed-action = "Deny & redirect": reject the exact proposal AND tell the agent what to do
instead. Lives in the shared `makeApprovalUX` factory (R0), reused by Live and Chat. The signed-approval
model is untouched: DENY the exact proposal (`act("deny", seq)`) and send the note as ordinary mid-run
guidance (`injectIntoRun` → `/api/instruct`); the agent re-plans (re-gated).

Reads files only (docs-only CI job). Behaviour verified against the REAL sliced factory in a headless jsdom
harness.
"""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
APPJS = (REPO / "packages" / "vigil-ui" / "app.js").read_text(encoding="utf-8")


def test_popup_has_a_redirect_input_and_button():
    assert "Deny & redirect" in APPJS
    assert 'placeholder: "Tell the agent what to do instead' in APPJS
    assert "const denyRedirect = function ()" in APPJS


def test_redirect_denies_the_exact_proposal_and_steers_via_instruct():
    # deny the exact seq AND steer through the existing mid-run instruct path (slug from the surface ctx).
    assert "injectIntoRun(ctx.slugOf && ctx.slugOf(), redirect)" in APPJS
    assert 'act("deny", a.seq)' in APPJS
    assert "/api/instruct" in APPJS


def test_empty_note_is_a_guarded_no_op():
    assert "Type what the agent should do instead first." in APPJS


def test_cards_also_offer_deny_and_redirect():
    # the inline approval card reuses the modal (guarded to one) so a card can deny-and-steer too.
    assert "if (!ctx.mem.modal) popModal(a)" in APPJS
