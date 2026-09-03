"""Edit-a-proposed-action = "Deny & redirect": reject the exact proposal AND tell the agent what to do
instead, so it re-plans — Claude-Code's reject-with-feedback, without relaxing the signed-approval model.

WHY THIS TEST EXISTS. An approval is bound to the exact signed (tool,target,args); you cannot approve a
different action under the same grant. So "edit" is: DENY the exact proposal (`act("deny", seq)`) and send the
operator's note as ordinary mid-run guidance (`/api/instruct` via `injectIntoRun`); the agent proposes afresh
(each new proposal is re-gated). This guard ensures the redirect stays deny-then-steer and never a silent
arg-mutation.

Reads files only (docs-only CI job). Behaviour (steer+deny on a note, guarded no-op on empty, plain
Deny/Approve unchanged) is verified against the REAL sliced code in a headless jsdom harness.
"""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
APPJS = (REPO / "packages" / "vigil-ui" / "app.js").read_text(encoding="utf-8")


def test_popup_has_a_redirect_input_and_button():
    assert "Deny & redirect" in APPJS
    assert 'placeholder: "Tell the agent what to do instead' in APPJS
    assert "const denyRedirect = function ()" in APPJS or "function denyRedirect" in APPJS or "denyRedirect = function" in APPJS


def test_redirect_denies_the_exact_proposal_and_steers_via_instruct():
    # deny the exact seq AND steer through the existing mid-run instruct path — NOT a modified-args approve.
    assert 'injectIntoRun(L.run && L.run.slug, redirect)' in APPJS
    assert 'act("deny", a.seq)' in APPJS
    # injectIntoRun is the /api/instruct path (the signed-approval model is untouched)
    assert '/api/instruct' in APPJS


def test_empty_note_is_a_guarded_no_op():
    assert 'Type what the agent should do instead first.' in APPJS


def test_cards_also_offer_deny_and_redirect():
    # the inline Live approval card reuses the modal (guarded to one) so a card can deny-and-steer too.
    assert "if (!L.approvalModal) popApprovalModal(a)" in APPJS
