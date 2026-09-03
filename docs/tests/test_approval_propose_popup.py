"""When the agent PROPOSES an action that needs owner sign-off, the Live view must INTERRUPT with an
approve/deny popup — not only drop a card into a list the operator might not be watching (the Claude-Code
"propose" permission prompt).

WHY THIS TEST EXISTS. Approvals already rendered as inline cards, but a decision could sit unseen. The popup
surfaces a NEW proposal the moment it arrives. It must (a) NOT nag on entry for approvals already pending
(baseline first), (b) interrupt for a genuinely new proposal, (c) send the SAME approve/deny action the cards
do, (d) show at most one at a time, and (e) not leak a floating modal after navigation.

Reads files only (docs-only CI job). Behaviour (baseline→interrupt→approve→close→single-modal) is verified
against the REAL sliced code in a headless jsdom harness during development; this is the drift guard.
"""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
APPJS = (REPO / "packages" / "vigil-ui" / "app.js").read_text(encoding="utf-8")


def test_popup_functions_exist_and_are_invoked_from_approvals():
    assert "function maybePopApproval(pend)" in APPJS
    assert "function popApprovalModal(a)" in APPJS
    assert "maybePopApproval(pend);" in APPJS, "drawApprovals must drive the popup on each snapshot"


def test_entry_baselines_then_interrupts_on_new_proposals():
    # approvalSeen flips on the first snapshot to baseline existing approvals without nagging.
    assert "approvalSeen" in APPJS
    assert "L.approvalSeen = true" in APPJS
    # only unpopped (new) proposals pop
    assert "L.approvalPopped[" in APPJS


def test_popup_uses_the_modal_and_sends_the_same_decision():
    assert 'openModal("Approve this action?"' in APPJS
    assert 'act("approve", a.seq)' in APPJS and 'act("deny", a.seq)' in APPJS


def test_only_one_modal_and_no_leak_after_navigation():
    # single-modal guard
    assert "if (L.approvalModal) return;" in APPJS
    # module-level ref closed by teardownLive (which runs on every screen change)
    assert "liveApprovalModal" in APPJS
    assert "liveApprovalModal.close()" in APPJS and "function teardownLive()" in APPJS
