"""S1 — the approve / deny / Deny-&-redirect interrupt must reach CHAT, not only the Live view. The global
process box (PBOX) that follows a chat-launched run polls the sovereign-plane pending approvals and pops the
SHARED approval modal (`makeApprovalUX`) on any screen except Live (which owns its own interrupt), and renders
the approval cards inline in the box.

Reads files only (docs-only CI job). The modal behaviour itself is verified against the REAL shared factory in
a headless jsdom harness (test_approval_ux.mjs); this guards the chat/PBOX wiring.
"""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
APPJS = (REPO / "packages" / "vigil-ui" / "app.js").read_text(encoding="utf-8")


def test_pbox_uses_the_shared_approval_factory():
    assert "var PBOX_AUX = makeApprovalUX({" in APPJS, "the PBOX must reuse the shared approval factory"
    assert 'reason: "from chat"' in APPJS
    assert "slugOf: function () { return PBOX.run && PBOX.run.slug; }" in APPJS


def test_pbox_polls_sovereign_approvals_and_pops_off_live():
    assert "function pboxApprovalPoll()" in APPJS
    assert 'V.getJSON(SOV("/api/snapshot"))' in APPJS
    assert "PBOX.pendingApprovals = (s && s.pending_approvals)" in APPJS
    # Live owns the interrupt on its own screen; the PBOX pops everywhere else (chat included).
    assert 'if ((location.hash || "").indexOf("#/live") !== 0) PBOX_AUX.maybePop(PBOX.pendingApprovals)' in APPJS


def test_pbox_renders_approval_cards_and_polls_on_the_interval():
    assert "PBOX.pendingApprovals.map(PBOX_AUX.card)" in APPJS, "approval cards must render in the box"
    assert "pboxPoll(); pboxApprovalPoll();" in APPJS, "the poll interval must include the approval poll"
    assert "PBOX_AUX.reset()" in APPJS, "following a new run must re-baseline approvals"
