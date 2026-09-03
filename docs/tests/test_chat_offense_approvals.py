"""S1b — a chat-launched OFFENSE engage's queued approval must reach CHAT.

S1 wired the sovereign-plane (seq-based) approval interrupt into the chat process box, but a chat-launched
`vigil engage` queues its higher-tier tool in the KEYLESS OFFENSE broker (`OFF /api/approvals/`), which the
sovereign snapshot does NOT carry. So a paused engage never surfaced its approval in the chat. S1b closes
that: the PBOX also polls the offense approvals and renders/pops them, wired to the route-via-sovereign
`offenseApprove`/`offenseDeny` handlers (the cockpit signs with the owner key; the offense console stays
keyless), with the out-of-band `vigil approve sign` command shown as a fallback.

Reads files only (docs-only CI job). The card wiring + baseline/pop behaviour is verified against the REAL
sliced functions in a headless jsdom harness (test_offense_approvals.mjs); this guards the wiring/plumbing.
"""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
APPJS = (REPO / "packages" / "vigil-ui" / "app.js").read_text(encoding="utf-8")


def test_pbox_polls_offense_broker_approvals():
    assert "function pboxApprovalPoll()" in APPJS
    assert 'V.getJSON(OFF("/api/approvals/loopback"))' in APPJS, "the PBOX must also poll the offense broker"
    assert "PBOX.offenseApprovals = (d && d.pending)" in APPJS
    # baseline + pop off-Live, same discipline as the sovereign approvals
    assert 'if ((location.hash || "").indexOf("#/live") !== 0) pboxOffenseMaybePop(PBOX.offenseApprovals)' in APPJS


def test_offense_card_wires_route_via_sovereign_handlers():
    assert "function pboxOffenseCard(p)" in APPJS
    # in-band approve/deny go through the existing route-via-sovereign handlers (cockpit signs; console keyless)
    assert "offenseApprove(p, refresh)" in APPJS
    assert "offenseDeny(p, refresh)" in APPJS


def test_offense_pop_is_baselined_and_shows_the_sign_command():
    assert "function pboxOffenseMaybePop(pend)" in APPJS
    assert "function pboxOffensePop(p)" in APPJS
    # baseline whatever is already queued on entry (no nag), one modal at a time across BOTH approval kinds
    assert "if (PBOX.offenseMem.modal || PBOX.approvalMem.modal) return;" in APPJS
    assert "if (!PBOX.offenseMem.seen)" in APPJS
    # out-of-band fallback: the exact CLI sign command for this request
    assert '"vigil approve sign --base-dir "' in APPJS


def test_offense_cards_render_in_the_box_and_reset_on_new_run():
    assert "PBOX.offenseApprovals.map(pboxOffenseCard)" in APPJS, "offense cards must render in the box"
    assert "var allCards = sovCards.concat(offCards);" in APPJS, "sovereign + offense cards render together"
    assert "pboxOffenseReset();" in APPJS, "following a new run must re-baseline offense approvals too"
