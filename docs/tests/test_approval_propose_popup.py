"""When the agent PROPOSES an action needing owner sign-off, an approve/deny popup must INTERRUPT — not only
drop a card into a list. The interaction lives in ONE shared factory `makeApprovalUX` (R0) reused by both the
Live view and Chat; the Live view wires it via `AUX`.

Reads files only (docs-only CI job). Behaviour (baseline-on-entry, interrupt, approve/deny, single-modal,
reset) is verified against the REAL sliced factory in a headless jsdom harness; this is the drift guard.
"""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
APPJS = (REPO / "packages" / "vigil-ui" / "app.js").read_text(encoding="utf-8")


def test_shared_factory_exists_with_the_interrupt_helpers():
    assert "function makeApprovalUX(ctx)" in APPJS, "the shared approval factory is gone"
    for fn in ("function maybePop(pend)", "function popModal(a)", "function card(a)", "function act(action, seq)"):
        assert fn in APPJS, f"makeApprovalUX is missing {fn}"


def test_baseline_on_entry_then_interrupt_on_new_proposals():
    assert "ctx.mem.seen = true" in APPJS, "baseline-on-entry flag is gone"
    assert "ctx.mem.popped[" in APPJS
    assert "if (ctx.mem.modal) return;" in APPJS, "single-modal guard is gone"


def test_popup_uses_the_modal_and_sends_the_signed_action():
    assert 'openModal("Approve this action?"' in APPJS
    assert 'act("approve", a.seq)' in APPJS and 'act("deny", a.seq)' in APPJS
    assert 'V.postJSON(SOV("/api/action")' in APPJS, "approvals must post the signed SOV action"


def test_live_view_wires_the_shared_factory():
    assert "const AUX = makeApprovalUX({" in APPJS
    assert "AUX.maybePop(pend)" in APPJS and "pend.map(AUX.card)" in APPJS
    assert "AUX.reset()" in APPJS, "selectRun must reset the approval memory via the shared factory"


def test_no_leak_after_navigation():
    assert "liveApprovalModal" in APPJS and "liveApprovalModal.close()" in APPJS and "function teardownLive()" in APPJS
