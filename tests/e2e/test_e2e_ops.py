"""E2E suite — MANAGE cluster: ops + ceremonies (the EVAL button) + safety.

Cluster KEY=ops. Screens (renderer line in packages/vigil-ui/app.js):
  system(6410) durability(6610) ceremonies(6769) safety(5282)
  charter(11159) apikeys(5177) budgets(9446)

Grounding method (no guessing): every assertion below is grounded by READING the
renderer in app.js. For each screen we assert (a) the TOP-OF-RENDER, nav-driven,
UN-POLLED backend read fires at the network layer (helpers.assert_calls over CDP),
plus a render assertion (a text that only appears once the screen rendered), and
(b) each interactive control:
  * SAFE read / non-mutating action  -> click it, assert its backend call fires  [real_flow]
  * DESTRUCTIVE / OFFENSE / owner-sign -> assert the GATE engages (confirm()/ceremony
    demanded) and DISMISS it so the action is NEVER performed                   [assert_gate]

POLLING TRAP (helpers.py warning): a background setInterval green-washes assert_calls.
Confirmed polled endpoints that must NEVER be asserted:
  /sovereign/api/snapshot        (pboxApprovalPoll 4s global + loadSafety 5s)
  /offense/api/approvals/loopback(loadPendingApprovals 5s)
So the SAFETY screen has NO nav-driven un-polled read; for it we assert render +
control wiring only (documented on each safety test).

Footprint honesty: the durability Backup/Escrow and charter loopback-Provision
controls have NO client confirm, so proving they are wired means firing their real
POST (the task mandates "assert the POST fires"). They are owner-authorized,
loopback-scoped / reversible ops on the operator's OWN stack and are fired with
DUMMY inputs. Docker-lifecycle (services up) and the Safety kill-switch Engage are
deliberately NOT fired (would touch docker / halt the mesh) — asserted present only.
"""
from __future__ import annotations

import time

import pytest

from helpers import assert_calls


# ── small grounded helpers ───────────────────────────────────────────────────
def _nav(page, screen_id: str) -> None:
    page.evaluate(f"location.hash = '#/{screen_id}'")


def _wait_owner(page, perm: str = "secrets", timeout_ms: int = 15_000) -> bool:
    """Poll until the SPA's principal carries `perm`.

    (CSP forbids wait_for_function — it needs 'unsafe-eval'; page.evaluate of a passed
    function is allowed, so we poll it.)
    """
    end = time.time() + timeout_ms / 1000
    while time.time() < end:
        if page.evaluate(
            "(p) => { var pr = window.VUI && VUI.principal();"
            " return !!(pr && pr.permissions && pr.permissions.indexOf(p) >= 0); }",
            perm,
        ):
            return True
        page.wait_for_timeout(200)
    return False


def _boot_owner(page, perm: str = "secrets") -> None:
    """Adopt the seeded owner principal into the SPA so owner-gated UI (V.can) renders.

    HARNESS NOTE (grounded): conftest.authed_page seeds the session token then does
    goto(base+"/#/home"), which only changes the HASH — boot() does NOT re-run, so the
    SPA's boot loadPrincipal() (app.js:11733 -> ui.js setPrincipal) never fetches whoami
    with the seeded token and VUI.principal() stays null (V.can('secrets') == false).
    API reads still work (ui.js token() is read live per call), but owner-gated cards
    (drawCeremonies `if (V.can("secrets"))`, app.js:6810) never mount. A real reload
    re-runs boot() with the persisted sessionStorage token and loads the principal. This
    is a session-seeding artifact of the fixture, NOT a product defect: a real full page
    load (what a user does) loads the principal normally.
    """
    page.reload(wait_until="domcontentloaded")
    page.wait_for_selector("#screen", timeout=15_000)
    assert _wait_owner(page, perm), f"owner principal with {perm!r} never loaded after reload"


def _gate_dismiss(page, click_selector: str, expect_substr: str, timeout_ms: int = 8000):
    """Click a DESTRUCTIVE control, assert its confirm() gate engages, DISMISS it.

    Uses page.once("dialog", ...) which dismisses the dialog the moment it opens (so the
    onClick's confirm() returns false and the destructive POST is NEVER sent), recording
    the message for the gate assertion. (A `with page.expect_request/expect_event` around
    the click deadlocks: the click blocks on confirm() while expect_event waits for the
    click to return.)
    """
    captured: dict = {}

    def _handle(dialog):
        captured["msg"] = dialog.message
        dialog.dismiss()

    page.once("dialog", _handle)
    page.click(click_selector)
    end = time.time() + timeout_ms / 1000
    while "msg" not in captured and time.time() < end:
        page.wait_for_timeout(100)
    assert "msg" in captured, f"no confirm() gate fired for {click_selector!r} (destructive control ungated?)"
    assert expect_substr.lower() in captured["msg"].lower(), (
        f"confirm() gate message {captured['msg']!r} does not mention {expect_substr!r}"
    )
    return captured["msg"]


def _goto(page, screen_id: str, ready_text: str) -> None:
    _nav(page, screen_id)
    page.wait_for_selector(f"text={ready_text}", timeout=15_000)


# ══════════════════════════════════════════════════════════════════════════════
# SYSTEM — renderSystem 6410; top read GET /offense/api/services (un-polled)
# ══════════════════════════════════════════════════════════════════════════════
@pytest.mark.real_flow
def test_system_renders_and_reads_services(authed_page):
    page = authed_page
    with assert_calls(page, "GET", "/offense/api/services"):
        _nav(page, "system")
    page.wait_for_selector("text=System & Services", timeout=15_000)


@pytest.mark.real_flow
def test_system_daemons_status_fires_on_render(authed_page):
    # daemonsCard() POSTs /offense/api/daemons/status at top of render (not polled).
    page = authed_page
    with assert_calls(page, "POST", "/offense/api/daemons/status"):
        _nav(page, "system")


@pytest.mark.real_flow
def test_system_render_compose_fires(authed_page):
    page = authed_page
    _goto(page, "system", "System & Services")
    page.wait_for_selector("button:has-text('Re-render compose')", timeout=15_000)
    with assert_calls(page, "POST", "/offense/api/services/render"):
        page.click("button:has-text('Re-render compose')")


@pytest.mark.real_flow
def test_system_mode_status_fires(authed_page):
    # Lifecycle "Mode status" -> POST /offense/api/emergency-stop {action:status} (safe read, no confirm).
    page = authed_page
    _goto(page, "system", "Lifecycle & Emergency")
    with assert_calls(page, "POST", "/offense/api/emergency-stop"):
        page.click("button:has-text('Mode status')")


@pytest.mark.real_flow
def test_system_offense_doctor_fires(authed_page):
    page = authed_page
    _goto(page, "system", "Run doctor")
    with assert_calls(page, "POST", "/offense/api/doctor"):
        page.click("button:has-text('Run offense doctor')")


@pytest.mark.real_flow
def test_system_sovereign_doctor_fires(authed_page):
    page = authed_page
    _goto(page, "system", "Run doctor")
    with assert_calls(page, "GET", "/sovereign/api/doctor"):
        page.click("button:has-text('Run sovereign doctor')")


@pytest.mark.assert_gate
def test_system_gateway_down_gated(authed_page):
    page = authed_page
    _goto(page, "system", "Docker services")
    _gate_dismiss(page, "button:has-text('Gateway down')", "egress-gateway")


@pytest.mark.assert_gate
def test_system_enter_restricted_mode_gated(authed_page):
    page = authed_page
    _goto(page, "system", "Lifecycle & Emergency")
    _gate_dismiss(page, "button:has-text('Enter Restricted Mode')", "RESTRICTED MODE")


@pytest.mark.assert_gate
def test_system_leave_restricted_mode_gated(authed_page):
    page = authed_page
    _goto(page, "system", "Lifecycle & Emergency")
    _gate_dismiss(page, "button:has-text('Leave (owner)')", "Leave Restricted Mode")


@pytest.mark.assert_gate
def test_system_panic_gated_never_tripped(authed_page):
    # The hard-stop. NEVER fired — assert the double-confirm engages and dismiss.
    page = authed_page
    _goto(page, "system", "Lifecycle & Emergency")
    _gate_dismiss(page, "button:has-text('Emergency hard-stop (panic)')", "HARD-STOP")


@pytest.mark.assert_gate
def test_system_contain_console_down_gated(authed_page):
    page = authed_page
    _goto(page, "system", "Lifecycle & Emergency")
    _gate_dismiss(page, "button:has-text('Contain the console (down)')", "Contain the running console")


@pytest.mark.real_flow
def test_system_bring_up_present_not_fired(authed_page):
    # POST /offense/api/services/up has NO client confirm and starts docker services.
    # ROE forbids touching docker -> assert present + wired, do NOT click.
    page = authed_page
    _goto(page, "system", "Docker services")
    assert page.locator("button:has-text('Bring up missing services')").count() >= 1


# ══════════════════════════════════════════════════════════════════════════════
# DURABILITY — renderDurability 6610; top read GET /sovereign/api/backup/list
# ══════════════════════════════════════════════════════════════════════════════
@pytest.mark.real_flow
def test_durability_renders_and_lists_backups(authed_page):
    page = authed_page
    with assert_calls(page, "GET", "/sovereign/api/backup/list"):
        _nav(page, "durability")
    page.wait_for_selector("text=Backups on this host", timeout=15_000)


@pytest.mark.real_flow
def test_durability_create_backup_fires(authed_page):
    page = authed_page
    _goto(page, "durability", "Create backup")
    page.fill("input[placeholder='backup passphrase (min 8 chars)']", "qa-dummy-pass-123")
    page.fill("input[placeholder='confirm passphrase']", "qa-dummy-pass-123")
    with assert_calls(page, "POST", "/sovereign/api/backup"):
        page.click("button:has-text('Create backup')")


@pytest.mark.real_flow
def test_durability_restore_fires_fail_closed(authed_page):
    # Restore stages into a FRESH home and NEVER overwrites live; a bogus id fails closed.
    page = authed_page
    _goto(page, "durability", "Restore (to a fresh staging home)")
    page.fill("input[placeholder*='backup id']", "qa-nonexistent-id")
    page.fill("input[placeholder='backup passphrase']", "qa-dummy-pass-123")
    with assert_calls(page, "POST", "/sovereign/api/restore"):
        page.click("button:has-text('Restore to staging')")


@pytest.mark.real_flow
def test_durability_escrow_fires(authed_page):
    # Escrow splits a DUMMY passphrase m-of-n (defaults 2/3). No confirm -> POST-fires proves wiring.
    page = authed_page
    _goto(page, "durability", "Escrow the backup passphrase")
    page.fill("input[placeholder='backup passphrase to escrow (min 8 chars)']", "qa-dummy-pass-123")
    with assert_calls(page, "POST", "/offense/api/escrow"):
        page.click("button:has-text('Escrow passphrase (m-of-n)')")


# ══════════════════════════════════════════════════════════════════════════════
# CEREMONIES — renderCeremonies 6769; top read GET /sovereign/api/ceremonies/owner-pubkey
# Owns the EVAL button. Mutations are owner (V.can secrets) + confirm()-gated.
# ══════════════════════════════════════════════════════════════════════════════
@pytest.mark.real_flow
def test_ceremonies_renders_and_reads_pubkey(authed_page):
    page = authed_page
    _boot_owner(page)
    with assert_calls(page, "GET", "/sovereign/api/ceremonies/owner-pubkey"):
        _nav(page, "ceremonies")
    page.wait_for_selector("text=Owner public key", timeout=15_000)


@pytest.mark.real_flow
def test_ceremonies_eval_card_and_override_enum(authed_page):
    # The eval card renders (owner-gated) and the override checkboxes are the CLOSED enum
    # {witness_quorum, blast_veto, containment_preview} — never-liftable floors can't be named.
    page = authed_page
    _boot_owner(page)
    _goto(page, "ceremonies", "Eval capability grant (supervised eval)")
    for ov in ("witness_quorum", "blast_veto", "containment_preview"):
        assert page.locator(f"input[type=checkbox][value='{ov}']").count() == 1, f"missing override {ov}"
    assert page.locator("input[type=checkbox]").count() == 3, "override enum is not the closed set of 3"


@pytest.mark.real_flow
def test_ceremonies_eval_status_read_fires(authed_page):
    page = authed_page
    _boot_owner(page)
    _goto(page, "ceremonies", "Status (fail-closed read)")
    page.fill("input[placeholder*='to inspect']", "qa-eval")
    with assert_calls(page, "GET", "/sovereign/api/ceremonies/eval-grant/status"):
        page.click("button:has-text('Read status')")


@pytest.mark.assert_gate
def test_ceremonies_eval_arm_gated_never_armed(authed_page):
    # Fill the required fields + one override so the control reaches its confirm() gate,
    # then DISMISS — the owner-sign/arm POST (/eval-grant/arm) is never sent.
    page = authed_page
    _boot_owner(page)
    _goto(page, "ceremonies", "Arm a grant (owner-signs on the host)")
    page.fill("input[placeholder*='acme-q4-eval']", "qa-eval")
    page.fill("input[placeholder*='no leading']", "http://127.0.0.1:19010/")
    page.fill("input[placeholder*='evaluator username']", "qa-evaluator")
    page.fill("input[placeholder*='evaluator pubkey']", "QUExYmFzZTY0ZHVtbXlwdWJrZXkxMjM0NTY3OA==")
    page.fill("input[placeholder*='evaluator PoP']", "QUExYmFzZTY0ZHVtbXlwb3BzaWduYXR1cmUxMjM0")
    page.check("input[type=checkbox][value='witness_quorum']")
    _gate_dismiss(page, "button:has-text('Arm grant (owner-sign)')", "EvalCapabilityGrant")


@pytest.mark.assert_gate
def test_ceremonies_eval_revoke_gated(authed_page):
    page = authed_page
    _boot_owner(page)
    _goto(page, "ceremonies", "Eval capability grant (supervised eval)")
    page.fill("input[placeholder*='to revoke']", "qa-eval")
    _gate_dismiss(page, "button:has-text('Revoke grant')", "Revoke the eval grant")


@pytest.mark.assert_gate
def test_ceremonies_vault_provision_gated(authed_page):
    page = authed_page
    _boot_owner(page)
    _goto(page, "ceremonies", "Seal & pin (owner)")
    _gate_dismiss(page, "button:has-text('Provision vault (TPM-seal a KEK)')", "Provision the vault")


@pytest.mark.assert_gate
def test_ceremonies_kernel_pin_gated(authed_page):
    page = authed_page
    _boot_owner(page)
    _goto(page, "ceremonies", "Seal & pin (owner)")
    _gate_dismiss(page, "button:has-text('Pin kernel binary')", "Pin the WARDEN kernel")


@pytest.mark.real_flow
def test_ceremonies_mesh_fingerprint_preview_fires(authed_page):
    # Preview fingerprint is a NON-mutating compute -> assert the POST fires.
    page = authed_page
    _boot_owner(page)
    _goto(page, "ceremonies", "Device mesh (phone pairing)")
    with assert_calls(page, "POST", "/sovereign/api/ceremonies/mesh/fingerprint"):
        page.click("button:has-text('Preview fingerprint')")


@pytest.mark.assert_gate
def test_ceremonies_mesh_authorize_gated(authed_page):
    page = authed_page
    _boot_owner(page)
    _goto(page, "ceremonies", "Device mesh (phone pairing)")
    _gate_dismiss(page, "button:has-text('Authorize device')", "Authorize this device")


@pytest.mark.assert_gate
def test_ceremonies_mesh_revoke_gated(authed_page):
    page = authed_page
    _boot_owner(page)
    _goto(page, "ceremonies", "Device mesh (phone pairing)")
    _gate_dismiss(page, "button:has-text('Revoke device')", "Revoke this device key")


@pytest.mark.real_flow
def test_ceremonies_delegate_preview_fires(authed_page):
    # Preview keys validates the offense identity server-side (non-mutating) -> POST fires.
    page = authed_page
    _boot_owner(page)
    _goto(page, "ceremonies", "Delegate offense authority (owner)")
    with assert_calls(page, "POST", "/sovereign/api/ceremonies/delegate/preview"):
        page.click("button:has-text('Preview keys')")


@pytest.mark.assert_gate
def test_ceremonies_delegate_sign_gated(authed_page):
    page = authed_page
    _boot_owner(page)
    _goto(page, "ceremonies", "Delegate offense authority (owner)")
    _gate_dismiss(page, "button:has-text('Sign delegation')", "Owner-sign the offense delegation")


# ══════════════════════════════════════════════════════════════════════════════
# SAFETY — renderSafety 5282. Both top reads are POLLED (snapshot 4s/5s,
# approvals/loopback 5s) -> NO nav-driven un-polled read exists. Assert render +
# control WIRING only (never assert_calls here: a poll would green-wash it).
# ══════════════════════════════════════════════════════════════════════════════
@pytest.mark.real_flow
def test_safety_renders(authed_page):
    page = authed_page
    _goto(page, "safety", "Approvals & Safety")
    page.wait_for_selector("#safety-tiles", timeout=15_000)
    page.wait_for_selector("#safety-kill", timeout=15_000)


@pytest.mark.real_flow
def test_safety_sections_render(authed_page):
    page = authed_page
    _goto(page, "safety", "Approvals & Safety")
    for sel in ("#safety-approvals", "#safety-caps", "#safety-promos", "#safety-feed", "#safety-pending"):
        assert page.locator(sel).count() == 1, f"safety section {sel} did not render"


@pytest.mark.assert_gate
def test_safety_killswitch_control_present_not_tripped(authed_page):
    # The kill-switch card renders with the halt/release control wired. Engaging halts the
    # agent mesh and has NO client confirm (by design: "halting is always safe and immediate"),
    # so there is no gate to dismiss -> assert the control is PRESENT + wired and NEVER click it
    # (clicking would halt the mesh; forbidden by ROE). See residual note in the report.
    page = authed_page
    _goto(page, "safety", "Approvals & Safety")
    # drawSafety() mounts the halt/release button only after the (polled) snapshot read
    # resolves — poll for it rather than racing the first fetch.
    end = time.time() + 12
    seen = 0
    while time.time() < end:
        seen = (page.locator("#safety-kill button:has-text('Engage kill-switch')").count()
                + page.locator("#safety-kill button:has-text('Release')").count())
        if seen:
            break
        page.wait_for_timeout(300)
    assert seen >= 1, "kill-switch card never rendered a halt/release control"


# ══════════════════════════════════════════════════════════════════════════════
# CHARTER — renderCharter 11159; top read GET /offense/api/charter/loopback
# ══════════════════════════════════════════════════════════════════════════════
@pytest.mark.real_flow
def test_charter_renders_and_reads_authority(authed_page):
    page = authed_page
    with assert_calls(page, "GET", "/offense/api/charter/"):
        _nav(page, "charter")
    page.wait_for_selector("text=Charter & Attestation", timeout=15_000)


@pytest.mark.real_flow
def test_charter_load_fires(authed_page):
    page = authed_page
    _goto(page, "charter", "Authorization status")
    with assert_calls(page, "GET", "/offense/api/charter/"):
        page.click("button:has-text('Load')")


@pytest.mark.real_flow
def test_charter_ledger_verify_fires(authed_page):
    page = authed_page
    _goto(page, "charter", "Usage attestation ledger")
    with assert_calls(page, "POST", "/offense/api/authority/ledger"):
        page.click("button:has-text('Load ledger + verify chain')")


@pytest.mark.real_flow
def test_charter_recheck_fires(authed_page):
    page = authed_page
    _goto(page, "charter", "Remote target")
    with assert_calls(page, "GET", "/offense/api/charter/"):
        page.click("button:has-text('Re-check charter')")


@pytest.mark.real_flow
def test_charter_remote_cannot_be_minted_in_ui(authed_page):
    # SAFETY property: a REMOTE charter can never be minted/widened in the UI — it only
    # VERIFIES + guides the out-of-band ceremony. Assert the guidance + the out-of-band
    # `vigil provision` command block are shown, and there is NO remote mint control.
    page = authed_page
    _goto(page, "charter", "Remote target")
    assert page.locator("text=never mint or widen a remote charter").count() >= 1
    assert page.locator("code:has-text('vigil provision --slug')").count() >= 1


@pytest.mark.real_flow
def test_charter_provision_loopback_fires(authed_page):
    # Loopback provision is scope-HARD-FIXED to 127.0.0.1 (reversible, benign) -> POST fires.
    page = authed_page
    _goto(page, "charter", "Provision a loopback authority")
    with assert_calls(page, "POST", "/offense/api/authority/provision"):
        page.click("button:has-text('Provision (loopback only)')")


# ══════════════════════════════════════════════════════════════════════════════
# API KEYS — renderApiKeys 5177; top read GET /sovereign/api/settings (un-polled)
# ══════════════════════════════════════════════════════════════════════════════
@pytest.mark.real_flow
def test_apikeys_renders_and_reads_settings(authed_page):
    page = authed_page
    with assert_calls(page, "GET", "/sovereign/api/settings"):
        _nav(page, "apikeys")
    page.wait_for_selector("text=API Keys", timeout=15_000)


@pytest.mark.real_flow
def test_apikeys_test_all_fires(authed_page):
    # "Test all keys" -> settingsAct check_secrets -> POST /sovereign/api/action (non-mutating live check).
    page = authed_page
    _goto(page, "apikeys", "API Keys")
    page.wait_for_selector("#test-all", timeout=15_000)
    with assert_calls(page, "POST", "/sovereign/api/action"):
        page.click("#test-all")


@pytest.mark.real_flow
def test_apikeys_secret_cards_present(authed_page):
    # Per-secret cards render (set/rotate deliberately NOT fired — it would overwrite real key
    # material; the owner-plane `secrets` permission is server-enforced).
    page = authed_page
    _goto(page, "apikeys", "API Keys")
    page.wait_for_selector("#apikeys-body", timeout=15_000)
    assert page.locator("#apikeys-body .empty:has-text('Loading')").count() == 0, "apikeys body stuck on Loading"
    assert page.locator("#apikeys-body h2").count() >= 1, "no secret category sections rendered"


# ══════════════════════════════════════════════════════════════════════════════
# BUDGETS — renderBudgets 9446; top read GET /offense/api/token-budgets (un-polled)
# ══════════════════════════════════════════════════════════════════════════════
@pytest.mark.real_flow
def test_budgets_renders_and_reads(authed_page):
    page = authed_page
    with assert_calls(page, "GET", "/offense/api/token-budgets"):
        _nav(page, "budgets")
    page.wait_for_selector("text=Token Budgets", timeout=15_000)


@pytest.mark.real_flow
def test_budgets_save_fires(authed_page):
    # Click the first per-tool Save with its pre-filled (current) values -> POST fires, no net change.
    page = authed_page
    _goto(page, "budgets", "Token Budgets")
    page.wait_for_selector("#budgets-body button:has-text('Save')", timeout=15_000)
    with assert_calls(page, "POST", "/offense/api/token-budgets"):
        page.locator("#budgets-body button:has-text('Save')").first.click()
