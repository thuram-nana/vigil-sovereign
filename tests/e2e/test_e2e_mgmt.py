"""E2E — MANAGE cluster (knowledge + accounts + settings).

Screens covered (id -> renderer in packages/vigil-ui/app.js):
    library     renderLibrary      (9709)
    sessions    renderSessions     (9643)
    activity    renderBackground   (3555)
    brain       renderBrain        (7118)
    tools       renderTools        (1328)
    mcp         renderMcp          (6370)
    governance  renderGovernance   (1943)
    compliance  renderCompliance   (11084)
    assurance   renderAssurance    (11373)
    settings    renderSettings     (4550)
    users       renderUsers        (4920)

Discipline (README §7):
  * real_flow   — safe reads / benign owner-plane sets / propose-only plan /
                  read-only integrity verifies. Run FOR REAL against the stack's
                  own read APIs and the MERIDIAN loopback (:19010). No target
                  traffic, no external host.
  * assert_gate — destructive/consent-gated controls (tool install, account
                  revoke, owner-session rotate, the protected-domains safety-floor
                  toggle). NEVER fired: we assert the gate ENGAGES (confirm/prompt
                  dialog or two-step consent reveal) and decline it.

GROUNDING RULE honoured here (helpers.assert_calls WARNING): a network-level
assertion is made ONLY against a nav-driven read that NO setInterval touches.
The GLOBAL process-box poll (app.js startProcessBox:11073, 4s) hits
  * GET /offense/api/runs            (pboxPoll 11049)
  * GET /sovereign/api/snapshot      (pboxApprovalPoll 10960)
  * GET /offense/api/approvals/...   (pboxApprovalPoll 10960)
so those three are NEVER asserted (a background poll would green-wash). That is
why `activity` (renderBackground) carries NO network-call assertion: its only
nav reads ARE /offense/api/runs + /sovereign/api/snapshot (both globally polled),
so it is render-asserted only — see test_activity_renders.
"""
from __future__ import annotations

import pytest

from helpers import assert_calls


# ── render helpers ───────────────────────────────────────────────────────────
def _nav(page, screen_id: str) -> None:
    page.evaluate(f"location.hash = '#/{screen_id}'")


def _assert_rendered(page, text: str, timeout_ms: int = 12_000) -> None:
    """A selector/text that only appears once THIS screen rendered in #screen.

    Scoped to #screen (the content mount, app.js setupShell) so a nav-sidebar
    label can never satisfy it.

    NOTE on the h2-screen-head screens (compliance/assurance): their draw*() now
    redraws into a dedicated child #<screen>-body container instead of re-mounting
    the whole screen node (B2 fix), so the <h2> screen-head PERSISTS after data
    loads. The title-wipe defect (V.mount(body=screen,…); ui.js mount() returns its
    arg) is fixed, and the compliance/assurance tests assert BOTH a stable post-draw
    marker and the persistent <h2>.
    """
    page.wait_for_selector(f"#screen :text('{text}')", timeout=timeout_ms)


def _wait_principal(page, perm: str = "read", timeout_ms: int = 20_000) -> None:
    """Block until the boot whoami resolved and V.setPrincipal ran, so V.can(perm)
    is true.

    V.can() is fail-closed (ui.js:82) — owner-only screens render a stub until the
    principal is known. authed_page returns after domcontentloaded, BEFORE the
    async boot whoami (app.js:11731 loadPrincipal). app.js aliases `V = window.VUI`
    (app.js:10) and ui.js exports can()/principal() on window.VUI, so the engine's
    OWN permission predicate is the deterministic, non-cosmetic ready signal.

    Implemented as a Python-side poll of page.evaluate rather than
    page.wait_for_function: the UI serves a strict CSP (default-src 'self', no
    'unsafe-eval'), so wait_for_function's predicate polling trips a CSP eval
    violation, whereas page.evaluate (the same call the login handshake uses) is
    exempt.

    HARNESS NUANCE (test fix, NOT a product defect): authed_page reaches
    '/#/home' via goto('/') then goto('/#/home'). The second goto only adds a
    hash to the SAME path, so the browser treats it as in-page nav and does NOT
    re-run boot(); the principal in effect is the one the FIRST (pre-login,
    tokenless) boot set — i.e. null (its whoami 401'd). A real logged-in user's
    browser boots WITH the session, so loadPrincipal sets the principal. We
    reproduce that faithfully with one reload (sessionStorage — the seeded bearer
    — survives a same-origin reload), after which boot's loadPrincipal runs with
    the token and V.setPrincipal fires. The login-gate path sets the principal
    directly; the API-seed path the harness uses does not, hence this reload.
    """
    probe = ("(p) => !!(window.VUI && typeof window.VUI.can === 'function' "
             "&& window.VUI.can(p))")
    if page.evaluate(probe, perm):
        return
    page.reload(wait_until="domcontentloaded")
    waited = 0
    while waited < timeout_ms:
        if page.evaluate(probe, perm):
            return
        page.wait_for_timeout(250)
        waited += 250
    raise AssertionError(
        f"principal never loaded (V.can({perm!r}) stayed false after {timeout_ms}ms)"
    )


class _Gate:
    """Record dialog(s) and matching backend request(s) while a gated control is
    clicked, and auto-DECLINE every dialog so the action is never performed.

    Playwright auto-dismisses dialogs when a handler is attached that dismisses,
    and even with NO handler its default is to dismiss — so a confirm()-gated
    destructive action cannot fire here. We attach our own handler purely to
    PROVE the gate engaged (a dialog was demanded).
    """

    def __init__(self, page, req_method: str, req_substr: str):
        self.page = page
        self.req_method = req_method.upper()
        self.req_substr = req_substr
        self.dialogs: list[str] = []
        self.requests: list[str] = []

    def _on_dialog(self, dialog):
        self.dialogs.append(f"{dialog.type}:{dialog.message}")
        dialog.dismiss()

    def _on_request(self, request):
        if request.method.upper() == self.req_method and self.req_substr in request.url:
            self.requests.append(request.url)

    def __enter__(self):
        self.page.on("dialog", self._on_dialog)
        self.page.on("request", self._on_request)
        return self

    def __exit__(self, *exc):
        # Give a blocked handler a beat to (not) fire its request, then detach.
        self.page.wait_for_timeout(1200)
        self.page.remove_listener("dialog", self._on_dialog)
        self.page.remove_listener("request", self._on_request)
        return False


# ══════════════════════════════════════════════════════════════════════════════
# LIBRARY — renderLibrary (9709). Top read: GET /offense/api/engagements (9730,
# loadLibrary). Not polled.
# ══════════════════════════════════════════════════════════════════════════════
@pytest.mark.real_flow
def test_library_list_renders(authed_page):
    page = authed_page
    with assert_calls(page, "GET", "/offense/api/engagements"):
        _nav(page, "library")
    _assert_rendered(page, "Engagement Library")


# ══════════════════════════════════════════════════════════════════════════════
# SESSIONS — renderSessions (9643). Top read: GET /offense/api/sessions (9540,
# loadSessions). Not polled. Control: "New session" -> window.prompt gate.
# ══════════════════════════════════════════════════════════════════════════════
@pytest.mark.real_flow
def test_sessions_list_renders(authed_page):
    page = authed_page
    with assert_calls(page, "GET", "/offense/api/sessions"):
        _nav(page, "sessions")
    _assert_rendered(page, "Sessions")


@pytest.mark.assert_gate
def test_sessions_new_session_prompt_gate(authed_page):
    """createSession (9612) opens window.prompt BEFORE any POST; cancel -> no
    POST /offense/api/session/create. We decline the prompt (no session minted)."""
    page = authed_page
    _nav(page, "sessions")
    _assert_rendered(page, "Sessions")
    with _Gate(page, "POST", "/offense/api/session/create") as g:
        page.click("#screen button:has-text('New session')")
    assert g.dialogs, "New session fired no prompt dialog — the create gate did not engage"
    assert not g.requests, f"session/create POSTed despite a declined prompt: {g.requests}"


# ══════════════════════════════════════════════════════════════════════════════
# ACTIVITY — renderBackground (3555). Its ONLY nav reads are GET /offense/api/runs
# (pollRuns) and GET /sovereign/api/snapshot (pollSnap) — BOTH globally polled
# (startProcessBox 11073). A network-level assertion would be green-washed by a
# background poll, so per the harness WARNING we assert RENDER only. Documented
# as a residual, not a defect.
# ══════════════════════════════════════════════════════════════════════════════
@pytest.mark.real_flow
def test_activity_renders(authed_page):
    page = authed_page
    _nav(page, "activity")
    _assert_rendered(page, "Activity")
    # The dual-plane status card is the screen-specific render signal.
    page.wait_for_selector("#bg-status", timeout=12_000)


# ══════════════════════════════════════════════════════════════════════════════
# BRAIN — renderBrain (7118). Default tab "decide" -> brainDecision (7351):
# GET /offense/api/brain/decision. Not polled. Control: "Propose chain
# (plan-only)" -> POST /offense/api/brain/propose (propose-only: persists a plan,
# sends NO target traffic, mints NO findings — brainControls 7240).
# ══════════════════════════════════════════════════════════════════════════════
@pytest.mark.real_flow
def test_brain_decision_renders(authed_page):
    page = authed_page
    with assert_calls(page, "GET", "/offense/api/brain/decision"):
        _nav(page, "brain")
    _assert_rendered(page, "Brain")


@pytest.mark.real_flow
def test_brain_run_benchmark_fires_post(authed_page):
    """REGROUNDED (test fix, not a product defect): the cluster brief's brain POST
    was "Propose chain / Run benchmark". The propose-only brain is UNAVAILABLE on
    this host — GET /offense/api/brain/decision returns brain.objectives == [] and
    brain.name == None, so the panel honestly shows "brain source unavailable" /
    "No live proposal wired". Clicking "Propose chain" then hits the client guard
    `if (objs.length === 0) return` (brainControls 7240) and fires NO POST — there
    is nothing to assert. So we ground the brain POST on the Benchmark tab's "Run
    benchmark now" -> POST /offense/api/benchmark/run (runBenchmark 7450): a
    self-contained, loopback-only soundness run (no target, no scope, no egress —
    the same check make-gate runs). We assert ONLY that the POST fires; we do not
    await the (minutes-long) result."""
    page = authed_page
    _nav(page, "brain?tab=benchmark")
    page.wait_for_selector("#screen button:has-text('Run benchmark now')", timeout=20_000)
    with assert_calls(page, "POST", "/offense/api/benchmark/run"):
        page.click("#screen button:has-text('Run benchmark now')")


# ══════════════════════════════════════════════════════════════════════════════
# TOOLS — renderTools (1328). Top reads: GET /offense/api/tools + GET
# /offense/api/toolprofiles (1336-1341). Neither polled. Control: "Install" ->
# TWO-STEP consent (drawToolProfiles ~1272): 1st click POSTs {name} (no consent)
# -> server returns needs_consent + the exact command (reveals a "Run it" button);
# only the 2nd "Run it" click POSTs {name, consent:true} and actually installs.
# assert_gate: fire ONLY the consent-check, assert the reveal, NEVER click Run it.
# ══════════════════════════════════════════════════════════════════════════════
@pytest.mark.real_flow
def test_tools_catalogue_renders(authed_page):
    page = authed_page
    with assert_calls(page, "GET", "/offense/api/tools"):
        _nav(page, "tools")
    _assert_rendered(page, "Tools")
    # #tools-summary tiles are driven by /api/tools (the asserted read); wait for
    # the live probe to populate the "Installed" tile label.
    page.wait_for_selector("#tools-summary :text('Installed')", timeout=30_000)


@pytest.mark.assert_gate
def test_tools_install_consent_gate(authed_page):
    page = authed_page
    _nav(page, "tools")
    _assert_rendered(page, "Tools")
    # tool-consciousness is driven by the slow /api/toolprofiles live probe.
    install = page.locator("#tool-consciousness button:has-text('Install')")
    install.first.wait_for(state="visible", timeout=45_000)
    assert install.count() > 0, "no installable tool offered — cannot exercise the consent gate"
    # First click = the consent CHECK (no consent flag): it POSTs but the server
    # returns needs_consent and the UI reveals the exact command + a "Run it"
    # button. That reveal IS the gate. We never click "Run it".
    with assert_calls(page, "POST", "/offense/api/tools/install"):
        install.first.click()
    # The consent-check POST does a live apt dry-run (~11s) before responding with
    # needs_consent + the exact command, which is when "Run it" is revealed.
    page.wait_for_selector("#tool-consciousness button:has-text('Run it')", timeout=30_000)
    # Prove the destructive second step is present but LEFT UNFIRED.
    assert page.locator("#tool-consciousness button:has-text('Run it')").count() > 0


# ══════════════════════════════════════════════════════════════════════════════
# MCP — renderMcp (6370). Top read: GET /offense/api/mcp (6376). Not polled.
# Read-only screen (no mutating controls).
# ══════════════════════════════════════════════════════════════════════════════
@pytest.mark.real_flow
def test_mcp_renders(authed_page):
    page = authed_page
    with assert_calls(page, "GET", "/offense/api/mcp"):
        _nav(page, "mcp")
    _assert_rendered(page, "MCP Servers")


# ══════════════════════════════════════════════════════════════════════════════
# GOVERNANCE — renderGovernance (1943). Top read: GET /offense/api/governance
# (1951). Not polled. Read-only audit (cannot provision/authorize/fire anything).
# ══════════════════════════════════════════════════════════════════════════════
@pytest.mark.real_flow
def test_governance_renders(authed_page):
    page = authed_page
    with assert_calls(page, "GET", "/offense/api/governance"):
        _nav(page, "governance")
    _assert_rendered(page, "Governance")


# ══════════════════════════════════════════════════════════════════════════════
# COMPLIANCE — renderCompliance (11084). Reads runsURL() first (GET
# /offense/api/runs — GLOBALLY POLLED, NOT asserted), then loadCompliance ->
# GET /offense/api/compliance/<run> (11099). The compliance read is NOT polled
# and fires on nav whenever a run exists (runs present on this host), so it is
# the sound nav-driven assertion.
# ══════════════════════════════════════════════════════════════════════════════
@pytest.mark.real_flow
def test_compliance_renders(authed_page):
    page = authed_page
    with assert_calls(page, "GET", "/offense/api/compliance/"):
        _nav(page, "compliance")
    # Stable post-draw marker (proves the async draw ran).
    _assert_rendered(page, "standards controls")
    # FIXED (B2): drawCompliance now redraws into #compliance-body, so the <h2>
    # screen-head PERSISTS after the data load (it used to be wiped).
    assert page.locator("#screen h2:has-text('Compliance & ATT&CK')").count() == 1, \
        "the <h2> 'Compliance & ATT&CK' screen-head did not persist after the async draw (B2 regressed)"


# ══════════════════════════════════════════════════════════════════════════════
# ASSURANCE — renderAssurance (11373). Top reads: GET /offense/api/telemetry
# (11381, NOT polled) + runsURL() (polled, not asserted). Controls (integrity
# card ~11465): "Verify integrity/ledger/spine" -> POST /offense/api/verify;
# "Verify sovereign spine" -> GET /sovereign/api/verify. All read-only re-fires
# of retained certificates (no target traffic) => real_flow.
# ══════════════════════════════════════════════════════════════════════════════
@pytest.mark.real_flow
def test_assurance_renders(authed_page):
    page = authed_page
    with assert_calls(page, "GET", "/offense/api/telemetry"):
        _nav(page, "assurance")
    # Stable post-draw marker (proves the async draw ran).
    _assert_rendered(page, "Integrity & verify")
    # FIXED (B2): drawAssurance now redraws into #assurance-body, so the <h2>
    # screen-head PERSISTS after the data load (it used to be wiped).
    assert page.locator("#screen h2:has-text('continuous proof')").count() == 1, \
        "the <h2> 'Assurance …' screen-head did not persist after the async draw (B2 regressed)"


@pytest.mark.real_flow
def test_assurance_verify_integrity_fires(authed_page):
    page = authed_page
    _nav(page, "assurance")
    page.wait_for_selector("#screen :text('Integrity & verify')", timeout=12_000)
    with assert_calls(page, "POST", "/offense/api/verify"):
        page.click("#screen button:has-text('Verify integrity')")


@pytest.mark.real_flow
def test_assurance_verify_sovereign_spine_fires(authed_page):
    """Grounding correction: the sovereign-spine verify is a GET /sovereign/api/
    verify (drawAssurance showVerify -> V.getJSON(SOV('/api/verify'))), NOT a POST
    as the cluster brief phrased it. Asserted as the actual GET it fires."""
    page = authed_page
    _nav(page, "assurance")
    page.wait_for_selector("#screen :text('Integrity & verify')", timeout=12_000)
    with assert_calls(page, "GET", "/sovereign/api/verify"):
        page.click("#screen button:has-text('Verify sovereign spine')")


# ══════════════════════════════════════════════════════════════════════════════
# SETTINGS — renderSettings (4550). Top read: GET /sovereign/api/settings (4575,
# loadSettings). Not polled. Controls: "Apply effort" -> POST /sovereign/api/
# action {set_effort} (benign, re-applies the current/default value — nothing
# dangerous). The VIGIL_ALLOW_PROTECTED_DOMAINS safety-floor toggle -> assert_gate.
# ══════════════════════════════════════════════════════════════════════════════
@pytest.mark.real_flow
def test_settings_renders(authed_page):
    page = authed_page
    with assert_calls(page, "GET", "/sovereign/api/settings"):
        _nav(page, "settings")
    _assert_rendered(page, "Settings")


@pytest.mark.real_flow
def test_settings_apply_effort_fires_benign_set(authed_page):
    """set_effort with the select left at its loaded value (selected_effort is
    None on this host => "Model default", value="") is a no-op set: the POST
    fires but nothing material changes."""
    page = authed_page
    _nav(page, "settings")
    page.wait_for_selector("#screen button:has-text('Apply effort')", timeout=12_000)
    with assert_calls(page, "POST", "/sovereign/api/action"):
        page.click("#screen button:has-text('Apply effort')")


@pytest.mark.assert_gate
def test_settings_protected_domains_danger_surface(authed_page):
    """drawConfigCard (4593) renders the VIGIL_ALLOW_PROTECTED_DOMAINS toggle with
    a DANGER warn banner (f.warn). The categorical-safety-floor disable must stay
    UNFIRED: we assert the env + its danger warning render and do NOT click Save.

    NOTE (recorded): this field has NO client-side confirm() — clicking Save POSTs
    set_config immediately (settingsAct 4526). The only client gate is the visible
    danger banner; the authoritative gate is server-side owner-signing. See the
    agent report's DEFECT/residual notes.
    """
    page = authed_page
    _nav(page, "settings")
    page.wait_for_selector("#screen :text('VIGIL_ALLOW_PROTECTED_DOMAINS')", timeout=12_000)
    # the danger banner copy from the config field's f.warn
    page.wait_for_selector("#screen :text('DANGER')", timeout=12_000)


# ══════════════════════════════════════════════════════════════════════════════
# USERS — renderUsers (4920). Owner-gated (V.can manage_users). Top read:
# GET /sovereign/api/accounts (loadUsers 5071). Not polled. Controls:
#   * "Create account" (usersCreateForm 5017) — refuses with no POST when the
#     username is empty (required-field gate).
#   * "Revoke all" (loadUsers 5079) — window.confirm gate; decline -> no POST.
#   * "Rotate session" (ownerSessionCard 4955) — window.confirm gate; decline ->
#     no POST.
# All assert_gate: no account is created/revoked, no session rotated.
# ══════════════════════════════════════════════════════════════════════════════
@pytest.mark.real_flow
def test_users_list_renders(authed_page):
    page = authed_page
    _wait_principal(page)  # manage_users is fail-closed until whoami resolves
    with assert_calls(page, "GET", "/sovereign/api/accounts"):
        _nav(page, "users")
    _assert_rendered(page, "Users & Roles")


@pytest.mark.assert_gate
def test_users_create_requires_username(authed_page):
    """Create with an empty username hits the required-field guard (usersCreateForm
    5020-5021) and returns BEFORE any POST /sovereign/api/action {create_account}."""
    page = authed_page
    _wait_principal(page)  # manage_users is fail-closed until whoami resolves
    _nav(page, "users")
    _assert_rendered(page, "Users & Roles")
    page.wait_for_selector("#screen button:has-text('Create account')", timeout=12_000)
    with _Gate(page, "POST", "/sovereign/api/action") as g:
        page.click("#screen button:has-text('Create account')")
    assert not g.requests, f"create_account POSTed with an empty username: {g.requests}"


@pytest.mark.assert_gate
def test_users_revoke_all_confirm_gate(authed_page):
    """Bulk "Revoke all" (loadUsers 5079) demands window.confirm; we decline it so
    no teammate account is revoked (no POST {revoke_all_teammates})."""
    page = authed_page
    _wait_principal(page)  # manage_users is fail-closed until whoami resolves
    _nav(page, "users")
    _assert_rendered(page, "Users & Roles")
    btn = page.locator("#screen button:has-text('Revoke all')")
    btn.first.wait_for(state="visible", timeout=12_000)
    with _Gate(page, "POST", "/sovereign/api/action") as g:
        btn.first.click()
    assert g.dialogs, "Revoke all fired no confirm dialog — the destructive gate did not engage"
    assert not g.requests, f"a revoke action POSTed despite a declined confirm: {g.requests}"


@pytest.mark.assert_gate
def test_users_rotate_session_confirm_gate(authed_page):
    """"Rotate session" (ownerSessionCard 4956) demands window.confirm; declining
    it leaves the owner token unchanged (no POST {rotate_bootstrap_token})."""
    page = authed_page
    _wait_principal(page)  # manage_users is fail-closed until whoami resolves
    _nav(page, "users")
    _assert_rendered(page, "Users & Roles")
    btn = page.locator("#screen button:has-text('Rotate session')")
    btn.first.wait_for(state="visible", timeout=12_000)
    with _Gate(page, "POST", "/sovereign/api/action") as g:
        btn.first.click()
    assert g.dialogs, "Rotate session fired no confirm dialog — the gate did not engage"
    assert not g.requests, f"rotate POSTed despite a declined confirm: {g.requests}"
