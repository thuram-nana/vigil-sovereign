"""E2E — cluster LEARN + global shell (KEY=learn-shell).

Browser-client coverage of the LEARN screens (Trust Center, Proof of Posture,
Manual, Knowledge Engine) plus the GLOBAL SHELL that is persistent across every
screen (login gate, plane toggle + scope chip, command palette, Start/Stop
offense-plane chip, user-chip logout, SIGIL HUD SSE).

Grounding (read, not guessed) against packages/vigil-ui/app.js:
  renderTrust 1352 · renderPosture 1568 · renderManual 1093 · renderKnowledge 9809
  NAV/topbar 107 · renderLoginGate 333 · offenseChip 492 · openPalette 982
  startSigilHud 10366 · boot 11711

Discipline (README §7 / conftest markers):
  real_flow   -- safe reads / offline re-verifications fired FOR REAL against the
                 stack's own read APIs (loopback). No third party, no production.
  assert_gate -- a control that must NOT actually execute (destructive / egress /
                 persistent-daemon / plane-stop). The test proves the control is
                 WIRED to the correct backend route at the network layer, but the
                 request is either BLOCKED by a client confirm() gate (dismissed)
                 or INTERCEPTED (route.abort) so the server never performs it.

The intercept technique: Playwright's request event (and assert_calls'
page.expect_request) fires when the browser ISSUES the request, before routing
resolves. Aborting in the route handler therefore still lets assert_calls prove
"button -> correct backend route" while guaranteeing the action never runs. This
is used for host-ops subprocess launches, vuln-feed egress, the recurring feed
daemon, a local git commit, and the posture attest scan — all real side effects
that a QA pass must not trigger on the operator's live stack.
"""
from __future__ import annotations

import contextlib

import pytest

from helpers import assert_calls


# ── grounded backend routes ───────────────────────────────────────────────────
CERTS = "/offense/api/certs"
VERIFY_CERT = "/offense/api/verify-cert"
AR_FLOOR = "/sovereign/api/antirollback/floor"
POSTURE = "/offense/api/posture"
POSTURE_ATTEST = "/offense/api/posture/attest"
POSTURE_VERIFY = "/offense/api/posture/verify"
ENGAGEMENTS = "/offense/api/engagements"
HOSTCMD_RUNS = "/sovereign/api/hostcmd/runs"
HOSTCMD = "/sovereign/api/hostcmd/"           # + <verb>
GITSYNC = "/offense/api/knowledge/gitsync"
FEED = "/offense/api/feed/"                    # + <slug>/<verb>
LOGIN = "/sovereign/api/login"
LOGOUT = "/sovereign/api/logout"
SIGIL_HUD = "/sovereign/api/sigil/hud"


def _nav(page, screen_id: str) -> None:
    """Hash-route to a screen exactly as voice/click nav does (location.hash)."""
    page.evaluate(f"location.hash='#/{screen_id}'")


@contextlib.contextmanager
def intercepted(page, url_glob: str):
    """Abort every request matching url_glob for the block's duration.

    The browser STILL issues the request (assert_calls sees it at the network
    layer) but it never reaches the server. For controls that are wired to a real
    DESTRUCTIVE / EGRESS / PERSISTENT-DAEMON action we must never perform on the
    operator's live stack.
    """
    page.route(url_glob, lambda route: route.abort())
    try:
        yield
    finally:
        page.unroute(url_glob)


# ════════════════════════════════════════════════════════════════════════════
# GLOBAL SHELL
# ════════════════════════════════════════════════════════════════════════════

@pytest.mark.real_flow
def test_login_gate_shown_when_unauthenticated(page, base_url):
    """An UNAUTH page (no session token) boots straight into the login gate.

    Uses the raw `page` (NOT authed_page): the uiproxy blanks the relayed
    data-token, so whoami is unauthenticated and boot() -> renderLoginGate.
    """
    page.goto(base_url + "/", wait_until="domcontentloaded")
    # the bearer sign-in gate (app.js renderLoginGate:333) — its own heading +
    # the bearer token field + the Sign in button.
    page.wait_for_selector("h1:has-text('Sign in to VIGIL')", timeout=15000)
    assert page.locator("input[placeholder='Paste your VIGIL bearer token']").count() == 1
    assert page.locator("button:has-text('Sign in')").count() >= 1
    # and the authed shell is NOT present (no user chip visible)
    assert page.locator("button.user-chip").count() == 0


@pytest.mark.real_flow
def test_plane_toggle_filters_nav(authed_page):
    """The plane segmented toggle (topbar:151) filters the sidebar NAV.

    offense -> assess/live/findings/fixes shown, defense hidden.
    defense -> those hidden, defense shown.  all -> everything shown.
    This is the toggle's real, observable effect (renderNav plane filter).
    """
    page = authed_page
    page.wait_for_selector("#nav [data-nav='assess']", timeout=15000)
    # baseline: plane 'all' shows both an offense-only item and defense
    assert page.locator("#nav [data-nav='assess']").count() == 1
    assert page.locator("#nav [data-nav='defense']").count() == 1

    page.click(".segmented button[data-plane='defense']")
    page.wait_for_selector("#nav [data-nav='assess']", state="detached", timeout=5000)
    assert page.locator("#nav [data-nav='assess']").count() == 0      # offense items filtered out
    assert page.locator("#nav [data-nav='defense']").count() == 1     # defense remains

    page.click(".segmented button[data-plane='offense']")
    page.wait_for_selector("#nav [data-nav='assess']", timeout=5000)
    assert page.locator("#nav [data-nav='assess']").count() == 1
    assert page.locator("#nav [data-nav='defense']").count() == 0

    page.click(".segmented button[data-plane='all']")
    page.wait_for_selector("#nav [data-nav='defense']", timeout=5000)
    assert page.locator("#nav [data-nav='assess']").count() == 1
    assert page.locator("#nav [data-nav='defense']").count() == 1


@pytest.mark.real_flow
def test_plane_toggle_highlight_updates_on_click(authed_page):
    """FIXED: the segmented plane toggle re-highlights the active plane on click.

    topbar() marks the `.on` class from app.get().plane at render time; the onClick
    now does `app.set({plane}); refreshTopbar()` (app.js:154) — refreshTopbar()
    rebuilds the topbar (so the clicked button gains `.on`) AND calls renderNav() (so
    the nav filter still updates). Previously the onClick called only renderNav() and
    never refreshed the topbar, leaving `.on` stuck on the original 'all' button — a
    cosmetic defect, now fixed. (Renamed from
    test_plane_toggle_highlight_is_stale_DEFECT: it now proves the fix.)
    """
    page = authed_page
    page.wait_for_selector(".segmented button[data-plane='defense']", timeout=15000)
    page.click(".segmented button[data-plane='defense']")
    # nav filter still applies (refreshTopbar -> renderNav): the offense 'assess' item is filtered out.
    page.wait_for_selector("#nav [data-nav='assess']", state="detached", timeout=5000)
    # the highlight MOVED: the clicked 'defense' button now carries `.on`, and the
    # original 'all' no longer does.
    page.wait_for_selector(".segmented button[data-plane='defense'].on", timeout=5000)
    defense_on = page.locator(".segmented button[data-plane='defense'].on").count()
    all_on = page.locator(".segmented button[data-plane='all'].on").count()
    assert defense_on == 1, "the clicked 'defense' plane button should gain `.on` after refreshTopbar()"
    assert all_on == 0, "the stale highlight should have left the original 'all' button"


@pytest.mark.real_flow
def test_scope_chip_navigates_to_library(authed_page):
    """The scope chip (topbar:151) navigates to the Engagement Library, whose
    top-of-render read is GET /offense/api/engagements."""
    page = authed_page
    page.wait_for_selector(".scope-chip", timeout=15000)
    with assert_calls(page, "GET", ENGAGEMENTS):
        page.click(".scope-chip")
    page.wait_for_selector("h1:has-text('Engagement Library')", timeout=10000)


@pytest.mark.real_flow
def test_command_palette_opens_and_runs(authed_page):
    """The command palette (openPalette:982) opens as an overlay and runs a
    screen entry; running 'Trust Center' navigates there and fires its real
    top-of-render read GET /offense/api/certs."""
    page = authed_page
    page.wait_for_selector(".cmdk", timeout=15000)
    page.click(".cmdk")
    page.wait_for_selector(".pal-box .pal-input", timeout=5000)   # overlay rendered
    page.fill(".pal-input", "Trust Center")
    page.wait_for_selector(".pal-row", timeout=5000)
    with assert_calls(page, "GET", CERTS):
        page.press(".pal-input", "Enter")
    page.wait_for_selector("h1:has-text('Trust Center')", timeout=10000)
    assert page.locator(".pal-box").count() == 0, "palette should close after running an entry"


@pytest.mark.real_flow
def test_offense_chip_reflects_up_state(authed_page):
    """The offense-plane chip (offenseChip:492) reflects the LIVE 'up' state.

    The stack is live, so watchOffensePlane -> /__vigil/plane/status reports
    running and the chip shows 'Offense up' (plus a Stop control). The chip is
    display:none until the first probe resolves, so wait for it to populate.

    Reload first: the authed_page fixture reaches #/home via a same-document hash
    change, which does NOT re-run boot()/watchOffensePlane with the now-seeded
    session token, so the plane probe would run token-less (canStart=false, no
    Stop). A real reload re-boots with the token. (Harness grounding, not a
    product defect — see report.)
    """
    page = authed_page
    page.reload(wait_until="domcontentloaded")
    page.wait_for_selector("#offense-chip .txt", timeout=20000)
    txt = page.locator("#offense-chip .txt").inner_text()
    assert "Offense up" in txt, f"expected the chip to show 'Offense up', got {txt!r}"
    # the Stop control is present (the proxy can start/stop this plane)
    assert page.locator("#offense-chip .oc-stop").count() == 1


@pytest.mark.assert_gate
def test_offense_stop_demands_confirm_and_is_declined(authed_page):
    """Stopping the offense plane is gated by a window.confirm (confirmStopOffense).

    ASSERT GATE: the confirm dialog is DEMANDED and we DISMISS it, so
    stopOffensePlane() never runs and POST /__vigil/plane/offense/stop never
    fires. The operator's own plane is left untouched.
    """
    page = authed_page
    dialogs = []
    stop_posts = []
    page.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))
    page.on("request", lambda r: stop_posts.append(r.url)
            if (r.method == "POST" and "/plane/offense/stop" in r.url) else None)

    page.reload(wait_until="domcontentloaded")   # re-boot with the seeded token so canStart=true -> Stop shows
    page.wait_for_selector("#offense-chip .oc-stop", timeout=20000)
    page.click("#offense-chip .oc-stop")
    page.wait_for_timeout(1000)

    assert dialogs, "expected a confirm() gate before stopping the offense plane"
    assert "Stop the offense side?" in dialogs[0]
    assert not stop_posts, "the stop POST must NOT fire once the confirm is dismissed"


@pytest.mark.real_flow
def test_logout_fires_and_clears_session(authed_page):
    """The user-chip Account -> Sign out (logout:) POSTs /sovereign/api/logout and
    then clears the session, landing back on the login gate.

    Self-contained: authed_page is function-scoped, so logging this page out does
    not affect other tests.

    Reload first so boot() re-runs loadPrincipal() with the seeded token and the
    authenticated user-chip renders (the fixture's hash-only nav does not re-boot
    — harness grounding, not a product defect).
    """
    page = authed_page
    page.reload(wait_until="domcontentloaded")
    page.wait_for_selector("button.user-chip", timeout=15000)
    page.click("button.user-chip")                       # opens the Account drawer
    page.wait_for_selector("button:has-text('Sign out')", timeout=5000)
    with assert_calls(page, "POST", LOGOUT):
        page.click("button:has-text('Sign out')")
    # session cleared -> login gate re-renders
    page.wait_for_selector("h1:has-text('Sign in to VIGIL')", timeout=10000)
    assert page.locator("button.user-chip").count() == 0


@pytest.mark.real_flow
def test_sigil_hud_sse_connects(authed_page):
    """The persistent SIGIL HUD channel (startSigilHud:10366) opens an
    EventSource GET /sovereign/api/sigil/hud at boot.

    Reloading the page re-runs boot() -> startSigilHud(), so the SSE GET fires
    again and can be observed at the network layer.
    """
    page = authed_page
    with assert_calls(page, "GET", SIGIL_HUD, timeout_ms=20000):
        page.reload(wait_until="domcontentloaded")


# ════════════════════════════════════════════════════════════════════════════
# LEARN — Trust Center  (renderTrust:1352)
# ════════════════════════════════════════════════════════════════════════════

@pytest.mark.real_flow
def test_trust_renders_and_reads_certs(authed_page):
    """Top-of-render read: GET /offense/api/certs; the Trust Center heading +
    a certificate card render."""
    page = authed_page
    with assert_calls(page, "GET", CERTS):
        _nav(page, "trust")
    page.wait_for_selector("h1:has-text('Trust Center')", timeout=10000)
    # live grounding confirmed a present cert — its card must render with Verify.
    page.wait_for_selector("button:has-text('Verify offline')", timeout=10000)


@pytest.mark.real_flow
def test_trust_verify_cert(authed_page):
    """The 'Verify offline' control (doVerifyCert) fires POST /offense/api/verify-cert.

    Read-only / offline re-verification of a signed certificate — safe to run for
    real. Asserts the backend call fires AND a PASS/FAIL verdict renders.
    """
    page = authed_page
    _nav(page, "trust")
    page.wait_for_selector("button:has-text('Verify offline')", timeout=15000)
    with assert_calls(page, "POST", VERIFY_CERT):
        page.locator("button:has-text('Verify offline')").first.click()
    # a verdict row renders (PASS re-verified offline, or FAIL did not verify)
    page.wait_for_selector("text=/re-verified offline|did not verify|Verify error/", timeout=10000)


@pytest.mark.real_flow
def test_trust_antirollback_refresh(authed_page):
    """The anti-rollback card's Refresh re-renders Trust, re-reading the sovereign
    anti-rollback floor status GET /sovereign/api/antirollback/floor (read-only
    metadata; the reset/rotate mutations stay CLI-only)."""
    page = authed_page
    _nav(page, "trust")
    page.wait_for_selector("h3:has-text('Anti-rollback status')", timeout=15000)
    with assert_calls(page, "GET", AR_FLOOR):
        # the Refresh button inside the anti-rollback card
        page.locator("button:has-text('Refresh')").first.click()


# ════════════════════════════════════════════════════════════════════════════
# LEARN — Proof of Posture  (renderPosture:1568)
# ════════════════════════════════════════════════════════════════════════════

@pytest.mark.real_flow
def test_posture_renders_and_reads(authed_page):
    """Top-of-render read: loadPosture() -> GET /offense/api/posture; heading +
    the Attest & verify card render. (Live grounding: no posture attested yet,
    so the body shows the honest empty state — not fabricated.)"""
    page = authed_page
    with assert_calls(page, "GET", POSTURE):
        _nav(page, "posture")
    page.wait_for_selector("h1:has-text('Proof of Posture')", timeout=10000)
    page.wait_for_selector("h3:has-text('Attest & verify')", timeout=10000)


@pytest.mark.real_flow
def test_posture_refresh(authed_page):
    """The Refresh control re-reads GET /offense/api/posture."""
    page = authed_page
    _nav(page, "posture")
    page.wait_for_selector("h1:has-text('Proof of Posture')", timeout=15000)
    with assert_calls(page, "GET", POSTURE):
        page.locator("button:has-text('Refresh')").first.click()


@pytest.mark.real_flow
def test_posture_verify_bundle(authed_page):
    """The 'Verify bundle' control fires POST /offense/api/posture/verify.

    A fast offline re-run of a bundle's own verifier — safe to run for real. The
    default bundle name may not exist (no posture attested yet), so the verdict is
    'NOT verified', but the backend call provably fires (the wiring under test).
    """
    page = authed_page
    _nav(page, "posture")
    page.wait_for_selector("button:has-text('Verify bundle')", timeout=15000)
    with assert_calls(page, "POST", POSTURE_VERIFY):
        page.click("button:has-text('Verify bundle')")


@pytest.mark.assert_gate
def test_posture_attest_wiring_not_executed(authed_page):
    """The 'Attest new certificate' control is wired to POST /offense/api/posture/attest.

    Attest kicks off a ~1-2 min live coverage SCAN on the server (a real,
    long-running side effect). ASSERT GATE: prove the button targets the correct
    route, but INTERCEPT the request so no scan is launched on the live stack.
    """
    page = authed_page
    _nav(page, "posture")
    page.wait_for_selector("button:has-text('Attest new certificate')", timeout=15000)
    with intercepted(page, "**/api/posture/attest"):
        with assert_calls(page, "POST", POSTURE_ATTEST):
            page.click("button:has-text('Attest new certificate')")


# ════════════════════════════════════════════════════════════════════════════
# LEARN — Manual  (renderManual:1093)  — STATIC, no backend
# ════════════════════════════════════════════════════════════════════════════

@pytest.mark.real_flow
def test_manual_renders_static_content(authed_page):
    """The Manual is in-app documentation rendered from window.VIGIL_MANUAL — no
    runtime backend call (grounded: renderManual uses no fetch). Assert it renders
    real, non-empty content: the heading, a non-empty table of contents, and at
    least one section card."""
    page = authed_page
    _nav(page, "manual")
    page.wait_for_selector("h1:has-text('Manual')", timeout=10000)
    # the content is driven by a real, non-empty manual dataset
    man_len = page.evaluate("(window.VIGIL_MANUAL || []).length")
    assert man_len and man_len > 0, "VIGIL_MANUAL must carry real documentation sections"
    page.wait_for_selector(".man-toc .nav-item", timeout=5000)
    assert page.locator(".man-toc .nav-item").count() == man_len
    assert page.locator("#man-" + str(page.evaluate("window.VIGIL_MANUAL[0].id"))).count() == 1


# ════════════════════════════════════════════════════════════════════════════
# LEARN — Knowledge Engine  (renderKnowledge:9809)
# ════════════════════════════════════════════════════════════════════════════

@pytest.mark.real_flow
def test_knowledge_renders_and_reads_engagements(authed_page):
    """Top-of-render read: loadKnowledge() -> GET /offense/api/engagements; the
    heading + the memory host-operations card render."""
    page = authed_page
    with assert_calls(page, "GET", ENGAGEMENTS):
        _nav(page, "knowledge")
    page.wait_for_selector("h1:has-text('Knowledge Engine')", timeout=10000)
    page.wait_for_selector("h3:has-text('Memory host operations')", timeout=10000)


@pytest.mark.real_flow
def test_knowledge_hostops_runs_read(authed_page):
    """The host-ops card Refresh reads GET /sovereign/api/hostcmd/runs (viewer+
    read of tracked background host-op runs)."""
    page = authed_page
    _nav(page, "knowledge")
    page.wait_for_selector("h3:has-text('Memory host operations')", timeout=15000)
    with assert_calls(page, "GET", HOSTCMD_RUNS):
        # the Refresh button inside the host-ops card header
        page.locator("h3:has-text('Memory host operations')") \
            .locator("xpath=ancestor::*[contains(@class,'card')][1]") \
            .locator("button:has-text('Refresh')").click()


@pytest.mark.assert_gate
@pytest.mark.parametrize("label,verb", [
    ("Rebuild vector index", "index"),
    ("Rebuild memory", "ingest"),
    ("Consolidate (dry-run)", "consolidate"),
])
def test_knowledge_hostops_launch_wiring_not_executed(authed_page, label, verb):
    """The host-op launch buttons are wired to POST /sovereign/api/hostcmd/<verb>.

    Each launches a REAL tracked background host subprocess (index/ingest rebuild,
    consolidation). 'Rebuild memory' (ingest) — which can carry a destructive
    --reset flag — is now additionally gated by a client-side window.confirm (B4),
    which we ACCEPT here so the underlying POST wiring is still proven; the other
    two carry no client confirm. ASSERT GATE either way: INTERCEPT the route so no
    host subprocess is spawned on the live stack.
    """
    page = authed_page
    _nav(page, "knowledge")
    page.wait_for_selector(f"button:has-text('{label}')", timeout=15000)
    if verb == "ingest":
        # B4: 'Rebuild memory' now confirms first — accept it so the POST still
        # fires (the destructive run itself is blocked by the intercept below). A
        # no-op if the confirm is not yet deployed.
        page.once("dialog", lambda d: d.accept())
    with intercepted(page, f"**/api/hostcmd/{verb}"):
        with assert_calls(page, "POST", HOSTCMD + verb):
            page.click(f"button:has-text('{label}')")


@pytest.mark.real_flow
def test_knowledge_gitsync_status(authed_page):
    """The knowledge/ -> git 'Status' control fires POST /offense/api/knowledge/gitsync
    {action:'status'} — a non-mutating local git status read (no egress, no
    commit). Safe to run for real."""
    page = authed_page
    _nav(page, "knowledge")
    page.wait_for_selector("h3:has-text('knowledge/ folder → git')", timeout=15000)
    with assert_calls(page, "POST", GITSYNC):
        page.click("button:has-text('Status')")


@pytest.mark.assert_gate
def test_knowledge_gitsync_sync_wiring_not_executed(authed_page):
    """'Regenerate + commit' is wired to POST /offense/api/knowledge/gitsync
    {action:'sync'} — a REAL local mutation (regenerates the system-map and makes
    a git commit in the knowledge/ folder). ASSERT GATE: prove the wiring, but
    INTERCEPT so no commit is made on the live stack."""
    page = authed_page
    _nav(page, "knowledge")
    page.wait_for_selector("button:has-text('Regenerate + commit')", timeout=15000)
    with intercepted(page, "**/api/knowledge/gitsync"):
        with assert_calls(page, "POST", GITSYNC):
            page.click("button:has-text('Regenerate + commit')")


@pytest.mark.assert_gate
def test_knowledge_feed_pull_wiring_not_executed(authed_page):
    """'Pull now' is wired to POST /offense/api/feed/<slug>/pull — a conscious
    opt-in EGRESS act (refreshes the vuln feed from NVD/OSV/CISA over the network).
    It is now additionally gated by a client-side window.confirm (B4), which we
    ACCEPT here to prove the POST wiring. ASSERT GATE: INTERCEPT so no outbound
    egress fires."""
    page = authed_page
    _nav(page, "knowledge")
    page.wait_for_selector("button:has-text('Pull now')", timeout=15000)
    # the live engagement 'loopback' is selected and the global kill-switch is
    # released, so the button is enabled. B4: accept the new confirm so the POST
    # still fires (the egress itself is blocked by the intercept below). A no-op if
    # the confirm is not yet deployed.
    page.once("dialog", lambda d: d.accept())
    with intercepted(page, "**/api/feed/**"):
        with assert_calls(page, "POST", FEED):
            page.click("button:has-text('Pull now')")


@pytest.mark.assert_gate
def test_knowledge_feed_sidecar_start_wiring_not_executed(authed_page):
    """The recurring feed sidecar 'Start' is wired to POST /offense/api/feed/<slug>/start
    — it spawns a PERSISTENT background egress daemon the console supervises.
    ASSERT GATE: prove the wiring, but INTERCEPT so no daemon is spawned. (Stop is
    disabled live — no sidecar is running — which is the correct state.)"""
    page = authed_page
    _nav(page, "knowledge")
    page.wait_for_selector("h3:has-text('Recurring feed sidecar')", timeout=15000)
    start_btn = page.locator("h3:has-text('Recurring feed sidecar')") \
        .locator("xpath=following::button[normalize-space(.)='Start'][1]")
    with intercepted(page, "**/api/feed/**"):
        with assert_calls(page, "POST", "/start"):
            start_btn.click()
