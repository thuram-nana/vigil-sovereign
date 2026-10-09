"""E2E suite — cluster `interactive` (DO: chat, terminal + Defense/AEGIS).

Each test loads the REAL unified UI at :8770 through the uiproxy with an owner
session (the `authed_page` fixture), navigates to a screen by hash route, and
asserts a REAL backend call at the NETWORK layer with `helpers.assert_calls`
(button -> real backend call, not "the DOM changed").

Grounding (read from packages/vigil-ui/app.js, verified live against the running
stack — see the per-test comments):

  chat      renderChat     app.js:7883  — load() reads GET /offense/api/chat/sessions
                                          (nav-driven, NOT polled; teardownLive()
                                          clears all liveTimers on entry). Send of a
                                          target-less/mode-less turn STREAMS to
                                          POST /offense/api/chat/stream (reallySend ->
                                          streamSend). Delete-chat is window.confirm()
                                          gated (deleteChat app.js:8098).
  terminal  renderTerminal app.js:6144  — termLoadHistory() reads GET
                                          /offense/api/terminal/history on nav (not
                                          polled). Ask -> POST .../terminal/propose;
                                          typing -> POST .../terminal/dryrun; Run ->
                                          POST .../terminal/run. The allowlist is the
                                          gate: a writer/network binary is REFUSED by
                                          dryrun and never run.
  defense   renderDefense  app.js:5581  — loadDefense() opens the live verdict SSE
                                          GET /offense/api/aegis/verdicts on nav
                                          (EventSource, NOT polled; /api/aegis/status
                                          IS polled every 4s and is deliberately not
                                          asserted). "Show identity keys" -> POST
                                          /offense/api/identity. "Start defense" ->
                                          POST /offense/api/aegis/setup (fail-closed on
                                          empty upstream — no gateway is spawned).

Discipline markers (README/conftest §7):
  real_flow   — safe reads / a trivial chat turn / a benign terminal run, run for real.
  assert_gate — a destructive control: the gate must engage and the action must NOT
                fire (chat-delete confirm dismissed; the allowlist refusing a writer).
"""
from __future__ import annotations

import pytest

from helpers import OFFENSE_BASE, SESSION_TOKEN_KEY, assert_calls
from screens import BY_ID

CHAT = BY_ID["chat"]
TERMINAL = BY_ID["terminal"]
DEFENSE = BY_ID["defense"]


def _nav(page, screen_id: str) -> None:
    page.evaluate(f"location.hash = '#/{screen_id}'")


def _same_origin_fetch(page, base_url: str, method: str, path: str, json_body=None):
    """Issue a same-origin fetch carrying the SPA's own session credential.

    Mirrors ui.js token(): the per-user bearer in sessionStorage is sent as the
    X-SIGIL-Token header (+ X-Requested-With). Used only to CROSS-CHECK a route's
    HTTP-method contract (never to drive a control under test).
    """
    return page.evaluate(
        """async ([url, method, key, body]) => {
            let tok = "";
            try { tok = sessionStorage.getItem(key) || ""; } catch (e) {}
            if (!tok && window.VIGIL_CFG && window.VIGIL_CFG.token) tok = window.VIGIL_CFG.token;
            const headers = { "X-Requested-With": "vigil-ui" };
            if (tok) headers["X-SIGIL-Token"] = tok;
            const opts = { method: method, credentials: "same-origin", headers: headers };
            if (body !== null) { headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
            const r = await fetch(url, opts);
            let data = null;
            try { data = await r.json(); } catch (e) { data = null; }
            return { status: r.status, data: data };
        }""",
        [base_url.rstrip("/") + path, method, SESSION_TOKEN_KEY, json_body],
    )


# ── CHAT ──────────────────────────────────────────────────────────────────────
@pytest.mark.real_flow
def test_chat_nav_fires_session_list_read_and_renders(authed_page):
    """Nav to #/chat fires the session-list read and the chat shell renders.

    renderChat -> load() -> loadChatList() reads GET /offense/api/chat/sessions
    (app.js:7968). It is nav-driven and on NO setInterval (renderChat calls
    teardownLive() first), so only the navigation can satisfy this match.
    """
    page = authed_page
    # load() is serial: settings -> roster (toolprofiles/capabilities/chat-models) ->
    # loadChatList, so the session-list GET only fires after ~4 prior cross-plane reads.
    # On a loaded host that can exceed the 10s default, so allow 30s for it to fire.
    with assert_calls(page, "GET", f"{OFFENSE_BASE}/api/chat/sessions", timeout_ms=30_000):
        _nav(page, CHAT.id)
    page.wait_for_selector("#chat-wrap", timeout=15_000)
    assert page.locator("h1", has_text="Chat").first.is_visible()


@pytest.mark.real_flow
def test_chat_send_trivial_message_posts_stream(authed_page):
    """Sending a trivial, target-less turn POSTs the streaming endpoint.

    reallySend() app.js (streamable = no target && no mode) -> streamSend ->
    streamChat -> fetch POST /offense/api/chat/stream. The prompt is trivial
    ("hi"); whether a model key is present or the server falls back, the
    stream POST fires first at the network layer.
    """
    page = authed_page
    _nav(page, CHAT.id)
    # The composer renders only after load()'s ~6 cross-plane reads resolve; that can
    # take >15s on a loaded host, so wait generously (it is not broken, just serial).
    page.wait_for_selector(".chat-composer textarea", timeout=30_000)
    page.fill(".chat-composer textarea", "hi")
    with assert_calls(page, "POST", f"{OFFENSE_BASE}/api/chat/stream"):
        page.click(".chat-composer button.btn.primary")


@pytest.mark.assert_gate
def test_chat_delete_is_gated_by_confirm_and_not_performed(authed_page):
    """Deleting a chat demands a window.confirm(); dismissed -> no delete POST.

    deleteChat (app.js:8098) guards POST /offense/api/chat/delete behind
    window.confirm(). We register a dialog handler that records + DISMISSES, click
    the row's trash control, and assert (a) the confirm fired and (b) no
    /api/chat/delete POST ever left the browser. The destructive action is NEVER
    performed.
    """
    page = authed_page
    _nav(page, CHAT.id)
    # The sidebar renders only after load()'s ~6 serial cross-plane reads resolve
    # (can exceed 15s on a loaded host). `.chat-new` is the drawSessions() render
    # marker; wait for it, then for a row, before counting — a premature count would
    # wrongly skip a stack that does have chats.
    page.wait_for_selector(".chat-new", timeout=30_000)
    try:
        page.wait_for_selector(".chat-session-row", timeout=10_000)
    except Exception:
        pytest.skip("no saved chat present to exercise the delete gate")
    rows = page.locator(".chat-session-row button[aria-label='Delete chat']")
    if rows.count() == 0:
        pytest.skip("no saved chat present to exercise the delete gate")

    dialogs: list[str] = []
    page.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))

    delete_posts: list[str] = []
    page.on(
        "request",
        lambda r: delete_posts.append(r.url)
        if (r.method.upper() == "POST" and "/api/chat/delete" in r.url)
        else None,
    )

    rows.first.click()
    page.wait_for_timeout(1_000)  # allow a (wrongly) un-gated POST to appear if it would

    assert dialogs, "expected a confirm() dialog to gate chat deletion; none fired"
    assert "Delete chat" in dialogs[0]
    assert not delete_posts, (
        "chat delete was DISMISSED but a POST /api/chat/delete still fired: "
        f"{delete_posts!r}"
    )


# ── TERMINAL ────────────────────────────────────────────────────────────────────
@pytest.mark.real_flow
def test_terminal_nav_fires_history_read_and_renders(authed_page):
    """Nav to #/terminal fires the signed-command history read and renders.

    renderTerminal -> termLoadHistory() reads GET /offense/api/terminal/history
    (app.js:6340), nav-driven and un-polled.
    """
    page = authed_page
    with assert_calls(page, "GET", f"{OFFENSE_BASE}/api/terminal/history"):
        _nav(page, TERMINAL.id)
    page.wait_for_selector("#term-dock", timeout=15_000)
    assert page.locator("h1", has_text="Terminal").first.is_visible()


@pytest.mark.real_flow
def test_terminal_propose_posts(authed_page):
    """The 'Ask' button routes the English intent through POST .../terminal/propose.

    termPropose() (app.js:6210) POSTs /offense/api/terminal/propose. It PROPOSES a
    command (or an answer/route); nothing runs. The POST fires even with no model
    key (the server returns need_key).
    """
    page = authed_page
    _nav(page, TERMINAL.id)
    page.wait_for_selector("#term-intent", timeout=15_000)
    page.fill("#term-intent", "show the hostname")
    with assert_calls(page, "POST", f"{OFFENSE_BASE}/api/terminal/propose"):
        page.click("#term-propose-btn")


@pytest.mark.real_flow
def test_terminal_direct_input_posts_dryrun(authed_page):
    """Typing a direct command triggers the live gate preview POST .../terminal/dryrun.

    termDirectDryrun() (app.js:6300) debounces 300ms then POSTs
    /offense/api/terminal/dryrun for the verdict badge. Nothing runs.
    """
    page = authed_page
    _nav(page, TERMINAL.id)
    page.wait_for_selector("#term-direct", timeout=15_000)
    with assert_calls(page, "POST", f"{OFFENSE_BASE}/api/terminal/dryrun"):
        page.fill("#term-direct", "ls")


@pytest.mark.real_flow
def test_terminal_run_benign_command_posts_run(authed_page):
    """Run of a benign allowlisted read command POSTs .../terminal/run (gated, signed).

    termRunDirect -> termRun (app.js:6362) POSTs /offense/api/terminal/run. `ls` is
    on the local read/inspect allowlist (verified live: dryrun verdict 'queued').
    No client confirm() is shown, so this is a real_flow; the server-side A2 gate +
    signed record govern execution.
    """
    page = authed_page
    _nav(page, TERMINAL.id)
    page.wait_for_selector("#term-direct", timeout=15_000)
    page.fill("#term-direct", "ls")
    with assert_calls(page, "POST", f"{OFFENSE_BASE}/api/terminal/run"):
        page.click("#term-direct-btn")


@pytest.mark.assert_gate
def test_terminal_writer_command_refused_by_allowlist_gate(authed_page):
    """A destructive writer command is REFUSED by the allowlist gate; Run is never clicked.

    The terminal's gate is the allowlist: `rm -rf …` is a writer, off the local
    read/inspect allowlist. The dryrun verdict badge must read REFUSED
    (termVerdictBadge, app.js:6174 — 'refused' -> 'REFUSED'), and we NEVER POST
    /offense/api/terminal/run for it, so nothing is executed. (Verified live: dryrun
    of `rm -rf /tmp/zz` -> {"verdict":"refused", ...}.)
    """
    page = authed_page

    run_posts: list[str] = []
    page.on(
        "request",
        lambda r: run_posts.append(r.url)
        if (r.method.upper() == "POST" and "/api/terminal/run" in r.url)
        else None,
    )

    _nav(page, TERMINAL.id)
    page.wait_for_selector("#term-direct", timeout=15_000)
    with assert_calls(page, "POST", f"{OFFENSE_BASE}/api/terminal/dryrun"):
        page.fill("#term-direct", "rm -rf /tmp/zz")

    badge = page.wait_for_selector("#term-direct-badge .vbadge", timeout=10_000)
    assert "REFUSED" in (badge.text_content() or "").upper(), (
        "writer command should be REFUSED by the allowlist gate; badge said: "
        f"{badge.text_content()!r}"
    )
    assert not run_posts, f"a refused command must never POST /api/terminal/run: {run_posts!r}"


# ── DEFENSE (AEGIS) ─────────────────────────────────────────────────────────────
@pytest.mark.real_flow
def test_defense_nav_opens_verdicts_sse_and_renders(authed_page):
    """Nav to #/defense opens the live verdict SSE and the screen renders.

    loadDefense() opens EventSource GET /offense/api/aegis/verdicts (app.js:5697),
    nav-driven and NOT on a setInterval. (/api/aegis/status IS polled every 4s —
    app.js:5694 — and is deliberately NOT asserted, to avoid green-washing.) With
    no gateway running the server answers 404, but the SSE REQUEST still fires on
    nav, which is what we assert.
    """
    page = authed_page
    with assert_calls(page, "GET", f"{OFFENSE_BASE}/api/aegis/verdicts"):
        _nav(page, DEFENSE.id)
    page.wait_for_selector("#def-tiles", timeout=15_000)
    assert page.locator("h1", has_text="Defense (AEGIS)").first.is_visible()


@pytest.mark.real_flow
def test_defense_show_identity_keys_posts(authed_page):
    """'Show identity keys' exports the offense PUBLIC identity keys via POST .../identity.

    detectIdentityCard (app.js:5654) -> POST /offense/api/identity ({}), a read-only
    export of PUBLIC keys. Safe real_flow.
    """
    page = authed_page
    _nav(page, DEFENSE.id)
    page.wait_for_selector("#def-tiles", timeout=15_000)
    btn = page.locator("button", has_text="Show identity keys")
    btn.wait_for(timeout=10_000)
    with assert_calls(page, "POST", f"{OFFENSE_BASE}/api/identity"):
        btn.click()


@pytest.mark.real_flow
def test_defense_start_gateway_posts_setup_fail_closed(authed_page):
    """'Start defense' POSTs /aegis/setup; with an empty upstream it fails closed (no spawn).

    defSetupForm 'Start defense' (app.js:5796) POSTs /offense/api/aegis/setup. The
    default host is loopback (no confirm()). With the upstream left empty,
    actions.aegis_setup (actions.py:5234) rejects BEFORE any spawn ('upstream must
    be a full http(s) URL …'), so this asserts the service-op POST fires while
    guaranteeing NO gateway is started.
    """
    page = authed_page
    _nav(page, DEFENSE.id)
    # The setup form only renders when no gateway is running (defDrawStatus). Its
    # url input is unique to the form (app.js:5797) — wait for it before clicking.
    page.wait_for_selector("#def-setup input[type='url']", timeout=15_000)
    start = page.locator("#def-setup button.btn.primary", has_text="Start defense")
    start.wait_for(timeout=10_000)
    with assert_calls(page, "POST", f"{OFFENSE_BASE}/api/aegis/setup"):
        start.click()


@pytest.mark.real_flow
def test_defense_destruction_quorum_card_reads_via_post(authed_page, base_url):
    """FIXED: the Destruction-quorum card reads via POST (the route is POST-only).

    destructionQuorumCard (app.js:5609) now does
    V.postJSON(OFF('/api/destruction/status'), {}) — matching the console server's
    POST-only dispatch (server.py:986). On nav the card POSTs and renders the REAL
    quorum status (a provisioned m-of-n line, or an honest 'No destruction quorum
    provisioned'), NOT the dead-read error fallback it showed when it used GET.

    Pins the fix deterministically:
      * the card issues the POST on nav (grounding the fix);
      * #dq-status shows a real status, never the 'Could not read the quorum
        status' error fallback;
      * POST /api/destruction/status -> 200 {"ok":true, ...}  (the working method);
      * GET  /api/destruction/status -> 404                   (still POST-only).
    """
    import time

    page = authed_page
    with assert_calls(page, "POST", f"{OFFENSE_BASE}/api/destruction/status"):
        _nav(page, DEFENSE.id)
    page.wait_for_selector("#def-tiles", timeout=15_000)
    page.wait_for_selector("#dq-status", timeout=15_000)

    # the card renders a REAL status, not the error fallback. (CSP-safe read via a
    # passed function — the harness CSP forbids wait_for_function's string eval.)
    end = time.time() + 15
    txt = ""
    while time.time() < end:
        txt = page.evaluate(
            "() => { var e = document.querySelector('#dq-status'); return e ? e.textContent : ''; }"
        ) or ""
        if ("Provisioned:" in txt) or ("No destruction quorum provisioned" in txt):
            break
        page.wait_for_timeout(200)
    assert "Could not read the quorum status" not in txt, (
        f"the card still shows the dead-read error fallback — the POST read is not working: {txt!r}"
    )
    assert ("Provisioned:" in txt) or ("No destruction quorum provisioned" in txt), (
        f"the card did not render a real quorum status (expected a provisioned m-of-n line or "
        f"'No destruction quorum provisioned'): {txt!r}"
    )

    # Contract: POST is the working method (200 ok); GET stays unregistered (404).
    post_res = _same_origin_fetch(page, base_url, "POST", f"{OFFENSE_BASE}/api/destruction/status", json_body={})
    assert post_res["status"] == 200 and (post_res["data"] or {}).get("ok") is True, (
        f"the POST contract for /api/destruction/status changed: {post_res!r}"
    )
    get_res = _same_origin_fetch(page, base_url, "GET", f"{OFFENSE_BASE}/api/destruction/status")
    assert get_res["status"] == 404, (
        f"GET /api/destruction/status should stay unregistered (POST-only); got {get_res['status']}"
    )
