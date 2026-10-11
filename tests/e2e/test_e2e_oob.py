"""E2E suite for the OOB (out-of-band / blind-callback) UI (KEY=oob).

Drives the Wave 1-2 OOB front end through a real Chromium against the live stack
(uiproxy :8770) and the MERIDIAN loopback range (:19010). Three tests, one per
invariant the OOB surface must hold:

  A. Charter arm + collaborator (loopback)  -> @real_flow
     The "Out-of-band (OOB) collaborator & arming" card reads a MEASURED status,
     stands up the managed loopback collaborator, and arms a loopback authority.
  B. Wizard toggle launches an OOB run       -> @real_flow
     The New-Assessment wizard enables its OOB checkbox ONLY because the
     engagement is armed, and a launch carries oob.enabled===true end to end.
  C. Remote arming is guided, never minted    -> @assert_gate
     A remote target renders the `vigil provision ... --oob-collector-pubkey`
     GUIDE and the console mints NOTHING (FATAL-2: the console never signs).

GROUNDING NOTES (load-bearing for soundness):

  * GET /offense/api/oob/status is NAV/BUTTON-DRIVEN, never polled. The only
    background polls (grep app.js for setInterval) touch /sovereign/api/snapshot
    (pboxApprovalPoll), /offense/api/runs (pboxPoll app.js:11131) and screen-local
    live refreshers — NONE touch /api/oob/* or the Charter screen (the Charter has
    no setInterval; app.js:11230 says so explicitly). So wrapping a nav-to-#/charter
    in assert_calls(GET /api/oob/status) is sound: the match can only come from
    loadCharter's render (app.js:11231), never a stray poll.

  * /offense/api/runs IS pboxPoll-polled (app.js:11104, a global setInterval(4000)
    that SURVIVES route changes), so it is GREEN-WASH-UNSAFE to assert with
    assert_calls — a background poll would satisfy the match regardless of the
    action. Test B therefore reads /api/runs with the PAGE'S OWN fetch as a pure
    DATA read, exactly as discover_runs() does in test_e2e_engage.py.

  * Test B's final "no --no-oob" check — ADAPTED to the real backend. The run's
    argv is recorded only in meta.json's "cmd" and is NOT surfaced by any
    page-reachable endpoint: list_runs (api.py:322-407) omits "cmd" entirely
    (the string "cmd" does not occur in console/api.py), and this harness is
    FATAL-2-isolated (network-only; it must never read the run dir off disk).
    So "OOB wiring present / no --no-oob" is proven at the strongest
    page-observable layer: the launch POST body carries oob.enabled===true —
    which is EXACTLY the field launch_assessment reads (actions.py:
    `_oob = body.get("oob"); oob_enabled = bool(_oob.get("enabled"))`) to decide
    `if not oob_enabled: cmd.append("--no-oob")`. oob.enabled===true in the body
    is therefore the sound, page-observable proof that the launched scan omits
    `--no-oob`; we additionally confirm the run was really created (it appears in
    /api/runs), i.e. the OOB launch was not rejected.

FATAL-2 (asserted by this suite, never relaxed): the console/offense plane NEVER
signs an authority. A LOOPBACK arm shells the governance-signed `vigil provision`
(scope HARD-FIXED to 127.0.0.1) sovereign-side; a REMOTE arm is GUIDE-ONLY and
mints nothing. The managed collaborator binds 127.0.0.1 only, and its poll secret
never enters a body (status returns only PUBLIC material + the secret PATH).
"""
from __future__ import annotations

import json
import time

import pytest

from helpers import SESSION_TOKEN_KEY, assert_calls

MERIDIAN_URL = "http://127.0.0.1:19010/"
# The engagement slug Test A arms on the Charter card (CHT.slug default, app.js:11197).
# Test B sets the wizard slug to the SAME value so the wizard's status read
# (oobSlug = W.slug.trim() || slugify(host), app.js:2614) hits the armed authority.
OOB_SLUG = "loopback"
# A deliberately NON-loopback host for the remote-arm boundary (Test C). It is never
# contacted — only used to drive the guide render + prove the console mints nothing.
REMOTE_HOST = "app.example.com"


# ── page-level data reads (the browser's own authenticated fetch; same creds the
#    SPA uses — mirrors helpers.current_principal / engage.discover_runs) ─────────
def _oob_status(page, base_url: str, slug: str) -> dict:
    """GET /offense/api/oob/status?slug=<slug> as a pure DATA read (not polled)."""
    return page.evaluate(
        """async ([base, tokKey, slug]) => {
            let tok = ""; try { tok = sessionStorage.getItem(tokKey) || ""; } catch (e) {}
            const H = { "X-Requested-With": "vigil-ui" }; if (tok) H["X-SIGIL-Token"] = tok;
            try {
                const r = await fetch(base + "/offense/api/oob/status?slug=" + encodeURIComponent(slug),
                                      { headers: H, credentials: "same-origin" });
                return r.ok ? await r.json() : { ok: false, status: r.status };
            } catch (e) { return { ok: false, error: String(e) }; }
        }""",
        [base_url.rstrip("/"), SESSION_TOKEN_KEY, slug],
    )


def _page_post(page, base_url: str, path: str, body: dict) -> dict:
    """POST <path> {body} with the page's own same-origin fetch (identical headers
    to the SPA's V.postJSON: X-Requested-With + X-SIGIL-Token + JSON). Returns
    {status, data}. Used only to probe the SERVER-SIDE FATAL-2 boundary in Test C."""
    return page.evaluate(
        """async ([url, body, tokKey]) => {
            let tok = ""; try { tok = sessionStorage.getItem(tokKey) || ""; } catch (e) {}
            const H = { "Content-Type": "application/json", "X-Requested-With": "vigil-ui" };
            if (tok) H["X-SIGIL-Token"] = tok;
            try {
                const r = await fetch(url, { method: "POST", credentials: "same-origin",
                                             headers: H, body: JSON.stringify(body) });
                let d = null; try { d = await r.json(); } catch (e) { d = null; }
                return { status: r.status, data: d };
            } catch (e) { return { status: 0, error: String(e) }; }
        }""",
        [base_url.rstrip("/") + path, body, SESSION_TOKEN_KEY],
    )


def _runs(page, base_url: str) -> list:
    """GET /offense/api/runs as a DATA read (NOT assert_calls — it is pboxPoll-polled)."""
    d = page.evaluate(
        """async ([base, tokKey]) => {
            let tok = ""; try { tok = sessionStorage.getItem(tokKey) || ""; } catch (e) {}
            const H = { "X-Requested-With": "vigil-ui" }; if (tok) H["X-SIGIL-Token"] = tok;
            try {
                const r = await fetch(base + "/offense/api/runs", { headers: H, credentials: "same-origin" });
                return r.ok ? await r.json() : { runs: [] };
            } catch (e) { return { runs: [] }; }
        }""",
        [base_url.rstrip("/"), SESSION_TOKEN_KEY],
    )
    return (d or {}).get("runs", []) or []


def _wait_hash_prefix(page, prefix: str, timeout_ms: int = 30_000) -> None:
    """Wait until location.hash starts with `prefix`. CSP-safe: polls page.evaluate
    of a FUNCTION (CDP Runtime), never wait_for_function's string eval — the idiom
    test_e2e_engage._wait_live_rendered uses for the same reason."""
    end = time.time() + timeout_ms / 1000
    while time.time() < end:
        if page.evaluate("(p) => (location.hash || '').indexOf(p) === 0", prefix):
            return
        page.wait_for_timeout(200)
    raise AssertionError(
        f"location.hash never became {prefix!r} (now {page.evaluate('() => location.hash')!r})"
    )


def _ensure_loopback_armed(page, base_url: str) -> dict:
    """Establish Test B's precondition idempotently: a listening loopback
    collaborator whose collector pubkey is pinned by an owner-signed authority for
    OOB_SLUG. If already armed (Test A ran, state persists server-side), returns at
    once. Otherwise it drives the SAME Charter buttons Test A asserts (Start, Arm)
    functionally and polls the authoritative status. Returns the final status dict;
    the caller skips honestly (never green-washes) if `armed` is not reached."""
    st = _oob_status(page, base_url, OOB_SLUG)
    if st.get("armed"):
        return st

    # Drive the Charter Start + Arm buttons functionally. Any UI hiccup falls through to the
    # authoritative poll below, which returns not-armed so the caller skips honestly (never errors).
    try:
        page.evaluate("location.hash = '#/charter'")
        page.wait_for_selector("#screen h3:has-text('Out-of-band (OOB) collaborator')", timeout=15_000)

        st = _oob_status(page, base_url, OOB_SLUG)
        if not (st.get("running") and st.get("listening")):
            page.click("button:has-text('Start collaborator (loopback)')")
            # The start POST blocks server-side until the relay binds (actions wait budget);
            # loadAuthority then re-reads status and the Arm button enables.
            page.wait_for_selector("button:has-text('Arm OOB (loopback)'):not([disabled])", timeout=30_000)

        arm = page.locator("button:has-text('Arm OOB (loopback)')")
        arm.wait_for(timeout=15_000)
        if not arm.is_disabled():
            arm.click()
    except Exception:  # noqa: BLE001 — any drive failure is an honest not-armed precondition, not a test error
        pass

    end = time.time() + 60
    while time.time() < end:
        st = _oob_status(page, base_url, OOB_SLUG)
        if st.get("armed"):
            return st
        page.wait_for_timeout(500)
    return st


# ── A. charter arm + collaborator (loopback) ────────────────────────────────────
@pytest.mark.real_flow
def test_charter_oob_start_collaborator_and_arm_loopback(authed_page, base_url):
    """Charter & Attestation: the OOB card reads a MEASURED status (nav-driven,
    UNPOLLED), stands up the managed loopback collaborator, and arms a loopback
    authority — all on 127.0.0.1, with the console signing NOTHING.

    Nav-driven read: navigating to #/charter runs loadCharter (app.js:11231),
    which fires GET /offense/api/oob/status?slug=<slug>. The Charter has NO
    setInterval (app.js:11230), so the assert_calls match can only come from the
    render. Controls:
      * "Start collaborator (loopback)" -> POST /offense/api/oob/collaborator/start
        {slug} — the managed relay binds 127.0.0.1 ONLY; the request body carries
        no public-bind directive (asserted).
      * "Arm OOB (loopback)" (enabled only once the relay is listening) -> POST
        /offense/api/oob/arm {slug, host:127.0.0.1} — shells the governance-signed
        `vigil provision` sovereign-side. The re-read status then shows armed + the
        collector pubkey.
    """
    page = authed_page

    # 1) Nav-driven, UNPOLLED status read.
    with assert_calls(page, "GET", "/offense/api/oob/status"):
        page.evaluate("location.hash = '#/charter'")
    page.wait_for_selector("#screen h3:has-text('Out-of-band (OOB) collaborator')", timeout=15_000)

    # 2) Start the managed collaborator; capture + assert the body implies a loopback bind.
    with assert_calls(page, "POST", "/offense/api/oob/collaborator/start") as start_ri:
        page.click("button:has-text('Start collaborator (loopback)')")
    start_body = start_ri.value.post_data or ""
    assert "0.0.0.0" not in start_body, \
        f"collaborator/start body must never request a public (0.0.0.0) bind: {start_body!r}"
    bj = {}
    if start_body:
        try:
            bj = json.loads(start_body)
        except ValueError:
            bj = {}
    # The UI sends only {slug}. Defensive: if any bind/host/advertise field is present it MUST be loopback.
    for k in ("host", "bind", "bind_host", "advertise_url", "advertise"):
        v = str(bj.get(k, "") or "").lower()
        if v:
            assert ("127.0.0.1" in v or "localhost" in v or "::1" in v), \
                f"collaborator/start field {k}={bj.get(k)!r} must be loopback, never public"
    assert bj.get("slug"), f"collaborator/start body must carry the engagement slug: {start_body!r}"

    # The relay must come up before Arm is offered (the pin is read from the RUNNING relay).
    page.wait_for_selector("button:has-text('Arm OOB (loopback)'):not([disabled])", timeout=30_000)

    # 3) Arm the loopback authority (the arm POST fires on click; `vigil provision` + re-read follow).
    with assert_calls(page, "POST", "/offense/api/oob/arm"):
        page.click("button:has-text('Arm OOB (loopback)')")

    # Re-read status shows armed — assert via the DOM (proves the UI re-render) AND authoritatively.
    try:
        page.wait_for_selector("text=pins this collector", timeout=60_000)
    except Exception as exc:  # noqa: BLE001 — turn an opaque timeout into a clear soundness message
        st = _oob_status(page, base_url, OOB_SLUG)
        raise AssertionError(
            "arming did not reach the ARMED state; the loopback authority was not minted "
            f"(status={st!r}). The console shells `vigil provision` sovereign-side — a lab without "
            f"authority provisioning cannot arm. ({type(exc).__name__})"
        ) from exc

    st = _oob_status(page, base_url, OOB_SLUG)
    assert st.get("armed") is True, f"re-read status must show armed after a loopback arm: {st!r}"
    assert str(st.get("collector_pubkey") or ""), \
        f"an armed engagement must expose the running collector's pubkey: {st!r}"
    # The status NEVER leaks the poll secret — only its PATH is allowed to appear.
    assert "secret" not in {k.lower() for k in st} or "secret_path" in st, st
    assert "poll_secret" not in st and "relay_secret" not in st, \
        f"status must never carry the poll secret value: {sorted(st.keys())}"


# ── B. wizard toggle launches an OOB run ────────────────────────────────────────
@pytest.mark.real_flow
def test_wizard_oob_toggle_launches_oob_run_meridian(authed_page, base_url):
    """New Assessment: the OOB checkbox is enabled ONLY because the engagement is
    armed, and a launch carries oob.enabled===true through to a real run.

    Precondition: OOB_SLUG armed (Test A; re-established here if needed, else the
    test skips honestly). Flow (wizard bodies order app.js:2873 =
    [stepTargetType, stepWhere, stepScope, stepMode, stepModel]):
      step1 pick "Scan a website" -> step2 target=MERIDIAN + slug=OOB_SLUG +
      authorized -> advance to step4 (stepMode), where oobCheckbox() renders ENABLED
      because the measured status is armed (app.js:2613) -> tick it -> step5 Launch.
    The launch POST body is captured and asserted to carry oob.enabled===true — the
    exact field launch_assessment branches on to OMIT `--no-oob` (see module
    docstring). The created run is then confirmed present via a page-fetch of
    /api/runs (a DATA read; /api/runs is pboxPoll-polled, so never assert_calls).
    """
    page = authed_page

    st = _ensure_loopback_armed(page, base_url)
    if not st.get("armed"):
        pytest.skip(
            "loopback OOB could not be armed in this lab (authority provisioning unavailable); "
            "the wizard OOB toggle is gated on an armed authority, so there is nothing to drive"
        )

    # step1 -> pick "Scan a website / API" (mode url); advances to step2 (stepWhere).
    page.evaluate("location.hash = '#/assess'")
    page.wait_for_selector("#screen h1:has-text('New Assessment')", timeout=15_000)
    page.click("button.choice:has-text('Scan a website')")
    page.wait_for_selector("input[type=url]", timeout=10_000)

    # step2: target (fires the read-only preview) + slug pinned to the ARMED slug + authorized.
    with assert_calls(page, "POST", "/offense/api/launch/preview"):
        page.fill("input[type=url]", MERIDIAN_URL)
    page.fill("#wiz-slug", OOB_SLUG)   # oobSlug = W.slug.trim() (app.js:2614) -> hits the armed authority
    page.check("label:has-text('I am authorized') input[type=checkbox]")

    # Advance step2 -> step3 -> step4 (stepMode) where the OOB checkbox lives.
    for _ in range(2):
        page.wait_for_selector("#wiz-foot button:has-text('Next'):not([disabled])", timeout=10_000)
        page.click("#wiz-foot button:has-text('Next')")

    # The OOB checkbox is ENABLED only because the engagement is armed (app.js:2620 vs the disabled
    # fallback app.js:2629). Its enabled state is the whole point of the gate — assert it, then tick it.
    oob_sel = "label:has-text('Confirm blind / out-of-band (OOB) findings') input[type=checkbox]"
    page.wait_for_selector(oob_sel + ":not([disabled])", timeout=15_000)
    oob_cb = page.locator(oob_sel)
    assert not oob_cb.is_disabled(), \
        "the wizard OOB checkbox must be ENABLED once the engagement is armed (gated on measured status)"
    oob_cb.check()
    assert oob_cb.is_checked(), "ticking the armed OOB checkbox must set it on"

    # step4 -> step5, then Launch.
    page.wait_for_selector("#wiz-foot button:has-text('Next'):not([disabled])", timeout=10_000)
    page.click("#wiz-foot button:has-text('Next')")
    page.wait_for_selector("#wiz-foot button:has-text('Launch assessment'):not([disabled])", timeout=10_000)

    with assert_calls(page, "POST", "/offense/api/launch/assessment") as launch_ri:
        page.click("#wiz-foot button:has-text('Launch assessment')")

    # The launch body carries oob.enabled===true — the sound, page-observable proof of OOB wiring
    # (the exact field that makes the server OMIT `--no-oob`; see module docstring).
    launch_body = launch_ri.value.post_data or ""
    payload = json.loads(launch_body) if launch_body else {}
    assert isinstance(payload.get("oob"), dict) and payload["oob"].get("enabled") is True, \
        f"launch body must carry oob.enabled===true (OOB wiring); got oob={payload.get('oob')!r}"

    # A run id came back and the SPA redirects to the run-scoped Live view.
    _wait_hash_prefix(page, "#/live?run=", timeout_ms=30_000)
    run_hash = page.evaluate("() => location.hash")
    run_id = run_hash.split("run=", 1)[1].split("&", 1)[0] if "run=" in run_hash else ""
    assert run_id, f"launch must return a run id and redirect to #/live?run=<id>; hash={run_hash!r}"

    # Confirm the run was REALLY created (the OOB launch was not rejected) via a DATA read of /api/runs.
    deadline = time.time() + 20
    created = None
    while time.time() < deadline and created is None:
        for r in _runs(page, base_url):
            if r.get("run_id") == run_id:
                created = r
                break
        if created is None:
            page.wait_for_timeout(500)
    assert created is not None, f"the launched OOB run {run_id!r} must appear in /api/runs"
    # Sanity: it is the loopback MERIDIAN scan we launched under the armed slug.
    assert str(created.get("slug") or "") == OOB_SLUG, \
        f"created run recorded slug {created.get('slug')!r}, expected {OOB_SLUG!r}"


# ── C. remote arming is guided, never minted (FATAL-2) ──────────────────────────
@pytest.mark.assert_gate
def test_charter_oob_remote_arm_is_guided_never_minted(authed_page, base_url):
    """Remote OOB arming is GUIDE-ONLY — the console never signs a remote authority.

    Setting a REMOTE host renders the exact `vigil provision ... --oob-collector-pubkey`
    ceremony for the owner to run out-of-band (app.js:11319 remoteGuide), and the UI
    offers NO mint for it — only Copy + a Re-check GET. We assert:
      1. the remote guide `<code>` renders (contains `vigil provision` + the pin flag);
      2. NO POST to /offense/api/oob/arm fires from the remote flow (page.on request);
      3. SERVER boundary (belt-and-braces): calling /api/oob/arm with a remote host
         returns a GUIDE and `armed:false` and mints nothing — never armed:true.
    This is the FATAL-2 gate: the pass condition is "the console refused to sign /
    only guided", never "a remote authority was minted".
    """
    page = authed_page

    page.evaluate("location.hash = '#/charter'")
    page.wait_for_selector("#screen h3:has-text('Out-of-band (OOB) collaborator')", timeout=15_000)

    # Record any arm POST the remote flow might fire (there must be none).
    arm_posts: list = []

    def _on_request(req):
        if "/offense/api/oob/arm" in req.url and req.method.upper() == "POST":
            arm_posts.append(req.url)

    page.on("request", _on_request)

    # 1) Set a REMOTE host in the card (onChange -> `change` event, ui.js:33 -> drawCharter re-render).
    page.fill("#cht-remote", REMOTE_HOST)
    page.eval_on_selector("#cht-remote", "el => el.dispatchEvent(new Event('change', { bubbles: true }))")

    # The OOB remote guide is the <code> carrying `--oob-collector-pubkey` (the charter-ceremony <code>
    # in the remote-target card does NOT carry that flag, so this locator is unambiguous).
    guide = page.locator("code:has-text('--oob-collector-pubkey')")
    guide.wait_for(timeout=15_000)
    guide_text = guide.inner_text()
    assert "vigil provision" in guide_text, f"remote guide must render the provision ceremony: {guide_text!r}"
    assert "--oob-collector-pubkey" in guide_text, f"remote guide must pin the collector pubkey: {guide_text!r}"
    assert REMOTE_HOST in guide_text, f"remote guide must scope to the remote host: {guide_text!r}"

    # 2) Exercise the remote flow's only backend control — "Re-check" — and prove it is a GET
    #    (loadAuthority re-reads status), never a mint.
    with assert_calls(page, "GET", "/offense/api/oob/status"):
        page.get_by_role("button", name="Re-check", exact=True).click()
    page.wait_for_timeout(800)   # allow any (forbidden) stray POST to surface
    assert arm_posts == [], \
        f"the remote flow must offer NO arm POST (console never signs a remote authority); saw: {arm_posts}"

    page.remove_listener("request", _on_request)

    # 3) SERVER boundary: even called directly with a remote host, /api/oob/arm mints NOTHING. It
    #    returns the out-of-band guide (remote:true, armed:false) when a collaborator is up, or an
    #    honest refusal when none is — NEVER armed:true. (oob_arm_loopback runs no `vigil provision`
    #    subprocess on the remote branch — actions.py — so nothing is signed.)
    res = _page_post(page, base_url, "/offense/api/oob/arm", {"slug": OOB_SLUG, "host": REMOTE_HOST})
    data = res.get("data") or {}
    assert data.get("armed") is not True, \
        f"/api/oob/arm must NEVER arm a remote host from the console (FATAL-2); response={data!r}"
    if data.get("remote") is True:
        assert data.get("armed") is False, f"a remote arm response must be armed:false; got {data!r}"
        g = str(data.get("guide") or "")
        assert "vigil provision" in g and "--oob-collector-pubkey" in g, \
            f"a remote arm must return the out-of-band provision GUIDE, not a mint; got {data!r}"
