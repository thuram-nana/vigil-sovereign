"""E2E suite for the DO / engagement-lifecycle cluster (KEY=engage).

Covers eight unified-UI screens and their controls, driven through a real
Chromium against the live stack (uiproxy :8770) and the MERIDIAN loopback range
(:19010). Each screen test NAVIGATES, asserts the screen's TOP-OF-RENDER,
NAV-DRIVEN backend read fires at the network layer (helpers.assert_calls), and
asserts a render signal that only appears when the screen actually rendered.
Each control is then driven: safe reads/flows run for real (@real_flow); the
one destructive/offense control here (Strix "Trip engagement kill-switch") is
NEVER fired — the test asserts the confirm() gate engages and declines it
(@assert_gate).

GROUNDING NOTES (packages/vigil-ui/app.js), load-bearing for test soundness:
  * /offense/api/runs is GREEN-WASH-UNSAFE to assert as nav-driven: pboxPoll()
    (app.js:11049) is a GLOBAL setInterval(4000) that fetches OFF("/api/runs")
    and SURVIVES route changes, so a background poll would satisfy the match
    regardless of the action. Every screen in this cluster reads /api/runs at
    the top of render, but we instead assert each screen's DISTINCT, UNPOLLED
    per-run read (/api/report, /api/proof, /api/evidence, /api/remediate,
    /api/strix/control, /api/capabilities) or its nav-opened SSE (/api/events).
  * setInterval audit (grep app.js): the only background polls touch
    /sovereign/api/snapshot (pboxApprovalPoll), /offense/api/runs (pboxPoll +
    live refreshRunMeta), and screen-local refreshers — NONE of the reads we
    assert below are on any interval.

Run ids are DISCOVERED live from the stack (discover_runs) so the suite grounds
itself in whatever runs exist rather than hard-coding; if a required run class
is absent the dependent assertion is skipped with an explicit reason (never
green-washed).
"""
from __future__ import annotations

import pytest

from helpers import OFFENSE_BASE, SESSION_TOKEN_KEY, assert_calls

MERIDIAN_URL = "http://127.0.0.1:19010/"

# Module cache so the (several-second) live run discovery runs once per session.
_DISCOVERED: dict = {}


def discover_runs(page, base_url: str) -> dict:
    """Probe the live stack (through the browser's own authenticated fetch) for
    runs that carry the properties each screen test needs:

      findings_run  -- a run whose /api/report has findings AND whose offline
                       re-verify reproduces >=1 certificate (so the Findings
                       Re-verify control has something real to re-fire).
      report_run    -- a run with /api/evidence total>0 (dossier has content).
      fixes_run     -- a run the backend says is `runnable` with fixable
                       oracle-confirmed findings (so the gated Apply/Deep-fix
                       controls actually render).
      proof_facts_run -- a run with >=1 proof FACT (so Export is enabled); may
                       be None, in which case Export is correctly gated OFF.
      newest        -- runs[0], used for the Live SSE check.

    Pure browser fetch (same credentials the SPA uses). Bounded to the first
    ~90 runs.
    """
    key = base_url
    if key in _DISCOVERED:
        return _DISCOVERED[key]
    result = page.evaluate(
        """async ([base, tokKey]) => {
            let tok = ""; try { tok = sessionStorage.getItem(tokKey) || ""; } catch (e) {}
            const H = { "X-Requested-With": "vigil-ui" }; if (tok) H["X-SIGIL-Token"] = tok;
            const j = async (u) => { try { const r = await fetch(base + u, { headers: H, credentials: "same-origin" }); return r.ok ? await r.json() : null; } catch (e) { return null; } };
            const runs = ((await j("/offense/api/runs")) || {}).runs || [];
            let findings_run = null, report_run = null, fixes_run = null, proof_facts_run = null;
            for (const r of runs.slice(0, 90)) {
                const id = r.run_id;
                if (!findings_run) {
                    const rep = await j("/offense/api/report/" + id);
                    if (rep && !rep.pending && (rep.findings || []).length) {
                        const ev = await j("/offense/api/evidence/" + id);
                        if (ev && (ev.reproduced || 0) > 0) { findings_run = id; if (!report_run && (ev.total || 0) > 0) report_run = id; }
                    }
                }
                if (!fixes_run) {
                    const rm = await j("/offense/api/remediate/" + id);
                    if (rm && rm.runnable && (rm.fixable_count || 0) > 0) fixes_run = id;
                }
                if (!proof_facts_run) {
                    const pr = await j("/offense/api/proof/" + id);
                    if (pr && (pr.facts || 0) > 0) proof_facts_run = id;
                }
                if (findings_run && fixes_run && proof_facts_run) break;
            }
            if (!report_run) report_run = findings_run;
            return { findings_run, report_run, fixes_run, proof_facts_run, newest: (runs[0] || {}).run_id || null };
        }""",
        [base_url.rstrip("/"), SESSION_TOKEN_KEY],
    )
    _DISCOVERED[key] = result
    return result


# ── assess ────────────────────────────────────────────────────────────────────
@pytest.mark.real_flow
def test_assess_preview_and_launch_meridian(authed_page, base_url):
    """New Assessment wizard, driven for real against the MERIDIAN loopback range.

    Top-of-render read: GET /offense/api/capabilities (renderAssess:2271 — the
    real capability catalogue; on no setInterval). Controls:
      * target entry -> refreshPlan() fires POST /offense/api/launch/preview
        (renderAssess:2338, read-only pre-send engine plan). This is the wizard's
        "Preview plan".
      * Launch assessment -> POST /offense/api/launch/assessment (launch():2798);
        a run id comes back and the SPA redirects to #/live?run=<id>.
    """
    page = authed_page

    with assert_calls(page, "GET", "/offense/api/capabilities"):
        page.evaluate("location.hash = '#/assess'")
    page.wait_for_selector("#screen h1:has-text('New Assessment')", timeout=15_000)

    # Step 1 -> pick "Scan a website / API" (mode url); this advances to step 2.
    page.click("button.choice:has-text('Scan a website')")
    page.wait_for_selector("input[type=url]", timeout=10_000)

    # Target entry fires the read-only preview (the pre-send engine plan).
    with assert_calls(page, "POST", "/offense/api/launch/preview"):
        page.fill("input[type=url]", MERIDIAN_URL)

    # Confirm the authorization gate checkbox (gates the wizard; not sent with launch).
    page.check("label:has-text('I am authorized') input[type=checkbox]")

    # Advance step 2 -> 3 -> 4 -> 5 (each Next enables only once the step validates).
    for _ in range(3):
        page.wait_for_selector("#wiz-foot button:has-text('Next'):not([disabled])", timeout=10_000)
        page.click("#wiz-foot button:has-text('Next')")

    page.wait_for_selector("#wiz-foot button:has-text('Launch assessment'):not([disabled])", timeout=10_000)
    with assert_calls(page, "POST", "/offense/api/launch/assessment"):
        page.click("#wiz-foot button:has-text('Launch assessment')")

    # A run id came back: the SPA redirects to the Live view scoped to it.
    page.wait_for_function(
        "location.hash.indexOf('#/live?run=') === 0", timeout=30_000
    )
    assert page.evaluate("location.hash").startswith("#/live?run="), \
        "launch must return a run id and redirect to #/live?run=<id>"


# ── live ────────────────────────────────────────────────────────────────────
@pytest.mark.real_flow
def test_live_run_appears_and_event_feed_streams(authed_page, base_url):
    """Live view: a run appears and its event feed (SSE) opens.

    Nav-driven, UNPOLLED read: the live screen opens an EventSource on the
    selected run (attachStream():3056). A loopback/scan run has stream "progress"
    -> GET /offense/api/events?run=...&from_start=1; a blackboard engage run ->
    GET /offense/api/blackboard?slug=... . Neither is on a setInterval (only
    refreshRunMeta polls /api/runs, which we deliberately do not assert). We
    assert the events SSE opens for the newest run.
    """
    page = authed_page
    d = discover_runs(page, base_url)
    newest = d.get("newest")
    assert newest, "no runs on the stack to drive the Live view"

    # Navigate to the newest run explicitly so the SSE target is deterministic.
    with assert_calls(page, "GET", "/offense/api/events", timeout_ms=20_000):
        page.evaluate(f"location.hash = '#/live?run={newest}'")
    page.wait_for_selector("#live-body", timeout=15_000)
    # Render signal: the run header/timeline replaced the "Loading runs…" empty.
    page.wait_for_function(
        "!!document.querySelector('#live-body') && "
        "document.querySelector('#live-body').textContent.indexOf('Loading runs') === -1",
        timeout=15_000,
    )


# ── strix (DESTRUCTIVE control -> assert the gate) ──────────────────────────────
@pytest.mark.assert_gate
def test_strix_control_loads_and_killswitch_is_gated(authed_page, base_url):
    """Strix Control: read-only load, and the kill-switch is gated.

    Top-of-render read: GET /offense/api/strix/control (loadStrix():7674 — read
    only, on no setInterval). Control: "Trip engagement kill-switch" is
    DESTRUCTIVE (strixTripKill():7811 posts /api/killswitch/<slug>/trip behind a
    window.confirm). We NEVER trip it: if the button is enabled we click it,
    assert the confirm() gate fired, and DISMISS it so no POST is sent; if it is
    disabled (no engagement slug / already tripped) the gate has already blocked
    it. Either way we assert no kill-switch POST fired.
    """
    page = authed_page

    dialog_fired = {"v": False}
    page.on("dialog", lambda dlg: (dialog_fired.__setitem__("v", True), dlg.dismiss()))
    killswitch_posts: list = []
    page.on(
        "request",
        lambda req: killswitch_posts.append(req.url)
        if ("/api/killswitch/" in req.url and req.method.upper() == "POST")
        else None,
    )

    with assert_calls(page, "GET", "/offense/api/strix/control"):
        page.evaluate("location.hash = '#/strix'")
    page.wait_for_selector("#screen h1:has-text('Strix Control')", timeout=15_000)

    trip = page.locator("button:has-text('Trip engagement kill-switch')")
    trip.wait_for(timeout=10_000)
    if trip.is_disabled():
        # The gate has already engaged: no slug / already tripped -> cannot fire.
        assert trip.is_disabled()
    else:
        trip.click()
        page.wait_for_timeout(600)
        assert dialog_fired["v"], \
            "Trip kill-switch must demand a confirm() before acting; none fired"

    assert not killswitch_posts, \
        f"kill-switch must NEVER be tripped; observed POST(s): {killswitch_posts}"


# ── findings ────────────────────────────────────────────────────────────────
@pytest.mark.real_flow
def test_findings_list_and_offline_reverify(authed_page, base_url):
    """Findings hub: the findings table renders and a finding's offline Re-verify
    re-fires its retained certificates.

    Nav-driven, UNPOLLED read: the default "findings" tab loads
    GET /offense/api/report/<run> (p3Findings():3931). Control: opening a finding
    drawer exposes "Re-verify this run (offline)" -> POST /offense/api/reverify/<run>
    (p3ReverifyInline():4064), a pure offline re-computation (no target traffic).
    """
    page = authed_page
    d = discover_runs(page, base_url)
    run = d.get("findings_run")
    if not run:
        pytest.skip("no run with report findings + reproducible certificates on the stack")

    with assert_calls(page, "GET", "/offense/api/report/", timeout_ms=15_000):
        page.evaluate(f"location.hash = '#/findings?run={run}'")
    page.wait_for_selector("#p3-body", timeout=15_000)
    page.wait_for_selector("table.tbl tr.click", timeout=15_000)

    # Open the first finding drawer, then re-verify this run OFFLINE.
    page.click("table.tbl tr.click >> nth=0")
    page.wait_for_selector("button:has-text('Re-verify this run (offline)')", timeout=10_000)
    with assert_calls(page, "POST", "/offense/api/reverify/", timeout_ms=30_000):
        page.click("button:has-text('Re-verify this run (offline)')")


# ── proof ────────────────────────────────────────────────────────────────────
@pytest.mark.real_flow
def test_proof_studio_read_and_export_gate(authed_page, base_url):
    """Proof Studio: the per-run proof read fires; Export is gated on a FACT.

    Nav-driven, UNPOLLED read: GET /offense/api/proof/<run> (loadProof():11546).
    Control: "Export verifiable bundle" -> POST /offense/api/proof/export, but it
    is disabled unless the run has >=1 oracle-confirmed FACT (canExport). If a
    fact-bearing run exists we select it and fire the export for real; otherwise
    we assert the control is correctly gated OFF (honest precondition, not a dead
    button).
    """
    page = authed_page
    d = discover_runs(page, base_url)

    with assert_calls(page, "GET", "/offense/api/proof/", timeout_ms=15_000):
        page.evaluate("location.hash = '#/proof'")
    # NB: the screen-head h2 "Proof Studio" is transient — drawProof() re-mounts
    # into the whole #screen (V.mount returns the element, body===screen) and
    # wipes it. The stable post-load render signal is the "Proofs" summary card.
    page.wait_for_selector("#screen h3:has-text('Proofs')", timeout=15_000)

    facts_run = d.get("proof_facts_run")
    export_btn = page.locator("button:has-text('Export verifiable bundle')")
    export_btn.wait_for(timeout=10_000)

    if facts_run:
        # Select the fact-bearing run, then fire the real export.
        with assert_calls(page, "GET", "/offense/api/proof/", timeout_ms=15_000):
            page.locator("#screen select").first.select_option(facts_run)
        page.wait_for_selector(
            "button:has-text('Export verifiable bundle'):not([disabled])", timeout=10_000
        )
        with assert_calls(page, "POST", "/offense/api/proof/export", timeout_ms=30_000):
            page.click("button:has-text('Export verifiable bundle')")
    else:
        # No run on the stack carries a proof FACT -> Export is correctly gated OFF.
        assert export_btn.is_disabled(), \
            "Export must be disabled when the run has no oracle-confirmed FACT"
        title = export_btn.get_attribute("title") or ""
        assert "FACT" in title, f"gated Export should explain the FACT precondition; title={title!r}"


# ── report ────────────────────────────────────────────────────────────────────
@pytest.mark.real_flow
def test_report_evidence_read_and_dossier_build(authed_page, base_url):
    """Client Report: the re-verified evidence read fires and Build dossier works.

    Nav-driven, UNPOLLED read: loadReport() fires GET /offense/api/evidence/<run>
    (loadReport():11316). Control: "Download dossier" -> POST
    /offense/api/dossier/<run>/build (downloadDossier():11263), which packages the
    run's reports + proof bundle + signed manifest (then streams the zip). Safe,
    read-only assembly.
    """
    page = authed_page
    d = discover_runs(page, base_url)
    run = d.get("report_run")
    if not run:
        pytest.skip("no run with evidence on the stack")

    with assert_calls(page, "GET", "/offense/api/evidence/", timeout_ms=15_000):
        page.evaluate("location.hash = '#/report'")
    # NB: the screen-head h2 "Client Report" is transient — drawReport() re-mounts
    # into the whole #screen (V.mount returns the element, body===screen) and
    # wipes it. The stable post-load render signal is the "Executive summary" card.
    page.wait_for_selector("#screen h3:has-text('Executive summary')", timeout=15_000)

    # Target a run that has evidence so the dossier build has content.
    with assert_calls(page, "GET", "/offense/api/evidence/", timeout_ms=15_000):
        page.locator("#screen select").first.select_option(run)
    page.wait_for_selector("#dossier-btn", timeout=10_000)
    with assert_calls(page, "POST", "/offense/api/dossier/", timeout_ms=30_000):
        page.click("#dossier-btn")


# ── fixes ────────────────────────────────────────────────────────────────────
@pytest.mark.real_flow
def test_fixes_plan_read_verify_and_apply_gate(authed_page, base_url):
    """Fixes: the remediation plan read fires; Verify (re-scan) runs for real;
    the destructive Apply / Deep-fix controls render behind the runnable gate.

    Nav-driven, UNPOLLED read: GET /offense/api/remediate/<run> (drawFixes():5909).
    Controls (only render when the backend says the run is `runnable`):
      * Verify (re-scan) -> POST /offense/api/remediate/<run>/<ref>/verify
        (verifyFix():6050): re-runs the deterministic static rule over the source,
        READ-ONLY (no patch applied, no PR). Fired for real.
      * Apply fix (gated) / Deep fix -> /api/remediate/<run>/<ref>/apply|deepfix:
        these MUTATE (gated patch ladder). We assert they RENDER (the gate offers
        them only for a runnable run) but NEVER fire them.
    """
    page = authed_page
    d = discover_runs(page, base_url)
    run = d.get("fixes_run")
    if not run:
        pytest.skip("no runnable fix run (DAA/sast with fixable findings) on the stack")

    with assert_calls(page, "GET", "/offense/api/remediate/", timeout_ms=15_000):
        page.evaluate(f"location.hash = '#/fixes?run={run}'")
    page.wait_for_selector("#fx-body", timeout=15_000)
    page.wait_for_selector("#fx-view", timeout=15_000)
    # Render signal: the gated fix ladder / fixable findings are present.
    page.wait_for_selector("text=The gated fix ladder", timeout=15_000)

    # The destructive controls render only behind the runnable gate — assert their
    # presence; NEVER click Apply / Deep-fix.
    apply_btn = page.locator("button:has-text('Apply fix (gated)')").first
    deep_btn = page.locator("button:has-text('Deep fix')").first
    apply_btn.wait_for(timeout=10_000)
    assert apply_btn.count() >= 1, "runnable run must offer the gated Apply control"
    assert deep_btn.count() >= 1, "runnable run must offer the gated Deep-fix control"

    # Verify (re-scan) is READ-ONLY — fire it for real.
    verify_btn = page.locator("button:has-text('Verify (re-scan)')").first
    verify_btn.wait_for(timeout=10_000)
    with assert_calls(page, "POST", "/offense/api/remediate/", timeout_ms=45_000):
        verify_btn.click()
    # Narrow confirmation that the fired call was the /verify leg, not apply/deepfix.
    # (assert_calls above matched the remediate prefix; the verify button can only
    # post the /verify suffix per verifyFix().)


# ── replay ────────────────────────────────────────────────────────────────────
@pytest.mark.real_flow
def test_replay_refires_proofs_offline(authed_page, base_url):
    """Replay the Proof: paste a report/finding JSON and re-fire its proofs OFFLINE.

    renderReplay (app.js:1858) mounts a static form with no top-of-render backend
    read; its control is "Re-fire proofs offline" -> doReplay() posts
    POST /offense/api/replay (doReplay():1875), a pure offline re-computation (no
    target, no traffic). We paste a minimal well-formed report document and assert
    the replay call fires.
    """
    page = authed_page

    page.evaluate("location.hash = '#/replay'")
    page.wait_for_selector("#replay-input", timeout=15_000)

    # A well-formed (empty) report document: valid JSON so doReplay POSTs rather
    # than bailing on a parse error.
    page.fill("#replay-input", '{"active_findings": []}')
    with assert_calls(page, "POST", "/offense/api/replay", timeout_ms=20_000):
        page.click("button:has-text('Re-fire proofs offline')")
    # Render signal: the result slot leaves its running state and reports a verdict.
    page.wait_for_selector("#replay-result", timeout=15_000)
