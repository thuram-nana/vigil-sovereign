"""E2E suite for the Fixes screen LOCAL-APPLY affordance (KEY=local-fix-apply).

Waves 1-2 added an only-verified LOCAL fix sink to the Fixes screen: a fixable
finding gains a Download / Apply-to-path affordance IFF its oracle-VERIFIED diff
was PERSISTED on disk (``<run_dir>/fixes/<ref>.patch`` — written by ``deep_fix``
only on a verified result), surfaced to the SPA as
``plan.fixable[].has_verified_diff`` (console/api.py remediate_plan). This suite
drives both halves of that gate through a real Chromium against the live stack
(uiproxy :8770).

  Tier 1 -- the GATE (@assert_gate, deterministic, model-free). The NEGATIVE a
  happy path misses: for a fixable finding with NO persisted verified diff
  (``has_verified_diff == false``) the per-finding SINK host ``#fx-sink-<idx>``
  (app.js fixSinkContent) renders ONLY the honest hint ("Produce a verified fix
  first ...") and NO Download / Apply-to-path controls. This proves a still-
  vulnerable / unverified fix can NEVER present an apply action -- the affordance
  is gated by what was PERSISTED, surfaced as the plan predicate, not by UI state.

  Tier 2 -- the EFFECT (@real_flow). For a finding WITH a persisted verified diff
  the SINK exposes the real controls, and we drive them:
    * "Download verified fix" issues a click/nav-driven GET
      /offense/api/remediate/<run>/<ref>/diff (pure read of the pre-built .patch;
      the backend 404s until a verified diff exists -- server.py _download_fix_diff).
    * "Apply fix to path" with in-place UNCHECKED fires POST
      /offense/api/remediate/<run>/<ref>/apply-local and renders ``applied_paths``
      + the re-verify verdict (CLEARED / STILL PRESENT). COPY mode writes a
      CONFINED fixed copy (a ``<source>-fixed`` sibling under the source's parent
      dir) -- the operator source is never touched (actions.apply_fix_local +
      _safe_apply_dest) -- so it is a safe real_flow, unlike the PR-opening
      autopatch. The destructive in-place path is NEVER driven.

GREEN-WASH SOUNDNESS (helpers.assert_calls WARNING + test_e2e_engage docstring).
The Fixes screen reads GET /offense/api/remediate/<run> at the top of render
(drawFixes app.js:5911) and the run list via runsURL() -> /offense/api/runs;
/api/runs rides the GLOBAL pboxPoll setInterval (app.js:11238) and the plan read
fires on nav itself, so NEITHER is asserted here. Both assertions below are
pinned to the distinct, UNPOLLED per-finding suffixes ``/<ref>/diff`` and
``/<ref>/apply-local`` -- the only setInterval reads in app.js touch
/api/aegis/status, /api/runs, /sovereign/api/snapshot and screen-local non-
remediate refreshers (grepped), so nothing but the click can fire them. Every
run/plan read is done through the page's OWN authenticated fetch (``_discover``),
never via assert_calls on a polled endpoint.

FATAL-2 ISOLATION: this file imports only ``time`` / ``pytest`` / ``helpers``
(playwright arrives lazily through helpers). No ``framework``, ``strix`` or
``vigil_integration`` -- the harness stays a pure network client of :8770.
"""
import time

import pytest

from helpers import OFFENSE_BASE, SESSION_TOKEN_KEY, assert_calls

# Module cache so the (several-second) live fix-target discovery runs once per session.
_DISCOVERED: dict = {}


def _discover(page, base_url: str) -> dict:
    """Probe the live stack (through the browser's own authenticated fetch -- the
    same credentials the SPA sends) for the two finding classes this suite needs:

      gate   -- {run, ref, idx}: a ``runnable`` run with a fixable finding that
                has a stable ``ref`` but NO persisted verified diff
                (has_verified_diff == false) -> its sink must show ONLY the hint.
      effect -- {run, ref, idx, default_dest, source_root}: a ``runnable`` LOCAL
                run (source_root present, not remote_host_only) with a fixable
                finding whose verified diff IS persisted (has_verified_diff ==
                true) -> its sink exposes the real Download/Apply controls. None
                if the stack has none (Tier 2 then skips, never green-washed).

    ``idx`` is the finding's position in ``plan.fixable`` -- EXACTLY the index the
    SPA uses for ``#fx-sink-<idx>`` (drawFixPlan: fixable.map((f, i) => ...)). Pure
    read; bounded to the first ~90 runs.
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
            let gate = null, effect = null;
            for (const r of runs.slice(0, 90)) {
                const id = r.run_id;
                const plan = await j("/offense/api/remediate/" + encodeURIComponent(id));
                if (!plan || !plan.runnable) continue;
                const fixable = plan.fixable || [];
                for (let i = 0; i < fixable.length; i++) {
                    const f = fixable[i];
                    if (!f || !f.ref) continue;            // no ref -> card is a hint, no sink controls either way
                    if (!gate && !f.has_verified_diff) gate = { run: id, ref: f.ref, idx: i };
                    if (!effect && f.has_verified_diff && !plan.remote_host_only && plan.source_root)
                        effect = { run: id, ref: f.ref, idx: i, default_dest: plan.default_dest || "", source_root: plan.source_root };
                }
                if (gate && effect) break;
            }
            return { gate, effect };
        }""",
        [base_url.rstrip("/"), SESSION_TOKEN_KEY],
    )
    _DISCOVERED[key] = result
    return result


def _open_fixes(page, run: str, idx: int):
    """Navigate to the run's Fixes plan and return the Playwright locator for its
    per-finding sink host (#fx-sink-<idx>), waiting until drawFixPlan has rendered.

    Guards the engagement-scoped picker: ``authed_page`` sets no active engagement
    so runsURL() returns the full list and our run loads, but if a scope ever
    filters it out the picker falls back to runs[0] -- we detect that (the <select>
    value != run) and skip rather than assert against the wrong plan.
    """
    page.evaluate(f"location.hash = '#/fixes?run={run}'")
    page.wait_for_selector("#fx-body select", timeout=15_000)
    loaded = page.locator("#fx-body select").first.input_value()
    if loaded != run:
        pytest.skip(
            f"the Fixes picker loaded run {loaded!r}, not the discovered {run!r} "
            "(engagement-scoped run list); cannot assert against the intended plan"
        )
    page.wait_for_selector("text=The gated fix ladder", timeout=15_000)   # drawFixPlan ran
    sink = page.locator(f"#fx-sink-{idx}")
    sink.wait_for(timeout=15_000)
    return sink


def _wait_apply_result(page, idx: int, timeout_ms: int = 120_000) -> str:
    """Poll the per-finding apply-output host (#fx-applyout-<idx>) until it renders
    a TERMINAL state -- the success legend + verdict, or an error legend. CSP-safe
    (polls page.evaluate of a FUNCTION, mirroring test_e2e_engage._wait_live_rendered).
    Raises if nothing terminal renders (the POST fired but the apply silently did
    nothing) rather than letting a blank slot pass."""
    sel = f"#fx-applyout-{idx}"
    terminals = ("CLEARED", "STILL PRESENT", "Fixed copy written to:",
                 "unsafe destination", "drifted", "refused", "failed")
    end = time.time() + timeout_ms / 1000
    while time.time() < end:
        txt = page.evaluate(
            "(s) => { var e = document.querySelector(s); return e ? e.textContent : ''; }", sel
        )
        if txt and any(t in txt for t in terminals):
            return txt
        page.wait_for_timeout(300)
    raise AssertionError(
        f"apply-local produced no result in {sel} within {timeout_ms}ms "
        "(the POST fired but nothing rendered -- a silent failure)"
    )


@pytest.mark.assert_gate
def test_local_apply_affordance_absent_without_verified_diff(authed_page, base_url):
    """Tier 1 GATE: an un-verified fixable finding presents the honest hint and NO
    Download / Apply-to-path control -- the only-verified gate, enforced by the
    persisted-diff predicate (plan.fixable[].has_verified_diff), not UI state."""
    page = authed_page
    d = _discover(page, base_url)
    gate = d.get("gate")
    if not gate:
        pytest.skip("no runnable run with an un-verified fixable finding on the stack")

    sink = _open_fixes(page, gate["run"], gate["idx"])
    sink_text = sink.inner_text()

    # The load-bearing safety message is present ...
    assert "Produce a verified fix first" in sink_text, (
        "an un-verified fix must show the honest 'Produce a verified fix first' hint; "
        f"sink text was: {sink_text!r}"
    )
    # ... and NONE of the apply affordances exist for a still-vulnerable fix.
    assert sink.locator("button:has-text('Download verified fix')").count() == 0, \
        "an un-verified fix must NOT offer a Download control"
    assert sink.locator("button:has-text('Apply fix to path')").count() == 0, \
        "an un-verified fix must NOT offer an Apply-to-path control"
    assert "Apply fix to a local path" not in sink_text, \
        "an un-verified fix must NOT render the local-apply block"
    assert "Oracle-verified fix" not in sink_text, \
        "the verified-fix legend must be absent until a diff is actually verified"


@pytest.mark.real_flow
def test_local_apply_downloads_and_applies_verified_fix(authed_page, base_url):
    """Tier 2 EFFECT: a verified finding's Download anchor targets GET .../diff, and
    Apply-to-path (COPY mode) fires POST .../apply-local and renders applied_paths +
    the deterministic-oracle re-verify verdict. The confined fixed COPY never
    touches the operator source; the destructive in-place path is never driven."""
    page = authed_page
    d = _discover(page, base_url)
    effect = d.get("effect")
    if not effect:
        pytest.skip(
            "no runnable LOCAL run with a PERSISTED verified fix diff on the stack "
            "(seed <run>/fixes/<ref>.patch, or run Deep fix until it reports VERIFIED)"
        )
    run, ref, idx = effect["run"], effect["ref"], effect["idx"]

    # Defense-in-depth: any confirm() dialog (ONLY the in-place path raises one) is
    # DISMISSED, so the destructive in-place apply can never be driven by this test.
    page.on("dialog", lambda dlg: dlg.dismiss())
    page.on("download", lambda dl: None)   # accept + ignore the .patch download

    sink = _open_fixes(page, run, idx)

    # The verified finding exposes the real controls (not the hint).
    assert sink.locator("button:has-text('Download verified fix')").count() >= 1, \
        "a verified fix must offer the Download control"
    assert sink.locator("button:has-text('Apply fix to path')").count() >= 1, \
        "a verified fix must offer the Apply-to-path control"
    assert "Oracle-verified fix" in sink.inner_text(), \
        "a verified fix must render the 'Oracle-verified fix' legend"

    # Encode run/ref EXACTLY as app.js does (OFF + encodeURIComponent) so the
    # substring matches the real request URL regardless of ref punctuation.
    enc = page.evaluate(
        "([r, f]) => ({ run: encodeURIComponent(r), ref: encodeURIComponent(f) })",
        [run, ref],
    )
    diff_frag = f"{OFFENSE_BASE}/api/remediate/{enc['run']}/{enc['ref']}/diff"
    apply_frag = f"{OFFENSE_BASE}/api/remediate/{enc['run']}/{enc['ref']}/apply-local"

    # (a) Download verified fix -> click/nav-driven GET of the pre-built .patch.
    with assert_calls(page, "GET", diff_frag, timeout_ms=20_000):
        sink.locator("button:has-text('Download verified fix')").first.click()

    # (b) Apply fix to path (COPY, in-place UNCHECKED). A fresh, confined dest -- a
    # timestamped <source>-fixed sibling, under the allowlisted source parent dir --
    # avoids the non-empty-dir refusal on re-runs and is never the source itself.
    fresh_dest = effect["default_dest"] + "-e2e-" + str(int(time.time() * 1000))
    sink.locator("input[type=text]").first.fill(fresh_dest)
    with assert_calls(page, "POST", apply_frag, timeout_ms=30_000):
        sink.locator("button:has-text('Apply fix to path')").first.click()

    # (c) The response renders applied_paths + the ZERO-TRUST oracle verdict. The
    # verdict is whatever the deterministic re-run over the WRITTEN tree returns --
    # asserting it RENDERED (CLEARED or STILL PRESENT) proves the re-verify ran; an
    # apply error would render neither "files:" nor a verdict and fail loudly here.
    result = _wait_apply_result(page, idx)
    assert "Fixed copy written to:" in result, \
        f"copy-mode apply must report the written path; got: {result!r}"
    assert "files:" in result, \
        f"apply-local must render applied_paths (files: ...); got: {result!r}"
    assert ("CLEARED" in result or "STILL PRESENT" in result), (
        "apply-local must render the deterministic-oracle re-verify verdict "
        f"(CLEARED / STILL PRESENT); got: {result!r}"
    )
