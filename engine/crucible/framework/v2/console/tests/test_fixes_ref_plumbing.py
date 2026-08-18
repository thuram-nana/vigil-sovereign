"""GAP A (end-to-end) — the Fixes screen gets a REAL finding reference for a fixable finding, and offers
the gated Apply button ONLY when the backend can actually run it.

Two halves, both pinned here against the REAL producer and the REAL consumer:

1. THE REFERENCE. The UI needs a non-empty ``ref`` to address a finding at all. That ``ref`` comes from the
   RENDERED report document's ``check_id``, which the report model used to drop — so no finding was ever
   addressable. These tests drive ``scanner.report.build_report`` over an oracle-confirmed ``ScanReport``
   into a run directory and then call ``api.remediate_plan``. Nothing is hand-written into report.json, so
   the test cannot pass by asserting its own fixture.

2. THE PREDICATE (the honest half). A reference is NOT permission. ``actions.apply_fix`` has its own
   precondition — a codebase (Strix) run, a valid slug, a resolvable ``vigil`` entrypoint and the
   engagement's OWN signed offense spine — and ``remediate_plan`` now returns THE SAME predicate as
   ``runnable``/``why_not``, computed by the ONE shared helper ``actions.fix_precondition``. The UI renders
   the button only when ``runnable`` is true. These tests pin that the two can never drift: for every run
   shape, ``plan["runnable"]`` equals what ``apply_fix`` actually does, and the reason strings are identical.

All writes go to a tmp_path-backed run store (``actions.run_dir`` is monkeypatched), so the suite never
touches the operator's real console runs and leaves nothing behind.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from framework.v2.console import actions, api
from framework.v2.scanner.campaign import ScanReport
from framework.v2.scanner.domxss import DomXssCandidate
from framework.v2.scanner.engine import AuditFinding
from framework.v2.scanner.passive import PassiveFinding
from framework.v2.scanner.report import build_report
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.confirmation import confirm_finding

_RUN_ID = "gapa-checkid-e2e"

#: what ``launch_scan`` actually writes for a plain URL scan — no ``mode``, no ``slug``.
_SCAN_META = {"status": "done", "run_kind": "scan", "target": "http://127.0.0.1:8000/"}
#: a live-target engagement run: it HAS a slug, but no source tree to patch.
_URL_META = {"status": "done", "mode": "url", "slug": "acme", "target": "http://127.0.0.1:8000/"}
#: the only shape the gated apply can ever run on: a codebase (Strix) assessment of a real repo.
_CODEBASE_META = {"status": "done", "mode": "codebase", "slug": "acme", "target": "/home/me/proj"}


@pytest.fixture()
def store(tmp_path, monkeypatch):
    """A tmp_path-backed console run store. Every read/write in this module goes through the patched
    ``actions.run_dir``, so the operator's REAL ``.console/runs`` is never written to."""
    root = tmp_path / "runs"

    def _run_dir(run_id, **_kw):
        return root / str(run_id)

    monkeypatch.setattr(actions, "run_dir", _run_dir)
    return root


def _confirmed_active(check_id: str = "boolean-sqli") -> AuditFinding:
    ctx = FindingContext.from_http_responses(
        {"status": 200, "body": "No results found."},
        {"status": 200, "body": "id=1 name=alice role=user\nid=2 name=bob role=admin"},
        bug_class="boolean_sqli",
        discriminator={"dimensions": ["status", "length", "lexical"]},
    )
    c = confirm_finding(finding={"bug_class": "boolean_sqli"}, context=ctx)
    assert c is not None, "the fixture must be oracle-confirmed or this test proves nothing"
    return AuditFinding(
        check_id=check_id, bug_class="boolean_sqli", insertion_point="query_value:q", param="q",
        endpoint="http://127.0.0.1:8000/search", confidence=c.confidence,
        confirmed_by=c.confirmed_by.value, rationale="rows diverged", oracle_context=ctx.model_dump(mode="json"),
    )


def _write_real_report(run_id: str, *, check_id: str = "boolean-sqli", meta: dict | None = None) -> None:
    """Render a REAL scan report (active fact + passive lead + DOM lead) into the run dir."""
    scan = ScanReport(
        target="http://127.0.0.1:8000/",
        active_findings=[_confirmed_active(check_id)],
        passive_findings=[PassiveFinding(
            check_id="missing-hsts", title="Missing HSTS", severity="Low", confidence="Certain",
            url="http://127.0.0.1:8000/", evidence="no STS header")],
        dom_xss_candidates=[DomXssCandidate(
            source="location.hash", sink="innerHTML", confidence="Firm",
            evidence="el.innerHTML = location.hash")],
    )
    rd = actions.run_dir(run_id)
    rd.mkdir(parents=True, exist_ok=True)
    (rd / "meta.json").write_text(json.dumps(dict(meta if meta is not None else _SCAN_META)),
                                  encoding="utf-8")
    (rd / "report.json").write_text(json.dumps(build_report(scan)), encoding="utf-8")


def _provision_spine(tmp_path, monkeypatch, slug: str = "acme") -> Path:
    """Write the engagement's signed offense spine the gated patch grounds on, and point the console at it."""
    base = tmp_path / "base"
    base.mkdir(exist_ok=True)
    (base / f"{slug}.spine").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("VIGIL_BASE_DIR", str(base))
    return base


def _no_spawn(monkeypatch) -> dict:
    """Make any subprocess spawn observable (and inert) — proof a refusal never shelled the verb."""
    spawned = {"ran": False, "argv": None}

    def _fake(argv, **_kw):
        spawned["ran"] = True
        spawned["argv"] = argv
        raise AssertionError("the gated verb must not be spawned behind a refused precondition")

    monkeypatch.setattr(actions.subprocess, "run", _fake)
    return spawned


# ---------------------------------------------------------------------------------------------------
# 1. THE REFERENCE — a fixable finding is addressable at all
# ---------------------------------------------------------------------------------------------------


def test_fixable_finding_carries_a_non_empty_ref(store) -> None:
    """The end-to-end plumbing proof: real report → remediate_plan → a non-empty, correct ``ref``."""
    _write_real_report(_RUN_ID)
    r = api.remediate_plan(_RUN_ID)
    assert r["fixable_count"] == 1, r
    f = r["fixable"][0]
    # a non-empty ref is what makes the finding addressable at all (without it the UI can only ever
    # offer the CLI fallback, for every finding on every run — the bug this closes)...
    assert f["ref"], "empty ref ⇒ the UI shows the 'no stable finding reference' fallback"
    # ...and it must be the finding's OWN check id (the token `vigil patch --finding-ref` takes)
    assert f["ref"] == "boolean-sqli"
    assert f["bug_class"] == "boolean_sqli"


def test_ref_tracks_the_real_check_id_not_a_constant(store) -> None:
    _write_real_report(_RUN_ID, check_id="m5-fw-git-config")
    assert api.remediate_plan(_RUN_ID)["fixable"][0]["ref"] == "m5-fw-git-config"


def test_leads_are_counted_but_never_offered_as_fixable(store) -> None:
    """The passive-hygiene finding and the DOM-XSS candidate are LEADS: counted, never fixable,
    and they contribute no ``ref`` — a lead must never become clickable-fixable."""
    _write_real_report(_RUN_ID)
    r = api.remediate_plan(_RUN_ID)
    assert r["lead_count"] == 2                       # the passive + the DOM candidate
    assert [f["bug_class"] for f in r["fixable"]] == ["boolean_sqli"]
    assert all(f["bug_class"] != "dom_xss" for f in r["fixable"])
    # and the underlying rendered document gives the leads no reference at all
    doc = json.loads((actions.run_dir(_RUN_ID) / "report.json").read_text(encoding="utf-8"))
    leads = [f for f in doc["findings"] if f["kind"] in ("passive", "dom_xss_candidate")]
    assert len(leads) == 2 and all(f["check_id"] == "" for f in leads)


def test_a_ref_that_apply_fix_would_reject_is_withheld(store) -> None:
    """Fail-closed at the seam: a check id that is not an argv-safe token is NOT handed to the UI, so the
    screen offers the CLI path instead of a button whose only possible answer is 'invalid finding reference'."""
    _write_real_report(_RUN_ID, check_id="../../etc/passwd")
    r = api.remediate_plan(_RUN_ID)
    assert r["fixable_count"] == 1
    assert r["fixable"][0]["ref"] == ""
    assert actions.apply_fix(_RUN_ID, "../../etc/passwd")["error"] == "invalid finding reference"


def test_ref_is_a_token_apply_fix_accepts(store) -> None:
    """The ref the UI hands back must survive ``apply_fix``'s argv-safety validator."""
    _write_real_report(_RUN_ID)
    ref = api.remediate_plan(_RUN_ID)["fixable"][0]["ref"]
    assert actions._valid_finding_ref(ref)
    assert ref and len(ref) <= 200 and not ref.startswith("-") and ".." not in ref
    assert not any(c in ref for c in "/\\ \t\r\n")


# ---------------------------------------------------------------------------------------------------
# 2. THE PREDICATE — the button renders only where the backend can actually proceed
# ---------------------------------------------------------------------------------------------------


def test_plain_scan_run_is_not_runnable_and_says_why(store, monkeypatch) -> None:
    """A plain URL scan (the meta ``launch_scan`` really writes: no engagement slug, no repository) can
    never run the gated ladder. The plan says so, with the SAME words apply_fix refuses with."""
    _write_real_report(_RUN_ID)
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/bin/vigil")
    spawned = _no_spawn(monkeypatch)
    plan = api.remediate_plan(_RUN_ID)
    assert plan["runnable"] is False
    assert "engagement slug" in plan["why_not"]
    out = actions.apply_fix(_RUN_ID, plan["fixable"][0]["ref"])
    assert out["ok"] is False and out["runnable"] is False
    assert out["error"] == plan["why_not"]            # one predicate, one message — no drift
    assert spawned["ran"] is False                    # fail-closed: no spawn behind the gate


def test_live_target_run_is_not_runnable_for_want_of_a_repository(store, monkeypatch) -> None:
    """The next gate down: even a slug-bearing live-target run has no source tree to patch."""
    _write_real_report(_RUN_ID, meta=_URL_META)
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/bin/vigil")
    spawned = _no_spawn(monkeypatch)
    plan = api.remediate_plan(_RUN_ID)
    assert plan["runnable"] is False and "no repository to patch" in plan["why_not"]
    out = actions.apply_fix(_RUN_ID, plan["fixable"][0]["ref"])
    assert out["ok"] is False and out["runnable"] is False and out["error"] == plan["why_not"]
    assert spawned["ran"] is False


def test_codebase_run_without_a_signed_spine_is_not_runnable(store, tmp_path, monkeypatch) -> None:
    """The other half of the same gate: even a codebase run refuses until the engagement's OWN signed
    offense spine exists. The reason must stay accurate and name the remedy."""
    _write_real_report(_RUN_ID, meta=_CODEBASE_META)
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/bin/vigil")
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path / "no-such-base"))
    spawned = _no_spawn(monkeypatch)
    plan = api.remediate_plan(_RUN_ID)
    assert plan["runnable"] is False
    assert "no signed offense spine" in plan["why_not"] and "vigil engage --slug acme" in plan["why_not"]
    out = actions.apply_fix(_RUN_ID, plan["fixable"][0]["ref"])
    assert out["ok"] is False and out["runnable"] is False and out["error"] == plan["why_not"]
    assert spawned["ran"] is False


def test_unresolvable_vigil_entrypoint_is_not_runnable(store, tmp_path, monkeypatch) -> None:
    """No `vigil` entrypoint ⇒ nothing to shell ⇒ no button (the plan says exactly that)."""
    _write_real_report(_RUN_ID, meta=_CODEBASE_META)
    _provision_spine(tmp_path, monkeypatch)
    monkeypatch.setattr(actions, "_vigil_bin", lambda: None)
    plan = api.remediate_plan(_RUN_ID)
    assert plan["runnable"] is False and "not resolvable" in plan["why_not"]
    assert actions.apply_fix(_RUN_ID, "boolean-sqli")["error"] == plan["why_not"]


def test_pending_run_still_carries_the_honest_predicate(store) -> None:
    """A run with no rendered report yet is `pending` — and still says why an apply could not run."""
    plan = api.remediate_plan("gapa-no-such-run")
    assert plan.get("pending") is True and plan["fixable"] == []
    assert plan["runnable"] is False and plan["why_not"]


def test_runnable_true_exactly_when_apply_fix_proceeds(store, tmp_path, monkeypatch) -> None:
    """THE anti-drift proof. A fully provisioned codebase run — valid slug, a repo, a resolvable `vigil`,
    and the signed offense spine — is the ONLY shape that flips ``runnable`` true, and on that shape
    ``apply_fix`` really does shell the gated verb (rather than refusing behind a rendered button)."""
    _write_real_report(_RUN_ID, meta=_CODEBASE_META)
    base = _provision_spine(tmp_path, monkeypatch)
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/bin/vigil")
    plan = api.remediate_plan(_RUN_ID)
    assert plan["runnable"] is True and plan["why_not"] == ""

    captured: dict = {}

    class _P:
        returncode = 0
        stdout = "--- result ---\nstatus         : pr-denied\napplied_paths  : ['app.py']\nremediated     : False\n"
        stderr = ""

    def _fake(argv, **_kw):
        captured["argv"] = argv
        return _P()

    monkeypatch.setattr(actions.subprocess, "run", _fake)
    out = actions.apply_fix(_RUN_ID, plan["fixable"][0]["ref"])
    assert out["runnable"] is True and out["ok"] is True
    argv = captured["argv"]
    assert argv[:2] == ["/bin/vigil", "patch"]
    assert argv[argv.index("--from-spine") + 1] == "acme"
    assert argv[argv.index("--finding-ref") + 1] == "boolean-sqli"
    assert argv[argv.index("--target-repo") + 1] == "/home/me/proj"
    assert argv[argv.index("--base-dir") + 1] == str(base)
    assert "--open-pr" not in argv                    # the console NEVER opens a PR


def test_the_plan_predicate_is_the_apply_predicate_for_every_run_shape(store, tmp_path, monkeypatch) -> None:
    """One helper, two callers: for every run shape the console can produce, the plan's ``runnable`` is
    exactly ``actions.fix_precondition``'s, which is exactly what ``apply_fix`` enforces before spawning."""
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/bin/vigil")
    _provision_spine(tmp_path, monkeypatch)
    for name, meta, expected in (("scan", _SCAN_META, False), ("url", _URL_META, False),
                                 ("codebase", _CODEBASE_META, True)):
        rid = f"{_RUN_ID}-{name}"
        _write_real_report(rid, meta=meta)
        plan = api.remediate_plan(rid)
        pre = actions.fix_precondition(rid)
        assert plan["runnable"] is pre["runnable"] is expected, (name, plan["why_not"])
        assert plan["why_not"] == ("" if expected else pre["why_not"]), name


# ---------------------------------------------------------------------------------------------------
# 3. NO TWO CONTRADICTORY STATEMENTS IN ONE BUNDLE — the ladder, the Manual, the hint and the argv agree
#
# The API ladder and the in-app Manual are ONE click apart in the SAME served bundle (index.html loads
# manual.js AND app.js; uiproxy.BUNDLE_JS copies all three), so fixing a false claim in one and leaving it
# in the other still ships the false claim — which is exactly what happened once here. The truths below are
# therefore asserted over BOTH texts by ``_assert_edit_approval_truth``, from one shared tuple.
# ---------------------------------------------------------------------------------------------------

#: what BOTH the served ladder row and the Manual must say about the edit approval.
_EDIT_APPROVAL_REQUIRED = (
    "up front",                  # the approval is a single UP-FRONT opt-in...
    "no per-file prompt",        # ...so neither path ever prompts per file
    "--apply-edits --approve",   # the argv that ACTUALLY reaches the edit stage (see below)
    "disposable clone",          # where the edits land — never the operator's own tree
    "rejected",                  # ...and without the opt-in every file times out and is REJECTED
)
#: the exact claims that shipped false in earlier rounds and must never come back, in EITHER file.
#: - a per-file approval prompt that no path shows;
#: - `--apply-edits` alone named as the CLI equivalent of the Apply button. It is NOT: --approve is what
#:   maps to operator_present, and without it the gate queues at CLONE (test_codefix_runner.py::
#:   test_unattended_run_cannot_even_clone__the_approval_leg_is_load_bearing proves the run dies there).
_EDIT_APPROVAL_FORBIDDEN = (
    "each file needs your explicit approval",
    "`--apply-edits` on the cli",
    "`--apply-edits` on the command line",
)

_UI_DIR = Path(__file__).resolve().parents[6] / "packages" / "vigil-ui"


def _assert_edit_approval_truth(text: str, where: str) -> None:
    low = text.lower()
    for needle in _EDIT_APPROVAL_REQUIRED:
        assert needle in low, f"{where} must state {needle!r}"
    for banned in _EDIT_APPROVAL_FORBIDDEN:
        assert banned not in low, f"{where} still ships the false claim {banned!r}"


def test_ladder_edit_stage_describes_what_the_console_path_really_does(store, tmp_path, monkeypatch) -> None:
    """The Fixes screen renders the ladder and the Apply button together. The console's argv passes
    ``--apply-edits`` (a blanket, up-front approval of every proposed file) and ``--approve`` (the click
    IS the operator-approval leg the WARDEN gate requires), so the ladder must NOT claim a per-file
    approval prompt this path never shows — NOR name ``--apply-edits`` alone as the CLI equivalent, which
    would send the operator into a run that dies at 'clone-denied'.

    The ladder text and the argv are pinned TOGETHER here: the CLI form the row prints must be the argv the
    button really spawns."""
    edit = next(s for s in api._REMEDIATION_LADDER if s["stage"] == "edit")
    what = edit["what"].lower()
    _assert_edit_approval_truth(what, "the served ladder's edit row")
    assert "timed out" in what or "times out" in what, edit          # the fail-closed default stays stated

    # ...and the argv the console really runs matches that description.
    _write_real_report(_RUN_ID, meta=_CODEBASE_META)
    _provision_spine(tmp_path, monkeypatch)
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/bin/vigil")
    captured: dict = {}

    class _P:
        returncode = 0
        stdout = "status: pr-denied"
        stderr = ""

    monkeypatch.setattr(actions.subprocess, "run",
                        lambda argv, **k: (captured.__setitem__("argv", argv), _P())[1])
    out = actions.apply_fix(_RUN_ID, "boolean-sqli")
    argv = captured["argv"]
    assert "--apply-edits" in argv          # the blanket up-front approval the ladder now states
    assert "--approve" in argv              # the click IS the operator-approval leg (else the gate queues)
    assert "--open-pr" not in argv
    # the CLI form the ladder PRINTS is the argv the button SPAWNS — adjacent flags, in that order.
    i = argv.index("--apply-edits")
    assert argv[i + 1] == "--approve", argv
    assert "--apply-edits --approve" in edit["what"], edit
    # ...and so is the command echoed back to the operator.
    assert "--apply-edits --approve" in out["command"], out["command"]
    # the returned note tells the same story as the screen
    assert "no per-file prompt" in out["note"] and "DISPOSABLE clone" in out["note"]


def test_the_manual_tells_the_same_story_as_the_ladder__both_halves_of_the_bundle_pinned() -> None:
    """The regression this exists for: round 2 fixed the API ladder and left the identical false sentence in
    ``manual.js``, which ships in the SAME bundle (``index.html`` script tags; ``uiproxy.BUNDLE_JS``) and is
    one click away on screen. So the shared truths are asserted over the Manual's Fixes chapter AND the
    served ladder row, and the forbidden claims over each whole file — neither can drift back alone."""
    manual = _UI_DIR / "manual.js"
    index = _UI_DIR / "index.html"
    assert manual.is_file() and index.is_file(), f"the command UI is part of this repo; expected {_UI_DIR}"
    src = manual.read_text(encoding="utf-8")

    # it really ships: the Manual is a script tag in the page AND a member of the proxy's copied bundle.
    assert "manual.js" in index.read_text(encoding="utf-8")
    uiproxy = _UI_DIR.parents[1] / "integration" / "vigil_integration" / "uiproxy.py"
    assert uiproxy.is_file(), uiproxy
    assert '"manual.js"' in uiproxy.read_text(encoding="utf-8")

    chapter = src[src.index('id: "fixes"'):src.index('id: "arming-autofix"')]
    _assert_edit_approval_truth(chapter, "the Manual's Fixes chapter")
    # the ladder row states the same truths (re-asserted here so ONE test failure names the drifted pair)...
    ladder = next(s for s in api._REMEDIATION_LADDER if s["stage"] == "edit")["what"]
    _assert_edit_approval_truth(ladder, "the served ladder's edit row")
    # ...and neither WHOLE file may carry a forbidden claim anywhere else in it.
    for banned in _EDIT_APPROVAL_FORBIDDEN:
        assert banned not in src.lower(), f"manual.js still ships {banned!r}"
        assert banned not in "\n".join(s["what"] for s in api._REMEDIATION_LADDER).lower(), banned


def test_ui_renders_the_button_only_when_the_plan_says_runnable() -> None:
    """The UI half of the same contract, pinned against the shipped app.js: the Apply button is gated on
    ``runnable`` and the not-runnable branch shows the backend's own ``why_not``."""
    app = Path(__file__).resolve().parents[6] / "packages" / "vigil-ui" / "app.js"
    assert app.is_file(), f"the command UI is part of this repo; expected {app}"
    src = app.read_text(encoding="utf-8")
    i = src.index("function fixFindingCard(")
    card = src[i:src.index("function applyFix(", i)]
    assert "runnable" in card and "whyNot" in card, card
    # the button exists in exactly one branch, and that branch is the runnable one
    assert card.count("Apply fix (gated)") == 1
    assert card.index("} else {") < card.index("Apply fix (gated)")
    assert "In-console apply is unavailable for this run: " in card
    # the old, now-false promise is gone
    assert "otherwise it refuses and names exactly what is missing" not in src
