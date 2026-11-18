"""R5 — Retest (+ the PoC re-fire behind it) and the keyless action trigger.

Retest re-fires each finding's OWN proof against the current tree and marks it Verified-Fixed or Still-Vulnerable:
a sandbox-reproduced FACT re-runs its PoC (``refire_reproduction`` — Verified-Fixed ONLY on positive evidence: every
run completed and none fired; silence is never 'fixed'); a DAA static fact re-runs the deterministic re-scan
(``codescan.verify_finding_cleared``). The trigger reads the dedicated ``redpen-actions`` seam and PRODUCES one
``SecurityJob`` per well-formed marker (it never runs one).
"""
from __future__ import annotations

import json

import pytest

pytest.importorskip("framework", reason="runs in the offense leg alongside the other redpen tests")

from vigil_core import redpen_action_marker  # noqa: E402

from vigil_integration.jobs.redpen_fix import (  # noqa: E402
    REDPEN_FIX_ACTION,
    REDPEN_RETEST_ACTION,
    STILL_VULNERABLE,
    VERIFIED_FIXED,
    build_reproduction_fix_oracle,
    make_redpen_retest_worker,
    redpen_action_jobs_from_seam,
    redpen_retest,
    refire_reproduction,
)
from vigil_integration.live.sandbox_exec import SandboxOutcome, SandboxUnavailable  # noqa: E402
from vigil_integration.redpen import LensCandidate  # noqa: E402

# The R1 recipe type the R3 resolver hands back (only poc_command / fire_markers / fire_mode are read).
_RECIPE = LensCandidate(lens="injection", bug_class="command_injection", channel="process",
                        poc_command="python3 poc.py", fire_markers=("PWNED",))
_FIRE = SandboxOutcome(exit_code=0, stdout="PWNED\n", stderr="")
_CLEAN = SandboxOutcome(exit_code=0, stdout="ok\n", stderr="")
_TIMEOUT = SandboxOutcome(exit_code=None, stdout="", stderr="", timed_out=True)


def _seq(*outcomes):
    """A deterministic fake sandbox returning ``outcomes`` in order (no bwrap, no network)."""
    it = iter(outcomes)
    return lambda cmd: next(it)


def _unavailable(cmd):
    raise SandboxUnavailable("no bwrap")


@pytest.fixture(autouse=True)
def _redpen_on(monkeypatch):
    monkeypatch.setenv("VIGIL_REDPEN_ENABLED", "1")


def _verifier(cleared_map):
    def fake(*, root, ref, max_files=5000):
        return {"ref": ref, "cleared": bool(cleared_map.get(ref)), "reason": ""}
    return fake


# ---- retest verdicts ---------------------------------------------------------------------------------


def test_retest_marks_verified_fixed_and_still_vulnerable():
    verify = _verifier({"F-1": True, "F-2": False})
    out = redpen_retest(["F-1", "F-2"], root="/x", _verify=verify)
    by = {r.ref: r for r in out}
    assert by["F-1"].status == VERIFIED_FIXED and by["F-1"].cleared is True
    assert by["F-2"].status == STILL_VULNERABLE and by["F-2"].cleared is False


def test_retest_is_fail_closed_still_vulnerable_when_rescan_cannot_confirm():
    # a re-scan that returns no `cleared` (e.g. a moved/removed file) is Still-Vulnerable, never a false 'fixed'
    out = redpen_retest(["F-9"], root="/x", _verify=lambda **kw: {"cleared": False, "reason": "moved"})
    assert out[0].status == STILL_VULNERABLE


def test_retest_is_inert_when_flag_off(monkeypatch):
    monkeypatch.delenv("VIGIL_REDPEN_ENABLED", raising=False)
    spy: list = []
    out = redpen_retest(["F-1"], root="/x", _verify=lambda **kw: spy.append(1) or {"cleared": True})
    assert out == [] and spy == []


def test_retest_daa_requires_a_strict_true_cleared():
    # a truthy-but-not-True `cleared` (e.g. the string "no") is NOT positive evidence of a fix
    out = redpen_retest(["F-1"], root="/x", _verify=lambda **kw: {"cleared": "no"})
    assert out[0].status == STILL_VULNERABLE and out[0].detail["proof"] == "daa"


# ---- the PoC re-fire (sandbox-reproduced FACTs) -------------------------------------------------------


def test_refire_reports_still_firing():
    assert refire_reproduction(_RECIPE, workspace="/w", sandbox=_seq(_FIRE, _FIRE))["fired"] is True


def test_refire_reports_cleared_only_when_every_run_completed_clean():
    res = refire_reproduction(_RECIPE, workspace="/w", sandbox=_seq(_CLEAN, _CLEAN))
    assert res["fired"] is False and res["clean_runs"] == res["runs"] == 2


def test_refire_any_fire_is_still_vulnerable():
    # clean then fire: one fire is enough — the defect is still there
    assert refire_reproduction(_RECIPE, workspace="/w", sandbox=_seq(_CLEAN, _FIRE))["fired"] is True


@pytest.mark.parametrize("sandbox,why", [
    (_seq(_CLEAN, _TIMEOUT), "a timed-out run"),
    (_unavailable, "the sandbox is unavailable"),
])
def test_refire_silence_is_not_cleared(sandbox, why):
    # a run that did not complete confirms nothing — never 'cleared' (silence is not evidence)
    assert refire_reproduction(_RECIPE, workspace="/w", sandbox=sandbox)["fired"] is None


def test_refire_a_markerless_recipe_cannot_be_judged():
    recipe = LensCandidate(lens="x", bug_class="y", channel="process", poc_command="true", fire_markers=())
    calls: list = []
    res = refire_reproduction(recipe, workspace="/w", sandbox=lambda c: calls.append(c) or _CLEAN)
    assert res["fired"] is None and calls == []      # never even run: a marker-less 'no fire' proves nothing


def test_reproduction_fix_oracle_reruns_the_poc_in_the_patched_clone():
    seen: list = []

    def sandbox(cmd):
        seen.append(cmd)
        return _CLEAN

    oracle = build_reproduction_fix_oracle(_RECIPE, sandbox=sandbox)
    v = oracle(object(), "/patched/clone")
    assert v.fired is False and seen == ["python3 poc.py", "python3 poc.py"]
    assert build_reproduction_fix_oracle(_RECIPE, sandbox=_unavailable)(object(), "/p").fired is None


def test_retest_reproduction_verified_fixed_vs_still_vulnerable():
    resolver = {("cust_x", "R-1"): _RECIPE, ("cust_x", "R-2"): _RECIPE}.get
    fixed = redpen_retest(["R-1"], root="/x", slug="cust_x", proof_resolver=lambda s, r: resolver((s, r)),
                          sandbox=_seq(_CLEAN, _CLEAN))
    still = redpen_retest(["R-2"], root="/x", slug="cust_x", proof_resolver=lambda s, r: resolver((s, r)),
                          sandbox=_seq(_FIRE, _FIRE))
    assert fixed[0].status == VERIFIED_FIXED and fixed[0].detail["proof"] == "reproduction"
    assert still[0].status == STILL_VULNERABLE


def test_retest_reproduction_unavailable_sandbox_is_not_verified_fixed():
    out = redpen_retest(["R-1"], root="/x", slug="cust_x", proof_resolver=lambda s, r: _RECIPE,
                        sandbox=_unavailable)
    assert out[0].status == STILL_VULNERABLE and out[0].cleared is False
    assert "unavailable" in out[0].detail["reason"]


def test_retest_falls_back_to_daa_when_the_resolver_has_no_recipe():
    daa: list = []
    out = redpen_retest(["F-1"], root="/x", slug="cust_x", proof_resolver=lambda s, r: None,
                        _verify=lambda **kw: daa.append(kw["ref"]) or {"cleared": True})
    assert daa == ["F-1"] and out[0].status == VERIFIED_FIXED and out[0].detail["proof"] == "daa"


# ---- the retest worker -------------------------------------------------------------------------------


def _retest_job(refs, action=REDPEN_RETEST_ACTION):
    from vigil_integration.jobs.model import SecurityJob
    return SecurityJob.normalize(source="api", repo="github.com/o/r", engagement_slug="cust_x",
                                 extra={"redpen_action": action, "finding_refs": list(refs)})


def test_retest_worker_re_fires_each_proof():
    verify = _verifier({"F-1": True, "F-2": False})
    worker = make_redpen_retest_worker(checkout=lambda job: "/root", _verify=verify)
    out = worker(_retest_job(["F-1", "F-2"]))
    assert out["redpen_action"] == REDPEN_RETEST_ACTION and out["enabled"] is True
    statuses = {r["ref"]: r["status"] for r in out["results"]}
    assert statuses == {"F-1": VERIFIED_FIXED, "F-2": STILL_VULNERABLE}


def test_retest_worker_is_inert_when_flag_off(monkeypatch):
    monkeypatch.delenv("VIGIL_REDPEN_ENABLED", raising=False)
    spy: list = []
    worker = make_redpen_retest_worker(checkout=lambda job: spy.append("checkout") or "/root",
                                       _verify=lambda **kw: spy.append("verify") or {"cleared": True})
    out = worker(_retest_job(["F-1"]))
    assert out["enabled"] is False and out["results"] == [] and spy == []


def test_retest_worker_refuses_a_non_retest_job():
    spy: list = []
    worker = make_redpen_retest_worker(checkout=lambda job: spy.append("checkout") or "/root",
                                       _verify=lambda **kw: spy.append("verify") or {"cleared": True})
    with pytest.raises(ValueError):
        worker(_retest_job(["F-1"], action=REDPEN_FIX_ACTION))
    assert spy == []                                   # no checkout, no re-scan for a job that is not a retest


def test_retest_worker_routes_a_reproduced_fact_through_its_poc():
    asked: list = []
    worker = make_redpen_retest_worker(checkout=lambda job: "/root",
                                       proof_resolver=lambda slug, ref: asked.append((slug, ref)) or _RECIPE,
                                       _sandbox=_seq(_CLEAN, _CLEAN))
    out = worker(_retest_job(["R-1"]))
    assert asked == [("cust_x", "R-1")]
    assert out["results"][0]["status"] == VERIFIED_FIXED and out["results"][0]["detail"]["proof"] == "reproduction"


# ---- the keyless sovereign→offense trigger (the redpen-actions seam) ---------------------------------


def _publish(base_dir, marker):
    from vigil_core import REDPEN_ACTION_SEAM_SUBDIR
    seam = base_dir / REDPEN_ACTION_SEAM_SUBDIR
    seam.mkdir(parents=True, exist_ok=True)
    (seam / (marker["redpen_action"] + "-" + marker["nonce"] + ".json")).write_text(
        json.dumps(marker), encoding="utf-8")


def test_trigger_produces_one_job_per_valid_marker(tmp_path):
    _publish(tmp_path, redpen_action_marker(action=REDPEN_FIX_ACTION, slug="cust_x", repo="github.com/o/r",
                                            nonce="n1", finding_ref="F-1"))
    _publish(tmp_path, redpen_action_marker(action=REDPEN_RETEST_ACTION, slug="cust_y", repo="github.com/o/r2",
                                            nonce="n2", finding_refs=["F-2", "F-3"]))
    jobs = redpen_action_jobs_from_seam(str(tmp_path))
    by = {j.extra["redpen_action"]: j for j in jobs}
    assert set(by) == {REDPEN_FIX_ACTION, REDPEN_RETEST_ACTION}
    assert by[REDPEN_FIX_ACTION].slug == "cust_x" and by[REDPEN_FIX_ACTION].extra["finding_ref"] == "F-1"
    assert by[REDPEN_RETEST_ACTION].extra["finding_refs"] == ["F-2", "F-3"]


def test_trigger_skips_a_malformed_marker(tmp_path):
    from vigil_core import REDPEN_ACTION_SEAM_SUBDIR
    seam = tmp_path / REDPEN_ACTION_SEAM_SUBDIR
    seam.mkdir(parents=True)
    (seam / "bad.json").write_text("{not json", encoding="utf-8")
    (seam / "nofix.json").write_text(json.dumps({"redpen_action": "fix", "slug": "s", "repo": "r", "nonce": "n"}),
                                     encoding="utf-8")   # a fix with no finding_ref → skipped
    (seam / "merge.json").write_text(json.dumps({"redpen_action": "merge", "slug": "s", "repo": "r", "nonce": "m",
                                                 "finding_ref": "F-1"}),
                                     encoding="utf-8")   # an unknown action (there is no 'merge') → skipped
    (seam / "noslug.json").write_text(json.dumps({"redpen_action": "retest", "slug": "", "repo": "r", "nonce": "q",
                                                  "finding_ref": "F-1"}),
                                      encoding="utf-8")  # no slug → skipped
    assert redpen_action_jobs_from_seam(str(tmp_path)) == []


def test_trigger_is_inert_when_flag_off(tmp_path, monkeypatch):
    _publish(tmp_path, redpen_action_marker(action=REDPEN_RETEST_ACTION, slug="cust_x", repo="github.com/o/r",
                                            nonce="n1", finding_refs=["F-1"]))
    monkeypatch.delenv("VIGIL_REDPEN_ENABLED", raising=False)
    assert redpen_action_jobs_from_seam(str(tmp_path)) == []
