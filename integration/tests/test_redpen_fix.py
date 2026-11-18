"""R5 — Fix this: write → re-review → gated PR (never merge).

The load-bearing control is the pre-PR RE-REVIEW (:func:`verify_before_pr`): a fix PR opens ONLY when the
reproduction cleared, the repo tests passed, AND a Quick Red-Pen of the patch found no new FACT. These tests drive
the orchestration with INJECTED seams (a fake ladder / Quick Red-Pen / fix-PR executor) so no clone/patch/PR/network
happens, and also exercise the REAL ``authorized_fix_pr`` chain (framework grant store, offense leg) through the R5
entry point to prove the ``"pr"`` grant + the signed audit + the never-merge property are wired.
"""
from __future__ import annotations

import contextlib
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("framework.v2.authority.store", reason="the fix-PR grant verify is framework-side (offense leg)")

from vigil_core import AuthorizerKey, TrustRoot, generate_keypair  # noqa: E402
from vigil_core.git_write_grant import GitWriteGrant, sign_git_write_grant  # noqa: E402

from framework.v2.authority.store import save_signed_git_write_grant  # noqa: E402

from vigil_integration.jobs.model import SecurityJob  # noqa: E402
from vigil_integration.jobs.redpen_fix import (  # noqa: E402
    REDPEN_FIX_ACTION,
    RedPenFixResult,
    ReReview,
    make_redpen_fix_worker,
    redpen_fix_this,
    verify_before_pr,
)
from vigil_integration.live.codefix_runner import CodefixConfig  # noqa: E402
from vigil_integration.live.github_write import GitHubWriteError  # noqa: E402

_NOW = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)
_REPO = "github.com/acme/widget"
_SLUG = "cust_deadbeef"
_FINDING = SimpleNamespace(ref="F-001")
_DIFF = "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-bad\n+good\n"


@pytest.fixture(autouse=True)
def _redpen_on(monkeypatch):
    monkeypatch.setenv("VIGIL_REDPEN_ENABLED", "1")


# ---- fakes ------------------------------------------------------------------------------------------


def _pass1(status="verified-no-pr", tests_passed=True, rid="ap-deadbeef01", paths=("app.py",)):
    """A pass-1 (write + pre-PR verify) PatchResult stand-in (duck-typed — the engine only reads attributes)."""
    return SimpleNamespace(status=status, tests_passed=tests_passed, applied_diff=_DIFF,
                           patched_paths=list(paths), remediation_id=rid, opened_pr=False, pr_ref="",
                           remediated=False, reason=status)


def _report(enabled=True, facts=()):
    return SimpleNamespace(enabled=enabled, facts=tuple(facts))


def _ladder(pass1_result):
    """A fake ``autopatch_live``: returns ``pass1_result`` on the pre-PR-verify call (verify_before_pr=True) and a
    PR-opened result on the pinned PR pass (proposed_diff set). Records every call so a test can inspect the diff
    pinned into the PR pass."""
    calls: list = []

    def fake(finding, *, config, client=None, killswitch=None, operator_present=True, verify_oracle=None,
             verify_before_pr=False, proposed_diff="", prefer_deterministic=True, quorum=None, now=None,
             max_fix_attempts=1, **kw):
        calls.append({"verify_before_pr": verify_before_pr, "proposed_diff": proposed_diff,
                      "pr_enabled": getattr(config, "pr_enabled", None)})
        if verify_before_pr:
            return pass1_result
        return SimpleNamespace(status="opened-pr-unverified", opened_pr=True,
                               pr_ref="https://github.com/acme/widget/pull/7", remediated=False,
                               applied_diff=proposed_diff, patched_paths=["app.py"], remediation_id="ap-pr")

    return fake, calls


def _fake_fix_pr(opened=True, record=None):
    """A fake ``authorized_fix_pr`` that drives its injected ``_autopatch`` (so the pinned-diff path runs) and
    records that it was reached — the spine of the 'opens only after the re-review passes' assertion."""
    def fake(*, slug, trust_root, repo, finding, config, audit, quorum=None, verify_oracle=None, client=None,
             killswitch=None, now=None, grant_path=None, epoch_path=None, _autopatch=None, **kw):
        if record is not None:
            record.append({"slug": slug, "repo": repo})
        res = _autopatch(finding, config=config, client=client, killswitch=killswitch, quorum=quorum,
                         verify_oracle=verify_oracle) if _autopatch is not None else None
        audit({"action": "github_pr", "slug": slug, "status": getattr(res, "status", "")})
        return res if res is not None else SimpleNamespace(status="opened-pr", opened_pr=opened, pr_ref="x",
                                                           remediated=False)
    return fake


def _cfg(tmp_path):
    return CodefixConfig(target_repo=str(tmp_path / "clone"), base_dir=str(tmp_path), github_token="t")


def _run(tmp_path, pass1_result, *, report, fix_pr, fix_calls=None, locate=None, **over):
    ladder, lcalls = _ladder(pass1_result)
    clone = tmp_path / "patched"
    clone.mkdir(exist_ok=True)
    res = redpen_fix_this(
        _FINDING, config=_cfg(tmp_path), trust_root=object(), repo=_REPO, slug=_SLUG,
        audit=(over.pop("audit", None) or (lambda r: None)), reviewer=object(), signers=[("owner", "k")],
        _autopatch=ladder, _run_redpen=lambda **kw: report, _fix_pr=fix_pr,
        _build_oracle=lambda ref: object(),
        _locate_clone=(locate if locate is not None else (lambda cfg, rid: str(clone))), **over)
    return res, lcalls


# ---- the re-review gate (unit) ----------------------------------------------------------------------


def test_verify_before_pr_passes_when_cleared_tests_pass_no_new_fact(tmp_path):
    clone = tmp_path / "c"; clone.mkdir()
    rv = verify_before_pr(_pass1(), patched_clone=str(clone), changed_paths=["app.py"], reviewer=object(),
                          engagement_slug=_SLUG, signers=[("owner", "k")], run_redpen=lambda **kw: _report())
    assert isinstance(rv, ReReview) and rv.ok and rv.reproduction_cleared and rv.tests_passed and rv.new_facts == 0


def test_verify_before_pr_refuses_when_reproduction_still_fires(tmp_path):
    rv = verify_before_pr(_pass1(status="verify-still-vulnerable"), patched_clone=str(tmp_path), changed_paths=["x"],
                          reviewer=object(), engagement_slug=_SLUG, signers=[], run_redpen=lambda **kw: _report())
    assert not rv.ok and not rv.reproduction_cleared


def test_verify_before_pr_refuses_when_suite_fails(tmp_path):
    rv = verify_before_pr(_pass1(tests_passed=False), patched_clone=str(tmp_path), changed_paths=["x"],
                          reviewer=object(), engagement_slug=_SLUG, signers=[], run_redpen=lambda **kw: _report())
    assert not rv.ok and rv.reproduction_cleared and not rv.tests_passed


def test_verify_before_pr_refuses_when_suite_was_skipped(tmp_path):
    # tests_passed=None (the suite never ran — e.g. no offline dep cache) is NOT a pass: only a strict True is
    rv = verify_before_pr(_pass1(tests_passed=None), patched_clone=str(tmp_path), changed_paths=["x"],
                          reviewer=object(), engagement_slug=_SLUG, signers=[], run_redpen=lambda **kw: _report())
    assert not rv.ok and not rv.tests_passed


def test_verify_before_pr_refuses_on_a_new_fact(tmp_path):
    rv = verify_before_pr(_pass1(), patched_clone=str(tmp_path), changed_paths=["x"], reviewer=object(),
                          engagement_slug=_SLUG, signers=[],
                          run_redpen=lambda **kw: _report(facts=(SimpleNamespace(bug_class="xss"),)))
    assert not rv.ok and rv.new_facts == 1


def test_verify_before_pr_fails_closed_when_quick_redpen_disabled(tmp_path):
    rv = verify_before_pr(_pass1(), patched_clone=str(tmp_path), changed_paths=["x"], reviewer=object(),
                          engagement_slug=_SLUG, signers=[], run_redpen=lambda **kw: _report(enabled=False))
    assert not rv.ok and "disabled" in rv.reason


# ---- the orchestration (fix opens ONLY after the re-review passes) ----------------------------------


def test_fix_opens_pr_only_after_review_passes(tmp_path):
    reached: list = []
    res, _ = _run(tmp_path, _pass1(), report=_report(), fix_pr=_fake_fix_pr(record=reached))
    assert res.enabled and res.opened_pr and res.review.ok
    assert reached == [{"slug": _SLUG, "repo": _REPO}]   # the fix-PR executor WAS reached


@pytest.mark.parametrize("pass1,report,why", [
    (_pass1(status="verify-still-vulnerable"), _report(), "reproduction"),
    (_pass1(tests_passed=False), _report(), "tests"),
    (_pass1(), _report(facts=(SimpleNamespace(bug_class="sqli"),)), "new fact"),
])
def test_review_failure_blocks_the_pr(tmp_path, pass1, report, why):
    reached: list = []
    res, _ = _run(tmp_path, pass1, report=report, fix_pr=_fake_fix_pr(record=reached))
    assert res.enabled and not res.opened_pr and not res.review.ok   # NO PR
    assert reached == []                                             # the fix-PR executor was NEVER reached


def test_clone_unavailable_refuses_the_pr(tmp_path):
    reached: list = []
    res, _ = _run(tmp_path, _pass1(), report=_report(), fix_pr=_fake_fix_pr(record=reached),
                  locate=lambda cfg, rid: None)
    assert res.enabled and not res.opened_pr and reached == []


def test_pass1_writes_without_the_pr_leg_and_only_pass2_enables_it(tmp_path):
    # pass 1 (write + pre-PR verify) must never carry an enabled PR leg; only the gated pass 2 turns it on
    _res, lcalls = _run(tmp_path, _pass1(), report=_report(), fix_pr=_fake_fix_pr())
    write = [c for c in lcalls if c["verify_before_pr"]]
    pr = [c for c in lcalls if not c["verify_before_pr"]]
    assert len(write) == 1 and write[0]["pr_enabled"] is False
    assert len(pr) == 1 and pr[0]["pr_enabled"] is True


def test_the_pr_pass_opens_the_exact_reviewed_diff(tmp_path):
    """Soundness: the diff pinned into the PR pass is the one the re-review approved (reviewed == opened)."""
    res, lcalls = _run(tmp_path, _pass1(), report=_report(), fix_pr=_fake_fix_pr())
    pr_pass = [c for c in lcalls if not c["verify_before_pr"]]
    assert res.opened_pr and len(pr_pass) == 1 and pr_pass[0]["proposed_diff"] == _DIFF


# ---- inert when the master flag is off (byte-identical) ---------------------------------------------


def test_inert_when_flag_off(tmp_path, monkeypatch):
    monkeypatch.delenv("VIGIL_REDPEN_ENABLED", raising=False)
    spy: list = []

    def never(*a, **k):
        spy.append(1)
        raise AssertionError("must not be reached when the flag is off")

    res = redpen_fix_this(_FINDING, config=_cfg(tmp_path), trust_root=object(), repo=_REPO, slug=_SLUG,
                          audit=never, reviewer=object(), signers=[], _autopatch=never, _run_redpen=never,
                          _fix_pr=never, _build_oracle=never, _locate_clone=never)
    assert res.enabled is False and res.opened_pr is False and spy == []


# ---- the REAL authorized_fix_pr chain through the R5 entry point ------------------------------------


def _provision_pr_grant(tmp_path, kp, *, allow_pr=True, slug=_SLUG, repo=_REPO):
    g = GitWriteGrant(engagement_slug=slug, repo=repo, grant_id="g1", epoch=1,
                      issued_at=_NOW - timedelta(hours=1), not_before=_NOW - timedelta(hours=1),
                      not_after=_NOW + timedelta(hours=1), allow_comment=False, allow_pr=allow_pr, revoked=False)
    save_signed_git_write_grant(sign_git_write_grant(g, {"owner": kp.private_key_b64}),
                                path=tmp_path / "grant.json")


def _owner_root():
    kp = generate_keypair()
    return kp, TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=kp.public_key_b64)])


def _run_real(tmp_path, tr, *, audit, **over):
    ladder, _ = _ladder(_pass1())
    clone = tmp_path / "patched"; clone.mkdir(exist_ok=True)
    return redpen_fix_this(
        _FINDING, config=_cfg(tmp_path), trust_root=tr, repo=_REPO, slug=_SLUG, audit=audit, reviewer=object(),
        signers=[("owner", "k")], now=_NOW, grant_path=tmp_path / "grant.json", epoch_path=tmp_path / "epoch",
        remote_of=lambda *a, **k: "https://github.com/acme/widget.git",   # origin IS the granted repo
        _autopatch=ladder, _run_redpen=lambda **kw: _report(), _build_oracle=lambda ref: object(),
        _locate_clone=lambda cfg, rid: str(clone), **over)


def test_real_chain_opens_pr_and_emits_signed_audit_never_merges(tmp_path):
    kp, tr = _owner_root()
    _provision_pr_grant(tmp_path, kp)
    recs: list = []
    res = _run_real(tmp_path, tr, audit=recs.append)
    assert res.opened_pr and res.status == "opened-pr-unverified"     # a PR opened — and never 'merged'
    assert res.status != "merged" and "merge" not in res.status
    assert len(recs) == 1 and recs[0]["action"] == "github_pr"       # the signed audit record was emitted


def test_real_chain_refuses_the_fix_without_a_pr_grant(tmp_path):
    _kp, tr = _owner_root()                       # NO grant provisioned
    recs: list = []
    with pytest.raises(GitHubWriteError):
        _run_real(tmp_path, tr, audit=recs.append)
    assert recs == []                             # nothing audited on a refused fix


def test_real_chain_refuses_when_only_comment_granted(tmp_path):
    kp, tr = _owner_root()
    _provision_pr_grant(tmp_path, kp, allow_pr=False)   # a "comment" grant, not "pr"
    with pytest.raises(GitHubWriteError):
        _run_real(tmp_path, tr, audit=lambda r: None)


# ---- the worker runs the fix ONLY on an explicit fix job -------------------------------------------


def _job(action=REDPEN_FIX_ACTION, ref="F-001"):
    extra = {"redpen_action": action}
    if ref:
        extra["finding_ref"] = ref
    return SecurityJob.normalize(source="api", repo=_REPO, engagement_slug=_SLUG, extra=extra)


def test_worker_runs_fix_and_pins_grant_model(tmp_path, monkeypatch):
    seen: dict = {}

    def fake_fix_this(finding, *, config, **kw):
        seen["model"] = config.model
        seen["repo"] = kw.get("repo")
        from vigil_integration.jobs.redpen_fix import RedPenFixResult, ReReview
        return RedPenFixResult(enabled=True, opened_pr=True, status="opened-pr-unverified",
                               review=ReReview(ok=True, reproduction_cleared=True, tests_passed=True))

    worker = make_redpen_fix_worker(
        spine_base_dir=str(tmp_path), checkout=lambda job: str(tmp_path / "root"),
        codefix_config=_cfg(tmp_path), trust_root=object(), reviewer=object(), signers=[("owner", "k")],
        audit=lambda r: None, model="grant-model-x", _fix_this=fake_fix_this,
        _from_spine=lambda **kw: _FINDING)
    out = worker(_job())
    assert out["redpen_action"] == REDPEN_FIX_ACTION and out["opened_pr"] is True
    assert seen["model"] == "grant-model-x" and seen["repo"] == _REPO   # grant model pinned onto the config


def _scope_worker(tmp_path, *, grant_scope, fix_this, model=None):
    return make_redpen_fix_worker(
        spine_base_dir=str(tmp_path), checkout=lambda job: str(tmp_path / "root"), codefix_config=_cfg(tmp_path),
        trust_root=object(), reviewer=object(), signers=[("owner", "k")], audit=lambda r: None, model=model,
        grant_scope=grant_scope, _fix_this=fix_this, _from_spine=lambda **kw: _FINDING)


def test_worker_runs_the_fix_inside_the_model_grant_scope(tmp_path):
    # M1c-2b: the coder's model calls are routed through the gateway on the job's grant ONLY while the scope is
    # active — so the whole fix (write + re-review + PR pass) must run inside it.
    events: list = []

    @contextlib.contextmanager
    def scope_for(job):
        events.append(("enter", job.slug))
        try:
            yield
        finally:
            events.append(("exit", job.slug))

    def fake_fix_this(finding, *, config, **kw):
        events.append(("fix", config.model))
        return RedPenFixResult(enabled=True)

    _scope_worker(tmp_path, grant_scope=scope_for, fix_this=fake_fix_this, model="grant-model-x")(_job())
    assert events == [("enter", _SLUG), ("fix", "grant-model-x"), ("exit", _SLUG)]


def test_worker_resolves_the_grant_model_inside_the_scope(tmp_path, monkeypatch):
    # no explicit model: the metered grant scope's model (resolved by codefix_runner._metered_model) is pinned —
    # and it must be read INSIDE the scope, where the grant publishes it
    import vigil_integration.live.codefix_runner as cr
    state = {"in_scope": False}

    @contextlib.contextmanager
    def scope_for(job):
        state["in_scope"] = True
        try:
            yield
        finally:
            state["in_scope"] = False

    monkeypatch.setattr(cr, "_metered_model", lambda default: "grant-model-y" if state["in_scope"] else default)
    seen: dict = {}

    def fake_fix_this(finding, *, config, **kw):
        seen["model"] = config.model
        return RedPenFixResult(enabled=True)

    _scope_worker(tmp_path, grant_scope=scope_for, fix_this=fake_fix_this)(_job())
    assert seen["model"] == "grant-model-y"


def test_worker_unmetered_keeps_the_configured_model(tmp_path):
    seen: dict = {}

    def fake_fix_this(finding, *, config, **kw):
        seen["model"] = config.model
        return RedPenFixResult(enabled=True)

    _scope_worker(tmp_path, grant_scope=None, fix_this=fake_fix_this)(_job())
    assert seen["model"] == _cfg(tmp_path).model      # no grant, no scope ⇒ byte-identical to the configured model


def test_worker_refuses_a_fix_job_with_no_finding_ref(tmp_path):
    worker = make_redpen_fix_worker(
        spine_base_dir=str(tmp_path), checkout=lambda job: str(tmp_path), codefix_config=_cfg(tmp_path),
        trust_root=object(), reviewer=object(), signers=[], audit=lambda r: None,
        _fix_this=lambda *a, **k: None, _from_spine=lambda **kw: _FINDING)
    with pytest.raises(GitHubWriteError):
        worker(_job(ref=""))


def test_fix_worker_runs_only_on_an_explicit_fix_action(tmp_path):
    # Fix only on an explicit action: a retest job (or any non-fix job) reaching the fix worker is refused
    # BEFORE any checkout, spine rebuild or fix — there is no implicit / automatic fix.
    spy: list = []
    worker = make_redpen_fix_worker(
        spine_base_dir=str(tmp_path), checkout=lambda job: spy.append("checkout") or str(tmp_path),
        codefix_config=_cfg(tmp_path), trust_root=object(), reviewer=object(), signers=[], audit=lambda r: None,
        _fix_this=lambda *a, **k: spy.append("fix"), _from_spine=lambda **kw: spy.append("spine"))
    with pytest.raises(ValueError):
        worker(_job(action="retest"))
    assert spy == []


def _capture_oracle_worker(tmp_path, resolver, sandbox=None):
    seen: dict = {}

    def fake_fix_this(finding, *, verify_oracle=None, **kw):
        seen["oracle"] = verify_oracle
        from vigil_integration.jobs.redpen_fix import RedPenFixResult
        return RedPenFixResult(enabled=True)

    worker = make_redpen_fix_worker(
        spine_base_dir=str(tmp_path), checkout=lambda job: str(tmp_path), codefix_config=_cfg(tmp_path),
        trust_root=object(), reviewer=object(), signers=[], audit=lambda r: None, proof_resolver=resolver,
        _repro_sandbox=sandbox, _fix_this=fake_fix_this, _from_spine=lambda **kw: _FINDING)
    return worker, seen


def test_worker_uses_the_poc_refire_for_a_sandbox_reproduced_fact(tmp_path):
    from vigil_integration.live.sandbox_exec import SandboxOutcome
    from vigil_integration.redpen import LensCandidate
    recipe = LensCandidate(lens="injection", bug_class="command_injection", channel="process",
                           poc_command="python3 poc.py", fire_markers=("PWNED",))
    asked: list = []
    worker, seen = _capture_oracle_worker(
        tmp_path, lambda slug, ref: asked.append((slug, ref)) or recipe,
        sandbox=lambda cmd: SandboxOutcome(exit_code=0, stdout="PWNED", stderr=""))
    out = worker(_job())
    assert asked == [(_SLUG, "F-001")] and out["proof"] == "reproduction"
    # the oracle handed to the fix re-fires THIS finding's PoC — here it still fires ⇒ never 'cleared'
    assert seen["oracle"] is not None and seen["oracle"](object(), str(tmp_path)).fired is True


def test_worker_keeps_the_daa_oracle_for_a_static_fact(tmp_path):
    worker, seen = _capture_oracle_worker(tmp_path, lambda slug, ref: None)
    out = worker(_job())
    assert out["proof"] == "daa" and seen["oracle"] is None   # redpen_fix_this then builds the DAA oracle


# ---- end-to-end over the REAL ladder (real repo, real DAA finding, real deterministic fix) -----------
# The fixture HAS the property: a real md5 weak-hash that the real DAA rule flags and the real key-free fixer
# repairs. Only the Quick Red-Pen reviewer and the PR executor are injected (no model, no GitHub).

_real = pytest.mark.skipif(not (shutil.which("bwrap") and shutil.which("git")),
                           reason="needs bwrap + git for the real sandbox ladder")
_WEAK_REF = "DAA-WEAK-HASH~c3ZjL2NvbmZpZy5weQ~L6"   # svc/config.py:6


def _weak_hash_repo(tmp_path):
    r = tmp_path / "repo"; (r / "svc").mkdir(parents=True)
    (r / "svc" / "config.py").write_text(
        "import hashlib\n\n\ndef fingerprint(pw):\n    # weak hash\n    return hashlib.md5(pw.encode()).hexdigest()\n",
        encoding="utf-8")
    subprocess.run(["git", "-C", str(r), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(r), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(r), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "i"],
                   check=True)
    return r


def _real_ladder_fix(tmp_path, *, require_tests):
    from vigil_integration.remediation.buildsys import detect_build_plan
    from vigil_integration.remediation.triage import TriageFinding
    repo = _weak_hash_repo(tmp_path)
    finding = TriageFinding(ref=_WEAK_REF, bug_class="Weak Cryptography", severity="Medium",
                            target="svc/config.py:6", confirmed=True, evidence_ref="sha256:demo",
                            target_repo=str(repo), source="daa:DAA-WEAK-HASH")
    cfg = CodefixConfig(target_repo=str(repo), base_dir=str(tmp_path / "b"),
                        build_cmd=detect_build_plan(str(repo)).build_cmd, apply_edits=True, model="x")
    reviewed: dict = {}

    def quick_redpen(*, checkout_path, changed_paths, **kw):
        reviewed["clone"] = checkout_path
        reviewed["paths"] = tuple(changed_paths)
        reviewed["patched_src"] = (Path(checkout_path) / "svc" / "config.py").read_text(encoding="utf-8")
        return _report()

    reached: list = []
    res = redpen_fix_this(finding, config=cfg, trust_root=object(), repo=_REPO, slug=_SLUG, audit=lambda r: None,
                          reviewer=object(), signers=[("owner", "k")], require_tests=require_tests,
                          _run_redpen=quick_redpen, _fix_pr=_fake_fix_pr(record=reached))
    return res, reviewed, reached, cfg


@_real
def test_real_ladder_rereviews_the_actual_patched_clone_and_still_needs_the_quorum(tmp_path):
    res, reviewed, reached, cfg = _real_ladder_fix(tmp_path, require_tests=False)
    # the clone the Quick Red-Pen reviewed is the REAL patched sandbox clone autopatch_live wrote (not the original)
    assert Path(reviewed["clone"]).parent == Path(cfg.base_dir) and Path(reviewed["clone"]).name.startswith("codefix-")
    assert "sha256" in reviewed["patched_src"] and "md5" not in reviewed["patched_src"]
    assert reviewed["paths"] == ("svc/config.py",)
    assert res.review.ok and reached == [{"slug": _SLUG, "repo": _REPO}]
    assert "not required" in res.review.reason       # honest: the suite was not run, so the reason never claims it
    # the PR pass re-applied + re-built the PINNED reviewed diff (it got past propose/clone/edit/build) and then the
    # REAL ladder's m-of-n destruction quorum refused it — no quorum provisioned ⇒ no PR, even after the re-review
    assert res.status == "pr-quorum-denied" and res.opened_pr is False


@_real
def test_real_ladder_refuses_when_the_suite_never_ran(tmp_path):
    # only a compile floor is configured (no real test suite) ⇒ tests_passed is None ⇒ the default re-review refuses
    res, reviewed, reached, _cfg_ = _real_ladder_fix(tmp_path, require_tests=True)
    assert res.review is not None and not res.review.ok and res.review.reproduction_cleared
    assert reached == [] and not res.opened_pr and reviewed == {}   # never reached the Quick Red-Pen or the PR


def test_worker_is_inert_when_flag_off(tmp_path, monkeypatch):
    monkeypatch.delenv("VIGIL_REDPEN_ENABLED", raising=False)
    spy: list = []
    worker = make_redpen_fix_worker(
        spine_base_dir=str(tmp_path), checkout=lambda job: spy.append("checkout") or str(tmp_path),
        codefix_config=_cfg(tmp_path), trust_root=object(), reviewer=object(), signers=[], audit=lambda r: None,
        _fix_this=lambda *a, **k: spy.append("fix"), _from_spine=lambda **kw: spy.append("spine"))
    out = worker(_job())
    assert out["enabled"] is False and spy == []    # no checkout, no spine rebuild, no fix
