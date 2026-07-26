"""LAP-1 — the live auto-patch runner (non-destructive core). Proven END-TO-END against a REAL local git
repo: a confirmed finding + a (fake) coder's real unified diff → clone → apply-in-sandbox, with the
destructive PR leg gated OFF. The sovereign invariants (confirmed-FACT-only, edit approval opt-in, PR
never opens) are asserted, and the SOURCE repo is never modified (we operate on a disposable clone).
"""
from __future__ import annotations

import os
import subprocess
import sys

import pytest

from vigil_integration.live.codefix_runner import CodefixConfig, autopatch_live
from vigil_integration.remediation.triage import TriageFinding

_VULN = 'def q(u):\n    return "SELECT * FROM t WHERE id=" + u\n'
_FIXED = 'def q(u):\n    return "SELECT * FROM t WHERE id=%s", (u,)\n'


def _git(*args, cwd):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=False)


@pytest.fixture
def repo_and_diff(tmp_path):
    """A real git repo with a vulnerable file, plus a git-generated unified diff that fixes it (guaranteed
    to apply). Returns (repo_path, diff_text)."""
    repo = tmp_path / "app"
    repo.mkdir()
    _git("init", "-q", cwd=repo)
    _git("config", "user.email", "t@t", cwd=repo)
    _git("config", "user.name", "t", cwd=repo)
    (repo / "app.py").write_text(_VULN, encoding="utf-8")
    _git("add", "app.py", cwd=repo)
    _git("commit", "-q", "-m", "init", cwd=repo)
    (repo / "app.py").write_text(_FIXED, encoding="utf-8")           # make the fix
    diff = _git("diff", cwd=repo).stdout                              # capture the exact applicable diff
    _git("checkout", "--", "app.py", cwd=repo)                        # revert — source stays vulnerable
    assert (repo / "app.py").read_text() == _VULN
    return str(repo), diff


class _FakeClient:
    """Stands in for anthropic.Anthropic — messages.create returns a fixed unified diff."""
    def __init__(self, diff):
        self._diff = diff
        self.messages = self

    def create(self, **_kw):
        return {"content": self._diff}


def _fact(repo, ref="sqli-1"):
    return TriageFinding(ref=ref, title="SQL injection", bug_class="sqli", severity="high",
                         target="app.py:2", confirmed=True, evidence_ref="cert:abc123",
                         target_repo=repo)


def _lead(repo):
    return TriageFinding(ref="lead-1", title="maybe", bug_class="xss", severity="low",
                         target="app.py:2", confirmed=False)


def _cfg(repo, tmp_path, **kw):
    return CodefixConfig(target_repo=repo, base_dir=str(tmp_path / "work"), **kw)


def _workdir(base_dir, rid):
    return os.path.join(base_dir, "codefix-" + rid)


def test_end_to_end_applies_fix_in_clone_but_never_opens_pr(repo_and_diff, tmp_path):
    repo, diff = repo_and_diff
    cfg = _cfg(repo, tmp_path, apply_edits=True)
    res = autopatch_live(_fact(repo), config=cfg, client=_FakeClient(diff))
    # the loop reached the PR gate and it DENIED (destructive, no m-of-n authority wired) — no PR opened
    assert res.opened_pr is False
    assert res.status == "pr-denied", res.status
    assert res.patched_paths == ["app.py"]
    # the fix was really applied to the disposable CLONE...
    wd = _workdir(cfg.base_dir, res.remediation_id)
    assert os.path.isfile(os.path.join(wd, "app.py"))
    assert "%s" in open(os.path.join(wd, "app.py"), encoding="utf-8").read()
    # ...and the SOURCE repo is untouched (still vulnerable)
    assert open(os.path.join(repo, "app.py"), encoding="utf-8").read() == _VULN
    # the ladder shows the gated stages
    stages = [(s.stage, s.outcome) for s in res.steps]
    assert ("clone-exec", "ok") in stages and ("build-exec", "ok") in stages
    assert any(s.stage == "pr-gate" and s.outcome == "deny" for s in res.steps)


def test_edits_off_by_default_reject_the_patch(repo_and_diff, tmp_path):
    repo, diff = repo_and_diff
    cfg = _cfg(repo, tmp_path)   # apply_edits defaults False → every edit times out (REJECT)
    res = autopatch_live(_fact(repo), config=cfg, client=_FakeClient(diff))
    assert res.status == "no-edits-approved" and res.opened_pr is False
    assert res.patched_paths == []


def test_a_lead_is_refused(repo_and_diff, tmp_path):
    repo, diff = repo_and_diff
    res = autopatch_live(_lead(repo), config=_cfg(repo, tmp_path, apply_edits=True), client=_FakeClient(diff))
    assert res.status == "refused-not-confirmed" and res.opened_pr is False


def test_no_coder_yields_no_patch(repo_and_diff, tmp_path, monkeypatch):
    repo, _diff = repo_and_diff
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    res = autopatch_live(_fact(repo), config=_cfg(repo, tmp_path, apply_edits=True), client=None)
    assert res.status == "no-patch-proposed" and res.opened_pr is False


def test_remediated_never_true_without_pr(repo_and_diff, tmp_path):
    # 'remediated' is type-enforced (needs opened_pr AND a signed evidence_ref); LAP-1 opens no PR, so it
    # can never be marked remediated — the whole point of the off-by-default destructive leg.
    repo, diff = repo_and_diff
    res = autopatch_live(_fact(repo), config=_cfg(repo, tmp_path, apply_edits=True), client=_FakeClient(diff))
    assert res.remediated is False and not res.evidence_ref


def test_runner_imports_no_offense_or_sovereign_engine():
    # order-independent: a FRESH interpreter imports only the runner, then checks sys.modules — so another
    # test importing framework first can never falsely pass/fail this.
    # Inherit the parent's env/PYTHONPATH (legit deps like vigil_gateway must resolve); we only assert the
    # runner pulls no framework/strix/sigil — a fresh interpreter so test import order can't mask it.
    code = ("import sys; import vigil_integration.live.codefix_runner;"
            "leaked=[m for m in sys.modules if m.split('.')[0] in ('framework','strix','sigil')];"
            "print('LEAK' if leaked else 'CLEAN', leaked)")
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=False)
    assert r.returncode == 0, r.stderr
    assert r.stdout.startswith("CLEAN"), f"live runner pulled an engine: {r.stdout} {r.stderr}"


def test_unsafe_remediation_id_refuses_workdir_escape(repo_and_diff, tmp_path):
    # HOLD-1: the clone workdir is built from remediation_id; a '../' id must NOT escape base_dir. The
    # shipped autopatch_live never passes one (it derives a slash-free digest), but clone() guards at the sink.
    from vigil_integration.live.codefix_runner import CodefixSession, _safe_workdir

    repo, _diff = repo_and_diff
    base = str(tmp_path / "work")
    assert _safe_workdir(base, "ap-abc123") is not None
    for bad in ["../escape", "..", "a/b", "a\\b", "", ".", "x/../../y", "a\x00b"]:
        assert _safe_workdir(base, bad) is None, bad
    sess = CodefixSession(CodefixConfig(target_repo=repo, base_dir=base))

    class _Req:
        remediation_id = "../../../../tmp/ESCAPE_SHOULD_NOT_HAPPEN"
        target_repo = repo
        fix_branch = "vigil-fix/x"
    res = sess.clone(_Req())
    assert res.ok is False and "unsafe remediation id" in res.reason
    assert not os.path.exists("/tmp/ESCAPE_SHOULD_NOT_HAPPEN")


def test_clone_refuses_flag_and_transport_helper_repos(tmp_path):
    # HOLD-2: a repo that is a git-flag (leading '-') or a transport-helper (ext::/fd:: → command exec) is
    # refused BEFORE git runs.
    from vigil_integration.live.codefix_runner import CodefixSession, _repo_ok

    for bad in ["--upload-pack=touch /tmp/x", "-x", "ext::sh -c 'touch /tmp/x'", "fd::7", ""]:
        ok, _why = _repo_ok(bad)
        assert ok is False, bad
    for good in ["/local/path/repo", "https://github.com/o/r.git", "git@github.com:o/r.git", "ssh://h/r"]:
        assert _repo_ok(good)[0] is True, good
    sess = CodefixSession(CodefixConfig(target_repo="ext::sh -c 'touch /tmp/EVIL_LAP1'", base_dir=str(tmp_path)))

    class _Req:
        remediation_id = "ap-x"
        target_repo = "ext::sh -c 'touch /tmp/EVIL_LAP1'"
        fix_branch = "vigil-fix/x"
    res = sess.clone(_Req())
    assert res.ok is False and "transport-helper" in res.reason
    assert not os.path.exists("/tmp/EVIL_LAP1")
