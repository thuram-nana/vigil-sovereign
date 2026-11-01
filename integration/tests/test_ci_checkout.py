"""live.ci_checkout — the CI-local checkout + changed-files seams (W4).

Pins:
  * make_ci_checkout is an identity validator (existing dir -> abspath; empty/missing -> fail-closed).
  * make_ci_changed_files computes the PR diff from REAL local git history (three-dot) and returns the
    repo-relative POSIX changed set — proven against an actual temp git repo.
  * fail-closed: a git failure RAISES (so the diff worker never reports a silent clean); an unsafe ref
    (flag-injection) is refused at build time.
"""

from __future__ import annotations

import subprocess

import pytest

from vigil_integration.jobs.model import SecurityJob
from vigil_integration.live.ci_checkout import (
    CiCheckoutError,
    make_ci_changed_files,
    make_ci_checkout,
)

_JOB = SecurityJob.normalize(source="ci", repo="github.com/o/r", delivery_id="d")


class _FakeRun:
    def __init__(self, exit_code, stdout="", stderr=""):
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr


def _real_git_runner(argv, *, timeout=60.0, **kw):
    """Run git directly (bypassing the egress-guarded default runner, which is irrelevant for a local
    `git diff`), returning a RunOutcome-shaped object."""
    p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)  # noqa: S603
    return _FakeRun(p.returncode, p.stdout, p.stderr)


def _git(cwd, *args):
    env = {"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
           "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@t", "HOME": str(cwd)}
    subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True, env=env)


def test_make_ci_checkout_validates_and_returns_the_workspace(tmp_path) -> None:
    checkout = make_ci_checkout(str(tmp_path))
    assert checkout(_JOB) == str(tmp_path.resolve())


def test_make_ci_checkout_fails_closed_on_missing_or_empty_workspace(tmp_path) -> None:
    with pytest.raises(CiCheckoutError):
        make_ci_checkout("")(_JOB)
    with pytest.raises(CiCheckoutError):
        make_ci_checkout(str(tmp_path / "nope"))(_JOB)


def test_make_ci_changed_files_over_a_real_git_repo(tmp_path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "keep.py").write_text("x = 1\n", encoding="utf-8")
    (repo / "untouched.py").write_text("y = 2\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    base = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                          capture_output=True, text=True).stdout.strip()
    # PR branch: change one file, add another; leave untouched.py alone
    (repo / "keep.py").write_text("x = 42\n", encoding="utf-8")
    (repo / "sub").mkdir()
    (repo / "sub" / "new.py").write_text("z = 3\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "pr")
    head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                          capture_output=True, text=True).stdout.strip()

    cf = make_ci_changed_files(base_ref=base, head_ref=head, workspace=str(repo),
                               _runner=_real_git_runner)
    changed = cf(_JOB)
    assert changed == {"keep.py", "sub/new.py"}          # repo-relative POSIX; untouched.py excluded


def test_make_ci_changed_files_fails_closed_on_git_error(tmp_path) -> None:
    cf = make_ci_changed_files(base_ref="aaa", head_ref="bbb", workspace=str(tmp_path),
                               _runner=lambda *a, **k: _FakeRun(128, "", "fatal: bad revision"))
    with pytest.raises(CiCheckoutError):
        cf(_JOB)


def test_unsafe_refs_are_refused_at_build_time(tmp_path) -> None:
    for bad in ("--output=/etc/passwd", "-x", "a b", "a;rm -rf", ""):
        with pytest.raises(CiCheckoutError):
            make_ci_changed_files(base_ref=bad, head_ref="main", workspace=str(tmp_path))
        with pytest.raises(CiCheckoutError):
            make_ci_changed_files(base_ref="main", head_ref=bad, workspace=str(tmp_path))


def test_changed_files_argv_is_a_three_dot_name_only_diff(tmp_path) -> None:
    seen = {}

    def _cap(argv, *, timeout=60.0, **kw):
        seen["argv"] = argv
        return _FakeRun(0, "a.py\n")

    make_ci_changed_files(base_ref="B", head_ref="H", workspace=str(tmp_path), _runner=_cap)(_JOB)
    assert seen["argv"] == ["git", "-C", str(tmp_path.resolve()), "diff", "--name-only", "B...H", "--"]
