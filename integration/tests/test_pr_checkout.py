"""repo-connect 3-live-b2: the gated PR-head checkout + changed-files seams (pr_checkout).

make_pr_bot_checkout clones a connected repo AT THE PR HEAD into a disposable workdir, token OFF-ARGV (child env
only), repo-identity + confined-workdir + no-shell guards, failing CLOSED on no-token / unsafe-repo / clone error.
make_pr_bot_changed_files reads the PR's changed files via the 3a gated client. Offline: the subprocess runner +
the http client are injected, so no real git/gh/network — the command sequence, the OFF-ARGV token, the workdir
confinement, and the fail-closed paths are all exercised.
"""
from __future__ import annotations

import os

import pytest

from vigil_integration.jobs.model import SecurityJob
from vigil_integration.live.pr_checkout import (
    PrCheckoutError,
    make_pr_bot_changed_files,
    make_pr_bot_checkout,
)

_TOKEN = "ghp_secrettoken_xyz"


class _Run:
    def __init__(self, exit_code: int = 0, stderr: str = "") -> None:
        self.exit_code = exit_code
        self.stderr = stderr
        self.stdout = ""
        self.timed_out = False


class _Runner:
    """Records each subprocess call; returns success unless a per-call failure is configured."""

    def __init__(self, fail_on: "int | None" = None) -> None:
        self.calls: list = []
        self._fail_on = fail_on

    def __call__(self, argv, *, timeout=None, output_cap=None, cwd=None, env=None):
        self.calls.append({"argv": [str(a) for a in argv], "cwd": cwd, "env": dict(env or {})})
        if self._fail_on is not None and len(self.calls) == self._fail_on:
            return _Run(exit_code=1, stderr="boom")
        return _Run(exit_code=0)


def _job(repo="github.com/acme/widget", pr=7):
    return SecurityJob(repo=repo, pr_number=pr, commit="deadbeef", source="manual", delivery_id="d1")


def test_checkout_clones_pr_head_with_token_off_argv(tmp_path):
    runner = _Runner()
    checkout = make_pr_bot_checkout(github_token=_TOKEN, base_dir=str(tmp_path), _runner=runner)
    wd = checkout(_job())
    # two subprocess steps: gh repo clone, then gh pr checkout in the clone
    assert [c["argv"][:3] for c in runner.calls] == [["gh", "repo", "clone"], ["gh", "pr", "checkout"]]
    assert runner.calls[0]["argv"] == ["gh", "repo", "clone", "acme/widget", wd, "--", "--depth", "1"]
    assert runner.calls[1]["argv"] == ["gh", "pr", "checkout", "7"] and runner.calls[1]["cwd"] == wd
    # the token is ONLY in the child env, NEVER in any argv (argv shows in ps/logs)
    for c in runner.calls:
        assert _TOKEN not in " ".join(c["argv"])
        assert c["env"]["GH_TOKEN"] == _TOKEN and c["env"]["GIT_TERMINAL_PROMPT"] == "0"
    # the workdir is CONFINED under base_dir
    assert os.path.abspath(wd).startswith(os.path.abspath(str(tmp_path)))


def test_checkout_fails_closed_without_a_token(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    runner = _Runner()
    checkout = make_pr_bot_checkout(github_token="", base_dir=str(tmp_path), _runner=runner)
    with pytest.raises(PrCheckoutError):
        checkout(_job())
    assert runner.calls == []                                   # no clone attempted


def test_checkout_rejects_unsafe_repo_identity(tmp_path):
    runner = _Runner()
    checkout = make_pr_bot_checkout(github_token=_TOKEN, base_dir=str(tmp_path), _runner=runner)
    for bad in ("github.com/acme/widget/../../other", "a/b/c", "github.com/acme"):
        with pytest.raises(PrCheckoutError):
            checkout(_job(repo=bad))
    assert runner.calls == []                                   # never shelled out for an unsafe repo


def test_checkout_fails_closed_on_bad_pr_number(tmp_path):
    runner = _Runner()
    checkout = make_pr_bot_checkout(github_token=_TOKEN, base_dir=str(tmp_path), _runner=runner)
    for bad in (None, "7;rm -rf", "abc", 0, -5):          # non-int / non-positive → documented PrCheckoutError
        with pytest.raises(PrCheckoutError):
            checkout(_job(pr=bad))
    assert runner.calls == []                              # never shelled out for a bad pr


def test_checkout_fails_closed_on_clone_error(tmp_path):
    runner = _Runner(fail_on=1)                                 # the clone step fails
    checkout = make_pr_bot_checkout(github_token=_TOKEN, base_dir=str(tmp_path), _runner=runner)
    with pytest.raises(PrCheckoutError):
        checkout(_job())
    assert len(runner.calls) == 1                               # stopped at the failed clone; no pr checkout


def test_checkout_fails_closed_on_pr_checkout_error(tmp_path):
    runner = _Runner(fail_on=2)                                 # clone ok, pr checkout fails
    checkout = make_pr_bot_checkout(github_token=_TOKEN, base_dir=str(tmp_path), _runner=runner)
    with pytest.raises(PrCheckoutError):
        checkout(_job())
    assert len(runner.calls) == 2


# ---- changed_files via the gated read client ------------------------------------------------------

class _Resp:
    def __init__(self, rows):
        self.status_code = 200
        self._rows = rows
        self.headers: dict = {}
        import json as _j
        self.content = _j.dumps(rows).encode("utf-8")

    def json(self):
        return self._rows


class _HTTP:
    def __init__(self, rows):
        self._rows = rows
        self.calls: list = []

    def get(self, url, headers=None, params=None):
        self.calls.append(url)
        page = (params or {}).get("page", 1)
        return _Resp(self._rows if page == 1 else [])


def test_changed_files_reads_the_prs_files(tmp_path):
    http = _HTTP([{"filename": "app/db.py"}, {"filename": "app/run.py"}])
    cf = make_pr_bot_changed_files(_TOKEN, http=http)
    files = cf(_job())
    assert files == {"app/db.py", "app/run.py"}
    assert http.calls[0] == "https://api.github.com/repos/acme/widget/pulls/7/files"


def test_changed_files_fails_closed_on_bad_pr_number(tmp_path):
    from vigil_integration.live.github_client import GitHubReadError
    http = _HTTP([])
    cf = make_pr_bot_changed_files(_TOKEN, http=http)
    for bad in (None, "x"):                               # a read error RAISES (typed), never a silent odd crash
        with pytest.raises(GitHubReadError):
            cf(_job(pr=bad))
    assert http.calls == []                               # no HTTP issued for a bad pr
