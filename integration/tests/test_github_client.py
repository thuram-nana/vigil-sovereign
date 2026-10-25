"""repo-connect Slice 3a — the gated, READ-ONLY api.github.com client + reconciliation lister.

Drives GitHubReadClient with an INJECTED HTTP double (no network, no framework), pinning the request /
pagination / cursor / fail-closed logic:
  * list_open_prs walks ?state=open&sort=updated&direction=desc pages, builds ChangedPR(number, head.sha,
    updated_at), stops at the first PR at/under the cursor, and returns the high-water cursor;
  * GET-only with an Authorization: Bearer header + api-version (the double has no post/patch, so any write
    attempt would AttributeError);
  * fail-closed on a missing token; a non-200 raises GitHubReadError (so the reconciliation driver skips
    the repo this cycle);
  * changed_files returns repo-relative POSIX paths; make_github_lister yields a RepoLister-shaped callable.

Framework-free (the gated transport is only built when http is NOT injected), so it runs in the sovereign
CI leg.
"""
from __future__ import annotations

import json

import pytest

from vigil_integration.jobs.reconciliation import ChangedPR
from vigil_integration.live.github_client import (
    GitHubReadClient,
    GitHubReadConfig,
    GitHubReadError,
    make_github_lister,
)


class _Resp:
    def __init__(self, status: int, payload):
        self.status_code = status
        self._payload = payload
        self.content = json.dumps(payload).encode() if payload is not None else b""

    def json(self):
        if self._payload is None:
            raise ValueError("no body")
        return self._payload


class _FakeHttp:
    """Records GET calls and replays a handler(url, params) -> _Resp. Implements ONLY get() + close(), so
    any attempt to POST/PATCH/PUT would AttributeError — a structural GET-only guard."""

    def __init__(self, handler):
        self.handler = handler
        self.calls: list = []

    def get(self, url, *, headers=None, params=None):
        self.calls.append({"url": url, "params": dict(params or {}), "headers": dict(headers or {})})
        return self.handler(url, dict(params or {}))

    def close(self):
        pass


def _pr(number, sha, updated):
    return {"number": number, "head": {"sha": sha}, "updated_at": updated}


def _cfg(**kw):
    base = dict(slug="repo-x", github_token="ghp_test")
    base.update(kw)
    return GitHubReadConfig(**base)


def test_list_open_prs_builds_changedprs_and_high_water_cursor():
    pages = {1: [_pr(9, "sha9", "2026-01-03T00:00:00Z"), _pr(8, "sha8", "2026-01-02T00:00:00Z")], 2: []}

    def handler(url, params):
        assert url.endswith("/repos/acme/widget/pulls")      # correct endpoint
        assert params["state"] == "open" and params["sort"] == "updated" and params["direction"] == "desc"
        return _Resp(200, pages.get(params["page"], []))

    http = _FakeHttp(handler)
    prs, cursor = GitHubReadClient(_cfg(), http=http).list_open_prs("github.com/acme/widget", "")
    assert [p.pr_number for p in prs] == [9, 8]
    assert prs[0] == ChangedPR(9, "sha9", "2026-01-03T00:00:00Z")
    assert cursor == "2026-01-03T00:00:00Z"                  # high-water = newest updated_at
    # GET-only + authenticated
    assert all("api.github.com" in c["url"] for c in http.calls)
    assert http.calls[0]["headers"]["Authorization"] == "Bearer ghp_test"
    assert http.calls[0]["headers"]["X-GitHub-Api-Version"]


def test_cursor_stops_at_already_seen_prs():
    page = [_pr(9, "s9", "2026-01-03T00:00:00Z"), _pr(8, "s8", "2026-01-02T00:00:00Z"),
            _pr(7, "s7", "2026-01-01T00:00:00Z")]

    def handler(url, params):
        return _Resp(200, page if params["page"] == 1 else [])

    prs, cursor = GitHubReadClient(_cfg(), http=_FakeHttp(handler)).list_open_prs(
        "github.com/acme/widget", "2026-01-02T00:00:00Z")   # since = PR#8's time
    assert [p.pr_number for p in prs] == [9]                 # only the strictly-newer PR#9
    assert cursor == "2026-01-03T00:00:00Z"


def test_pagination_collects_across_full_pages():
    def handler(url, params):
        pg = params["page"]
        if pg == 1:   # a FULL page (per_page=100) → keep going
            return _Resp(200, [_pr(i, f"s{i}", f"2026-02-{(i % 28) + 1:02d}T00:00:00Z") for i in range(100, 0, -1)])
        if pg == 2:
            return _Resp(200, [_pr(160, "s160", "2026-03-01T00:00:00Z")])   # a short page → stop after it
        return _Resp(200, [])

    prs, _cursor = GitHubReadClient(_cfg(), http=_FakeHttp(handler)).list_open_prs("github.com/acme/widget", "")
    assert len(prs) == 101 and 160 in [p.pr_number for p in prs]


def test_mis_ordered_page_does_not_hide_a_newer_pr():
    # the client must NOT early-break on the first at/under-cursor row (that trusts remote ordering); a newer
    # PR appearing AFTER an older one on the same page must still be emitted.
    page = [_pr(8, "s8", "2026-01-02T00:00:00Z"),   # older (<= cursor) appears FIRST (mis-ordered)
            _pr(9, "s9", "2026-01-03T00:00:00Z")]   # newer (> cursor) appears AFTER it
    prs, cursor = GitHubReadClient(
        _cfg(), http=_FakeHttp(lambda u, p: _Resp(200, page if p["page"] == 1 else []))
    ).list_open_prs("github.com/acme/widget", "2026-01-02T00:00:00Z")
    assert [p.pr_number for p in prs] == [9] and cursor == "2026-01-03T00:00:00Z"


def test_rest_path_traversal_is_refused():
    c = GitHubReadClient(_cfg(), http=_FakeHttp(lambda u, p: _Resp(200, [])))
    for hostile in ("acme/widget/../../orgs/evil", "acme/widget/pulls", "../../etc", "acme/wid get",
                    "https://evil.test/acme/widget"):
        with pytest.raises(GitHubReadError):
            c.list_open_prs(hostile, "")


def test_host_pin_refuses_a_non_github_api_base():
    bad = GitHubReadClient(GitHubReadConfig(slug="x", github_token="t", api_base="https://evil.test"),
                           http=_FakeHttp(lambda u, p: _Resp(200, [])))
    with pytest.raises(GitHubReadError):
        bad.list_open_prs("github.com/acme/widget", "")


def test_oversized_declared_content_length_is_refused():
    class _Big:
        status_code = 200
        headers = {"content-length": str(50 * 1024 * 1024)}
        content = b"[]"

        def json(self):
            return []

    http = _FakeHttp(lambda u, p: _Big())
    with pytest.raises(GitHubReadError):
        GitHubReadClient(_cfg(), http=http).list_open_prs("github.com/acme/widget", "")


def test_changed_files_truncation_fails_closed():
    # a PR whose /files list never short-pages (always a full page) → truncated → raise (not a partial scope)
    def handler(url, params):
        return _Resp(200, [{"filename": f"f{params['page']}_{i}.py"} for i in range(100)])   # always full

    with pytest.raises(GitHubReadError):
        GitHubReadClient(_cfg(), http=_FakeHttp(handler)).changed_files("github.com/acme/widget", 7)


def test_missing_token_fails_closed(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    http = _FakeHttp(lambda url, params: _Resp(200, []))
    with pytest.raises(GitHubReadError):                     # never makes an unauthenticated call
        GitHubReadClient(_cfg(github_token=""), http=http).list_open_prs("github.com/acme/widget", "")
    assert http.calls == []                                  # no request was attempted


def test_token_from_env_when_config_empty(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_from_env")
    http = _FakeHttp(lambda url, params: _Resp(200, []))
    GitHubReadClient(_cfg(github_token=""), http=http).list_open_prs("github.com/acme/widget", "")
    assert http.calls[0]["headers"]["Authorization"] == "Bearer ghp_from_env"


def test_non_200_raises_so_driver_skips():
    http = _FakeHttp(lambda url, params: _Resp(503, None))
    with pytest.raises(GitHubReadError):
        GitHubReadClient(_cfg(), http=http).list_open_prs("github.com/acme/widget", "")


def test_changed_files_returns_repo_relative_paths():
    def handler(url, params):
        assert url.endswith("/repos/acme/widget/pulls/7/files")
        return _Resp(200, [{"filename": "src/a.py"}, {"filename": "src/b.py"}] if params["page"] == 1 else [])

    files = GitHubReadClient(_cfg(), http=_FakeHttp(handler)).changed_files("github.com/acme/widget", 7)
    assert files == {"src/a.py", "src/b.py"}


def test_owner_repo_parsing_and_bad_identity():
    c = GitHubReadClient(_cfg(), http=_FakeHttp(lambda url, params: _Resp(200, [])))
    # a bare host with no org/repo is refused (not a repo identity)
    with pytest.raises(GitHubReadError):
        c.list_open_prs("github.com", "")


def test_make_github_lister_is_repolister_shaped():
    http = _FakeHttp(lambda url, params: _Resp(200, [_pr(1, "s1", "2026-01-01T00:00:00Z")]
                                               if params["page"] == 1 else []))
    lister, client = make_github_lister(_cfg(), http=http)
    prs, cursor = lister("github.com/acme/widget", "")       # (repo, since_cursor) -> (list, cursor)
    assert [p.pr_number for p in prs] == [1] and cursor == "2026-01-01T00:00:00Z"
    assert client.changed_files  # the same client is returned for changed_files + close
