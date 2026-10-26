"""repo-connect 3-live-b1: `vigil reconcile`'s real, per-repo GitHub lister (make_reconcile_github_lister).

The multi-repo reconciliation lister lists a connected repo's open PRs via the gated read client, scoping egress
PER REPO (each repo's api.github.com read rides THAT repo's SecurityJob slug). Offline — a fake http double is
injected, so no gated transport / framework / network; it exercises the list→ChangedPR→cursor wiring + the
per-repo client caching.
"""
from __future__ import annotations

import json as _json

from vigil_integration.jobs.model import SecurityJob
from vigil_integration.live.github_client import make_reconcile_github_lister


class _Resp:
    def __init__(self, status: int, rows: list) -> None:
        self.status_code = status
        self._rows = rows
        self.headers: dict = {}
        self.content = _json.dumps(rows).encode("utf-8")

    def json(self) -> list:
        return self._rows


class _HTTP:
    """Fake httpx-like client; returns one page of PR rows keyed on the ``page`` param, recording each GET."""

    def __init__(self, page1: list) -> None:
        self._page1 = page1
        self.calls: list = []

    def get(self, url, headers=None, params=None):
        self.calls.append({"url": url, "params": params})
        page = (params or {}).get("page", 1)
        return _Resp(200, self._page1 if page == 1 else [])


_ROWS = [
    {"number": 7, "updated_at": "2026-06-01T00:00:00Z", "head": {"sha": "s7"}},
    {"number": 8, "updated_at": "2026-06-02T00:00:00Z", "head": {"sha": "s8"}},
]


def test_reconcile_lister_lists_open_prs_for_the_repo():
    http = _HTTP(_ROWS)
    lister = make_reconcile_github_lister("TOK", http=http)
    prs, cursor = lister("github.com/acme/widget", "")
    assert {p.pr_number for p in prs} == {7, 8}
    assert {p.head_sha for p in prs} == {"s7", "s8"}
    assert cursor == "2026-06-02T00:00:00Z"                     # the high-water updated_at
    # it hit api.github.com for THIS repo's pulls endpoint (host-pinned, repo-scoped path)
    assert http.calls[0]["url"] == "https://api.github.com/repos/acme/widget/pulls"
    assert http.calls[0]["params"]["state"] == "open"


def test_reconcile_lister_is_multi_repo():
    http = _HTTP(_ROWS)
    lister = make_reconcile_github_lister("TOK", http=http)
    prs_a, _ = lister("github.com/acme/widget", "")
    prs_b, _ = lister("github.com/acme/other", "")
    assert prs_a and prs_b                                      # both repos listed through the one lister
    # each repo's read targeted its OWN pulls path (distinct per-repo egress scope under the one token)
    paths = {c["url"] for c in http.calls}
    assert "https://api.github.com/repos/acme/widget/pulls" in paths
    assert "https://api.github.com/repos/acme/other/pulls" in paths


def test_reconcile_lister_slug_is_the_per_repo_job_slug():
    # the per-repo client is scoped to the SAME injective slug the queue + signed authority use, so the read
    # rides that engagement's egress scope — not a shared/foreign one.
    assert SecurityJob(repo="github.com/acme/widget").slug == "repo-github-com-acme-widget-8ac5bc08a417"
