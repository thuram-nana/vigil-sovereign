"""
W1.3 — engage's opt-in cross-engagement TRANSFER wiring.

`--transfer-archetype NAME` loads smoothed cross-engagement priors for that archetype
(blended from lexically similar past archetypes, evidence-gated) and warm-starts the
scan's check-ordering bandit with them. Because the bandit only ORDERS effort, the scan
still confirms the same findings — transfer changes ordering, never coverage. With no
archetype (the default), priors stays None and behaviour is byte-identical.

All traffic is loopback pytest-httpserver; nothing leaves the test host.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pytest_httpserver import HTTPServer
from werkzeug.wrappers import Response

from framework.v2.common import paths as _paths
from framework.v2.engage import run_engagement
from framework.v2.memory import priors as _priors
from framework.v2.memory.store import open_store

_CHARTER = """\
# Engagement charter — `{slug}`

**Status:** Final

## 1. Operator attestation

Signed: `tester`     Date: `2026-05-04`

## 2. In-scope systems

| Host / Surface | Notes | Auth |
|----------------|-------|------|
| `{host}` | Test app | Yes |

## 3. Out of scope

- Anything not listed above.

## 7. Posture

- [x] **TEST**
"""


@pytest.fixture()
def isolated_engagement(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    targets_root = tmp_path / "targets"
    targets_root.mkdir()

    def build(slug: str, host: str) -> Path:
        td = targets_root / slug
        td.mkdir(parents=True, exist_ok=True)
        (td / "charter.md").write_text(_CHARTER.format(slug=slug, host=host), encoding="utf-8")
        return td

    monkeypatch.setattr(_paths, "target_dir", lambda s: targets_root / s)
    monkeypatch.setattr(_paths, "charter_path", lambda s: targets_root / s / "charter.md")
    monkeypatch.setattr(_paths, "killswitch_path", lambda s: targets_root / s / ".halt")
    return build


def _root(request) -> Response:
    return Response('<a href="/search?q=hi">search</a>', status=200, mimetype="text/html")


def _search(request) -> Response:
    q = request.args.get("q", "")
    if "'1'='1" in q or "1=1" in q:
        body = "echo:" + q + "\n" + "".join(f"user{i}:secret{i}\n" for i in range(40))
    else:
        body = "echo:" + q
    return Response(body, status=200, mimetype="text/html")


def _deny(_q: str, _t: float) -> bool:
    return False


def test_transfer_archetype_warmstarts_without_breaking_the_scan(
    isolated_engagement, httpserver: HTTPServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    # A populated MLS store: a LEXICALLY SIMILAR past archetype has a strong boolean_sqli
    # prior. --transfer-archetype for the (new) target archetype should blend it in and
    # warm-start the bandit — and the scan must still confirm its findings.
    db = tmp_path / "mls.sqlite"
    s = open_store(db)
    for _ in range(8):
        _priors.bump_success(s, "laravel commerce shop", "boolean_sqli", "")
    for _ in range(2):
        _priors.bump_attempt(s, "laravel commerce shop", "boolean_sqli", "")
    s.close()
    monkeypatch.setattr(_paths, "memory_db", lambda: db)

    port = httpserver.port
    isolated_engagement("alpha", "127.0.0.1")
    httpserver.expect_request("/").respond_with_handler(_root)
    httpserver.expect_request("/search").respond_with_handler(_search)

    result = run_engagement(
        "alpha", f"http://127.0.0.1:{port}/",
        max_pages=5, enable_oob=False, prompt_callback=_deny,
        transfer_archetype="laravel commerce marketplace",
    )
    assert result.report.active_findings, "transfer warm-start must not break the scan"


def test_transfer_archetype_absent_store_is_harmless(
    isolated_engagement, httpserver: HTTPServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    # No MLS store on disk: the transfer lookup is best-effort and must degrade to no
    # warm-start (priors None) without breaking the engagement.
    monkeypatch.setattr(_paths, "memory_db", lambda: tmp_path / "does-not-exist.sqlite")

    port = httpserver.port
    isolated_engagement("alpha", "127.0.0.1")
    httpserver.expect_request("/").respond_with_handler(_root)
    httpserver.expect_request("/search").respond_with_handler(_search)

    result = run_engagement(
        "alpha", f"http://127.0.0.1:{port}/",
        max_pages=5, enable_oob=False, prompt_callback=_deny,
        transfer_archetype="brand new never seen archetype",
    )
    assert result.report.active_findings
