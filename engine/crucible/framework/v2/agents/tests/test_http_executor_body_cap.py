"""Regression: the gated_fetch body excerpt must be large enough to contain oracle signatures that render
in a page's MAIN CONTENT — past the head / nav / inline CSS.

Root cause it guards: with an 8 KiB cap, a datastore-error signature at byte ~12.6 KiB of a ~12.9 KiB page
was truncated out of the returned body, so the T2 SQLi re-drive's error_signature oracle never saw it and a
genuinely-confirmed SQLi was silently demoted from a FACT to a LEAD. The excerpt is what oracles fire over
(the full body is only archived to evidence/), so the cap directly bounds oracle RECALL.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pytest
from pytest_httpserver import HTTPServer
from werkzeug.wrappers import Response

from framework.v2.agents.http_executor import HttpExecutor, _BODY_EXCERPT_BYTES
from framework.v2.common import paths as _paths

_CHARTER = """\
# Engagement charter — `{slug}`

## 1. Operator attestation

Signed: `tester`     Date: `2026-05-04`

## 2. In-scope systems

| Host / Surface | Notes | Auth |
|----------------|-------|------|
| `{host}` | Test app | Yes |

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


@dataclass
class _Req:
    url: str
    method: str = "GET"
    headers: list = field(default_factory=list)
    body: str | None = None


def test_body_excerpt_captures_a_signature_past_8kib(isolated_engagement, httpserver: HTTPServer):
    # A page whose oracle-relevant signature ("SQL error: unrecognized token") renders AFTER ~12 KiB of
    # leading markup — exactly the shape that the old 8 KiB cap silently truncated.
    marker = "SQL error: unrecognized token"
    filler = "<div class='pad'>" + ("x" * 12000) + "</div>"
    body = "<html><head><style>" + ("/*css*/" * 200) + "</style></head><body>" + filler + \
           "<pre>" + marker + "</pre></body></html>"
    assert body.index(marker) > 8 * 1024, "test fixture must place the marker past the OLD 8 KiB cap"

    isolated_engagement("alpha", "127.0.0.1")
    httpserver.expect_request("/records/search").respond_with_response(
        Response(body, status=200, mimetype="text/html"))

    ex = HttpExecutor(engagement_slug="alpha", base_url=f"http://127.0.0.1:{httpserver.port}/",
                      prompt_callback=lambda _q, _t: False)
    resp = ex.gated_fetch(_Req(url=f"http://127.0.0.1:{httpserver.port}/records/search?q=%27"))

    assert resp["status"] == 200
    assert marker in resp["body"], "the signature past 8 KiB must be present in the returned excerpt"


def test_cap_is_large_enough_for_main_content_signatures():
    # A guard on the constant itself so a future edit can't quietly shrink it back below the recall floor.
    assert _BODY_EXCERPT_BYTES >= 16 * 1024
