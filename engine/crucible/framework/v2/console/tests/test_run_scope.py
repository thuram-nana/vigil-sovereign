"""The ACTIVE-ENGAGEMENT SCOPE on the runs listing — ``GET /api/runs?slug=<engagement>``.

The operator's requirement: the console has no notion of "the job I am working on now", so every
screen defaults to the newest run of ANY past job and one engagement's work bleeds into another's.
The scope fixes that: each screen asks for the active engagement's runs and shows nothing else.

What is pinned here:
  * The scope is a FILTER, never an assertion. A run's engagement is the slug the RUN ITSELF recorded
    in its own ``meta.json``; a caller can only select among those, and can never claim a run into an
    engagement it does not record (the mutation control below proves the test bites).
  * Membership is the SAME notion the engagement library groups on (``api._run_slug``) — one
    definition, so the library and the scoped listing can never drift apart.
  * Absent/blank ``slug`` ⇒ the unscoped listing, unchanged.
  * Total + fail-safe: an unknown/unsafe/over-long slug yields an honest EMPTY list — never an error,
    and never a silent fallback to the unfiltered list (which is the failure that would show one
    job's work under another).
  * The listing exposes each run's engagement (``slug``) and its human name (``engagement_label``,
    presentation only) so the UI can label, group and pick a default run within the scope.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager

import pytest

from framework.v2.console import actions, api, labels, server

from .conftest import AUTH_HEADERS

# ---------------------------------------------------------------------------
# helpers — a console run store in tmp_path
# ---------------------------------------------------------------------------


@pytest.fixture()
def console_root(tmp_path, monkeypatch):
    """Point the console's run store (and therefore the label side-car) at tmp_path."""
    root = tmp_path / "console"
    (root / "runs").mkdir(parents=True)
    monkeypatch.setattr(actions, "console_dir", lambda: root)
    return root


def _write_run(console_root, run_id: str, *, slug: str | None, started: float,
               target: str = "http://127.0.0.1/") -> None:
    d = console_root / "runs" / run_id
    d.mkdir(parents=True, exist_ok=True)
    meta = {"target": target, "status": "done", "started": started, "finished": started + 60,
            "mode": "url"}
    if slug is not None:                       # a legacy run may record NO engagement at all
        meta["slug"] = slug
    (d / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    (d / "report.json").write_text(json.dumps({"findings": [{"title": "f"}]}), encoding="utf-8")


@pytest.fixture()
def three_runs(console_root):
    """Two engagements + one engagement-less legacy run."""
    _write_run(console_root, "20260101-000000-001", slug="acme-web", started=1767225600.0)
    _write_run(console_root, "20260102-000000-002", slug="beta-corp", started=1767312000.0)
    _write_run(console_root, "20260103-000000-003", slug=None, started=1767398400.0)
    return console_root


def _ids(payload) -> list[str]:
    return [r["run_id"] for r in payload["runs"]]


# ---------------------------------------------------------------------------
# the filter itself
# ---------------------------------------------------------------------------


def test_absent_slug_is_the_unscoped_listing(three_runs) -> None:
    """No scope ⇒ every run, newest first — the behaviour every existing caller already relies on."""
    assert _ids(api.list_runs()) == ["20260103-000000-003", "20260102-000000-002",
                                     "20260101-000000-001"]
    assert api.list_runs()["slug"] == ""
    # a blank/whitespace scope is "all engagements" too, not "an engagement named ''"
    assert _ids(api.list_runs("")) == _ids(api.list_runs("   ")) == _ids(api.list_runs())


def test_a_scoped_listing_shows_only_that_engagements_runs(three_runs) -> None:
    assert _ids(api.list_runs("acme-web")) == ["20260101-000000-001"]
    assert _ids(api.list_runs("beta-corp")) == ["20260102-000000-002"]
    assert api.list_runs("acme-web")["slug"] == "acme-web"    # the server echoes the scope it applied


def test_an_unknown_slug_is_an_honest_empty_list_not_the_whole_store(three_runs) -> None:
    """Fail-safe: the failure mode of a filter is showing TOO MUCH, so an unrecognised scope must
    resolve to nothing at all — never an error page, and never the unfiltered list."""
    for bad in ("does-not-exist", "../../etc/passwd", "%", "acme-Web", "acme_web", "x" * 400):
        out = api.list_runs(bad)
        assert out["runs"] == [], bad
    # ... and the store itself is untouched: the unscoped listing still has everything.
    assert len(api.list_runs()["runs"]) == 3
    # Surrounding whitespace is trimmed, exactly as the library trims it (`library_engagement`), so
    # the two agree on what " acme-web " names — one notion of the slug, not two.
    assert _ids(api.list_runs("  acme-web  ")) == _ids(api.list_runs("acme-web"))


# ---------------------------------------------------------------------------
# the safety property — membership is recorded, never asserted
# ---------------------------------------------------------------------------


def test_a_caller_cannot_assert_a_run_into_an_engagement(three_runs) -> None:
    """The load-bearing property. The scope SELECTS among the engagement each run recorded for
    itself; there is no request shape that moves a run into another engagement."""
    acme = api.list_runs("acme-web")["runs"]
    assert [r["slug"] for r in acme] == ["acme-web"]
    # the beta run records beta-corp, so it is absent from every other scope, forever
    for scope in ("acme-web", "", "unrelated"):
        got = api.list_runs(scope)["runs"] if scope else []
        assert "20260102-000000-002" not in [r["run_id"] for r in got]
    # mutation control: the property is read from the RUN's own meta.json, so rewriting that file —
    # the only place membership lives — is the ONLY thing that moves the run. If this control did not
    # flip, the assertions above would be vacuous.
    meta = three_runs / "runs" / "20260102-000000-002" / "meta.json"
    doc = json.loads(meta.read_text(encoding="utf-8"))
    doc["slug"] = "acme-web"
    meta.write_text(json.dumps(doc), encoding="utf-8")
    assert _ids(api.list_runs("acme-web")) == ["20260102-000000-002", "20260101-000000-001"]


def test_the_scope_uses_the_librarys_own_notion_of_membership(three_runs) -> None:
    """One definition of run→engagement, so the library and the scoped listing cannot drift."""
    for slug in ("acme-web", "beta-corp", "nope"):
        assert _ids(api.list_runs(slug)) == [r["run_id"] for r in
                                             api.library_engagement(slug)["runs"]]
    # the engagement-less run stays reachable — unscoped, and in the library's "" group
    assert "20260103-000000-003" in api._runs_by_slug()[""][0]["run_id"]


# ---------------------------------------------------------------------------
# what a run row tells the client about its engagement
# ---------------------------------------------------------------------------


def test_each_run_row_carries_its_engagement_and_its_human_name(three_runs, monkeypatch) -> None:
    """The UI labels the scope chip and groups an unscoped list from the row itself — no second round
    trip. The label is PRESENTATION ONLY (the rename side-car); the slug is what membership uses."""
    monkeypatch.setattr(labels, "engagement_labels", lambda: {"acme-web": "ACME web app"})
    rows = {r["run_id"]: r for r in api.list_runs()["runs"]}
    assert rows["20260101-000000-001"]["slug"] == "acme-web"
    assert rows["20260101-000000-001"]["engagement_label"] == "ACME web app"
    assert rows["20260102-000000-002"]["engagement_label"] == ""      # unlabelled → honest blank
    assert rows["20260103-000000-003"]["slug"] is None                # no engagement recorded
    assert rows["20260103-000000-003"]["engagement_label"] == ""


# ---------------------------------------------------------------------------
# over HTTP
# ---------------------------------------------------------------------------


@contextmanager
def _running():
    httpd = server.serve(host="127.0.0.1", port=0)
    port = httpd.server_address[1]
    th = threading.Thread(target=httpd.serve_forever, daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        th.join(timeout=5)


def _get(url):
    req = urllib.request.Request(url, headers=AUTH_HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310 (loopback test)
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def test_the_route_scopes_on_the_slug_query_parameter(three_runs, tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path))
    assert server._SCOPED_ROUTES.get("/api/runs") is api.list_runs
    assert "/api/runs" not in server._EXACT_ROUTES      # the zero-arg entry would drop the scope
    with _running() as base:
        st, all_runs = _get(base + "/api/runs")
        assert st == 200 and len(all_runs["runs"]) == 3 and all_runs["slug"] == ""
        st, scoped = _get(base + "/api/runs?slug=acme-web")
        assert st == 200 and _ids(scoped) == ["20260101-000000-001"]
        st, empty = _get(base + "/api/runs?slug=nope")
        assert st == 200 and empty["runs"] == [] and empty["slug"] == "nope"   # not a 404/500
        st, blank = _get(base + "/api/runs?slug=")
        assert st == 200 and len(blank["runs"]) == 3
        # one scope, never a set: a repeated parameter takes the first value
        st, dupe = _get(base + "/api/runs?slug=acme-web&slug=beta-corp")
        assert st == 200 and _ids(dupe) == ["20260101-000000-001"]
        # the scope is data, not a path: an encoded traversal is just an unknown engagement
        st, trav = _get(base + "/api/runs?slug=%2F..%2Fetc%2Fpasswd")
        assert st == 200 and trav["runs"] == []
