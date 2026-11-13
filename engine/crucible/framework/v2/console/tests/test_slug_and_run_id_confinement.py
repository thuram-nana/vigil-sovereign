"""The console's slug-keyed READ routes and its run-id guard, attacked end to end.

Two defects, each reproduced here against the real HTTP server before it was fixed:

1. An engagement ``slug`` taken from the URL (``/api/library/<slug>``, ``/api/charter/<slug>``,
   ``/api/planner/<slug>``, ``/api/events?slug=``) was joined into a path with no validation, so an
   authenticated caller could read the EXISTENCE/size of files outside ``targets/``, the CONTENT of any
   ``*.authority.json`` / ``.planner-state.json`` on disk, and live-tail any ``.crucible-v2.log``.
2. ``actions._SAFE_RUN_ID`` ended in ``$`` and was used with ``.match``; ``$`` also matches BEFORE a
   trailing newline, so ``"victim\\n"`` passed as a run / session / chat id — a directory whose name ends
   in a newline, and (because the graph store drops the newline) a second session sharing ``victim``'s
   graph partition.

The fixes are at the source (``common.paths`` / the regex), so the assertions here are on the routes'
existing honest-empty and 404 shapes.
"""

from __future__ import annotations

import http.client
import json
import os
import threading
from contextlib import contextmanager

import pytest

from framework.v2.common import paths
from framework.v2.console import actions, api, labels, oob_collaborator, server, sessions, sse

from .conftest import CONSOLE_TEST_TOKEN

_SECRET_SCOPE = "secret-client-host.example"
_SECRET_ISSUER = "OTHER-TENANT-OWNER"
_SECRET_PLAN = "OTHER-TENANT-PLAN"
_SECRET_EVENT = "OTHER-TENANT-EVENT"


@pytest.fixture()
def deploy(tmp_path, monkeypatch):
    """A tmp deployment tree, plus an ``outside/other-tenant`` directory that is NOT part of it and holds
    every fixed-basename file a slug-keyed reader looks for."""
    root = tmp_path / "deploy" / "engine" / "crucible"
    (root / "targets" / "acme").mkdir(parents=True)
    (root / "framework" / "v2" / ".authority").mkdir(parents=True)
    (root / "CLAUDE.md").write_text("# crucible\n", encoding="utf-8")
    (root / "targets" / "acme" / "charter.md").write_text("# charter\n", encoding="utf-8")
    monkeypatch.setenv("CRUCIBLE_ROOT", str(root))
    monkeypatch.delenv("CRUCIBLE_ROOT_STRICT", raising=False)
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path / "deploy" / "live"))
    paths._reset_cache()
    console = tmp_path / "deploy" / "console"
    (console / "runs").mkdir(parents=True)
    monkeypatch.setattr(actions, "console_dir", lambda: console)

    out = tmp_path / "outside" / "other-tenant"
    (out / "evidence" / "act-1").mkdir(parents=True)
    (out / "charter.md").write_text("# someone else's charter\n", encoding="utf-8")
    (out / ".crucible-v2.log").write_text(json.dumps({"event": "old"}) + "\n", encoding="utf-8")
    (out / ".planner-state.json").write_text(json.dumps({"goal": _SECRET_PLAN}), encoding="utf-8")
    (tmp_path / "outside" / "other-tenant.authority.json").write_text(json.dumps({"authority": {
        "environment": "prod", "scope": [_SECRET_SCOPE], "issued_by": _SECRET_ISSUER,
        "not_after": "2099-01-01T00:00:00Z", "allow_destructive": True}}), encoding="utf-8")
    yield {"root": root, "outside": out}
    paths._reset_cache()


def _traversals(deploy) -> dict[str, str]:
    """The hostile slugs: relative to targets/ (reaches the planted dir), relative to the authority dir
    (reaches the planted ``*.authority.json``), and the absolute form (query-string routes only)."""
    out = deploy["outside"]
    return {
        "rel_targets": os.path.relpath(out, paths.targets_root()),
        "rel_authority": os.path.relpath(out, paths.authority_dir()),
        "absolute": str(out),
    }


@contextmanager
def _serve():
    httpd = server.serve(host="127.0.0.1", port=0)
    th = threading.Thread(target=httpd.serve_forever, daemon=True)
    th.start()
    try:
        yield httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()
        th.join(timeout=5)


def _raw_get(port: int, path: str, *, read: bool = True):
    """A RAW request line (no client-side normalisation of ``../``) with the loopback Host + the token."""
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=8)
    c.putrequest("GET", path, skip_host=True)
    c.putheader("Host", f"127.0.0.1:{port}")
    c.putheader("X-SIGIL-Token", CONSOLE_TEST_TOKEN)
    c.endheaders()
    r = c.getresponse()
    if not read:
        return r, c
    body = r.read().decode("utf-8")
    c.close()
    return r.status, body


# ---------------------------------------------------------------------------
# 1. slug-keyed readers
# ---------------------------------------------------------------------------


def test_engagement_row_does_not_probe_outside_the_targets_tree(deploy):
    for name, slug in _traversals(deploy).items():
        row = api._engagement_row(slug)
        assert row["has_charter"] is False, name
        assert row["log_exists"] is False and row["log_size"] == 0, name
        assert row["evidence_count"] == 0, name
        assert row["authority"] is None, name


def test_authority_content_is_not_disclosed_for_a_traversal_slug(deploy):
    for name, slug in _traversals(deploy).items():
        for provider in (api.library_engagement, api.engagement_detail, api.authority_full,
                         api.charter_status):
            doc = provider(slug)
            blob = json.dumps(doc)
            assert _SECRET_SCOPE not in blob and _SECRET_ISSUER not in blob, (name, provider.__name__)
            assert doc.get("authority") is None, (name, provider.__name__)
        assert api.charter_status(slug)["scope"] == []
        assert api.charter_status(slug)["has_remote_authority"] is False


def test_planner_state_content_is_not_disclosed_for_a_traversal_slug(deploy):
    for name, slug in _traversals(deploy).items():
        doc = api.planner_data(slug)
        assert doc == {"slug": slug, "present": False}, name


def test_event_stream_path_refuses_a_traversal_slug(deploy):
    for name, slug in _traversals(deploy).items():
        with pytest.raises(ValueError):
            sse.stream_path(slug=slug)
        with pytest.raises(ValueError):
            sse.log_path_for(slug)


def test_a_legitimate_engagement_still_reads_normally(deploy):
    """Positive control — without it every assertion above is satisfied by a console that reads nothing."""
    root = deploy["root"]
    (root / "targets" / "acme" / ".crucible-v2.log").write_text("{}\n", encoding="utf-8")
    (root / "targets" / "acme" / ".planner-state.json").write_text(json.dumps({"goal": "g"}),
                                                                   encoding="utf-8")
    (root / "framework" / "v2" / ".authority" / "acme.authority.json").write_text(json.dumps({"authority": {
        "environment": "staging", "scope": ["127.0.0.1"], "issued_by": "owner"}}), encoding="utf-8")
    row = api.library_engagement("acme")
    assert row["has_charter"] is True and row["log_exists"] is True and row["log_size"] == 3
    assert row["authority"]["issued_by"] == "owner"
    assert api.charter_status("acme")["is_loopback_only"] is True
    assert api.planner_data("acme") == {"slug": "acme", "present": True, "state": {"goal": "g"}}
    assert sse.stream_path(slug="acme") == root / "targets" / "acme" / ".crucible-v2.log"
    assert sse.log_path_for(None) == paths.v2_root() / ".crucible-v2.log"


def test_http_library_and_charter_routes_return_the_honest_empty_shape(deploy):
    """The live reproduction: a raw ``GET /api/library/../../…`` used to answer has_charter / log_exists /
    log_size / evidence_count for a directory outside the deployment, and the authority file's content."""
    t = _traversals(deploy)
    with _serve() as port:
        for slug in (t["rel_targets"], t["rel_authority"]):
            for route in ("/api/library/", "/api/charter/", "/api/planner/"):
                status, body = _raw_get(port, route + slug)
                assert status == 200, (route, slug, body)          # the route's existing honest-empty shape
                assert _SECRET_SCOPE not in body and _SECRET_ISSUER not in body, (route, slug)
                assert _SECRET_PLAN not in body, (route, slug)
                doc = json.loads(body)
                if route == "/api/library/":
                    assert doc["has_charter"] is False and doc["log_exists"] is False
                    assert doc["log_size"] == 0 and doc["evidence_count"] == 0
                    assert doc["authority"] is None and doc["runs"] == []
                elif route == "/api/charter/":
                    assert doc["authority"] is None and doc["scope"] == []
                    assert doc["charter_present"] is False
                else:
                    assert doc["present"] is False
        status, body = _raw_get(port, "/api/library/acme")          # control: a real engagement
        assert status == 200 and json.loads(body)["has_charter"] is True


def test_http_event_stream_refuses_a_traversal_slug_with_a_404(deploy):
    """``GET /api/events?slug=<dir outside the tree>`` used to answer 200 text/event-stream and live-tail
    that directory's ``.crucible-v2.log``. It must be a clean 404 BEFORE any stream header is sent."""
    from urllib.parse import quote
    t = _traversals(deploy)
    with _serve() as port:
        for slug in (t["absolute"], t["rel_targets"]):
            # Read the status line only: a stream never ends, so reading its body would hang until the
            # client timeout instead of failing on the status.
            r, c = _raw_get(port, f"/api/events?slug={quote(slug, safe='')}", read=False)
            try:
                assert r.status == 404, (slug, r.status, r.getheader("Content-Type"))
                body = r.read().decode("utf-8")
            finally:
                c.close()
            assert _SECRET_EVENT not in body and "unsafe engagement slug" in body, body
        # control: a real engagement's slug still opens the live tail
        r, c = _raw_get(port, "/api/events?slug=acme", read=False)
        try:
            assert r.status == 200
            assert r.getheader("Content-Type", "").startswith("text/event-stream")
        finally:
            c.close()


# ---------------------------------------------------------------------------
# 2. the run-id guard's anchor
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("rid", ["victim\n", "a\n", "20261111T101500.123-0001\n"])
def test_run_id_guard_refuses_a_trailing_newline(rid):
    with pytest.raises(ValueError):
        actions._safe_run_id(rid)
    with pytest.raises(ValueError):
        actions.run_dir(rid)
    with pytest.raises(ValueError):
        sessions._safe_session_id(rid)
    with pytest.raises(ValueError):
        labels.safe_run_id(rid)


@pytest.mark.parametrize("rid", ["victim", "20261111T101500.123-0001", "Run_1.b-2", "a"])
def test_run_id_guard_still_accepts_real_ids(rid):
    assert actions._safe_run_id(rid) == rid
    assert actions._safe_run_id(actions._new_run_id())


def test_a_newline_suffixed_session_cannot_be_created_beside_its_victim(deploy):
    """The consequence of the bad anchor: ``victim\\n`` was a SECOND registered session whose graph
    partition (the store drops the newline) was ``victim``'s — a cross-session read and a collateral drop."""
    assert sessions.create_session(name="v", kind="chat", session_id="victim").get("ok") is True
    res = sessions.create_session(name="evil", kind="chat", session_id="victim\n")
    assert "error" in res and not res.get("ok")
    assert sorted(p.name for p in sessions._sessions_dir().iterdir() if p.is_dir()) == ["victim"]
    # ...and the newline id can no longer address victim's partition (read it, or drop it on a hard delete).
    for op in (lambda: sessions.session_graph_partition("victim\n"),
               lambda: sessions.session_graph("victim\n", project=False),
               lambda: sessions.delete_session("victim\n", hard=True)):
        with pytest.raises(ValueError):
            op()
    assert sessions.get_session("victim").get("session", {}).get("id") == "victim"


def test_the_sibling_slug_patterns_are_anchored_too():
    """``oob_collaborator._SLUG_RE`` and ``labels._SAFE_SLUG`` carried the same ``$``. Both callers strip
    first, so it was not reachable — the pattern itself is pinned so it stays unreachable if that changes."""
    for pat in (oob_collaborator._SLUG_RE, labels._SAFE_SLUG, actions._SAFE_RUN_ID, actions._SLUG_RE):
        assert pat.match("victim") is not None
        assert pat.match("victim\n") is None, pat.pattern
