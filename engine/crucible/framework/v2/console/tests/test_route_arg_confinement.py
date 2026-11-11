"""A console GET route can only ever hand its provider ONE safe path component.

The providers behind ``/api/library/<slug>``, ``/api/charter/<slug>``, every other prefixed route and the ``/api/events?slug=`` / ``/api/blackboard?slug=`` streams join that argument
verbatim under a fixed root (``paths.authority_path``, ``paths.target_dir``, ``actions.run_dir``). Before the
boundary check a request-target such as ``/api/library/../../<dir>/x`` (any HTTP client may send one) made
``authority_path`` read ``<dir>/x.authority.json`` from an arbitrary directory and return its scope.
``test_library_route_cannot_read_an_authority_outside_the_authority_dir`` is the end-to-end proof: on the
unfixed server it returns the planted file's contents.

The run-id / slug allowlists also ended in ``$``, which matches before a trailing newline, so ``"victim\\n"``
passed them; they now end in ``\\Z``.
"""
from __future__ import annotations

import http.client
import json
import os
import threading

import pytest

from framework.v2.common import paths
from framework.v2.console import actions, labels, oob_collaborator, server

_TOKEN = "route-arg-test-token"


@pytest.fixture()
def console():
    srv = server.serve(port=0, token=_TOKEN)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    port = srv.server_address[1]

    def get(target: str) -> tuple[int, str]:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        try:
            c.putrequest("GET", target, skip_host=True)     # the raw request-target, NOT normalised
            c.putheader("Host", f"127.0.0.1:{port}")
            c.putheader("X-SIGIL-Token", _TOKEN)
            c.endheaders()
            r = c.getresponse()
            return r.status, r.read(65536).decode("utf-8", "replace")
        finally:
            c.close()

    try:
        yield get
    finally:
        srv.shutdown()
        srv.server_close()


@pytest.fixture()
def planted_authority(tmp_path):
    """An authority-shaped file in a directory that is NOT the authority dir, and the traversal slug that
    authority_path() would join onto it."""
    victim = tmp_path / "elsewhere"
    victim.mkdir()
    (victim / "x.authority.json").write_text(
        json.dumps({"authority": {"scope": ["PLANTED-OUTSIDE-THE-AUTHORITY-DIR"]}}), encoding="utf-8")
    adir = paths.ensure_authority_dir_secure()     # exists on any real host; path resolution needs it to
    rel = os.path.relpath(victim, adir)
    return f"{rel}/x"


def test_library_route_cannot_read_an_authority_outside_the_authority_dir(console, planted_authority):
    status, body = console("/api/library/" + planted_authority)
    assert "PLANTED-OUTSIDE-THE-AUTHORITY-DIR" not in body
    assert status == 404, body


def test_charter_route_cannot_read_an_authority_outside_the_authority_dir(console, planted_authority):
    status, body = console("/api/charter/" + planted_authority)
    assert "PLANTED-OUTSIDE-THE-AUTHORITY-DIR" not in body
    assert status == 404, body


@pytest.mark.parametrize("target", [
    "/api/planner/../../../../etc",
    "/api/events?slug=../../../../etc",
    "/api/blackboard?slug=../x",
    "/api/drift/ok:../../x",
    "/api/library/victim%0A",
])
def test_every_slug_bearing_route_refuses_a_traversal(console, target):
    status, body = console(target)
    assert status == 404, (target, status, body[:200])
    assert "unsafe route argument" in body


def test_a_plain_slug_and_a_blank_one_still_reach_the_provider(console):
    status, body = console("/api/library/acme-1.prod_x")
    assert status == 200, body
    assert json.loads(body)["slug"] == "acme-1.prod_x"
    status, body = console("/api/library/")
    assert status == 200 and json.loads(body)["note"] == "select an engagement"


def test_drift_pair_of_safe_run_ids_is_accepted():
    assert server._route_arg_pair("20261111-101010-001:20261110-090909-002") == \
        "20261111-101010-001:20261110-090909-002"
    with pytest.raises(ValueError):
        server._route_arg_pair("ok:../x")


@pytest.mark.parametrize("bad", ["victim\n", "a/b", "../a", ".hidden", "a..b", "-opt", "a b", "x" * 129])
def test_route_arg_refuses(bad):
    with pytest.raises(ValueError):
        server._route_arg(bad)


def test_run_id_and_slug_allowlists_refuse_a_trailing_newline():
    with pytest.raises(ValueError):
        actions._safe_run_id("victim\n")
    assert actions._safe_run_id("victim") == "victim"
    assert actions._SAFE_RUN_ID.match("victim\n") is None
    assert oob_collaborator._SLUG_RE.match("acme\n") is None
    assert labels._SAFE_SLUG.match("acme\n") is None
