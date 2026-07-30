"""B7 — orphan-surface cleanup: three HTTP routes with no unified-UI consumer are removed, while their
PROVIDER functions REMAIN (used internally + keep their unit tests), matching the A6 precedent that dropped
``/api/engagement/`` and ``/api/reports/`` but kept ``engagement_detail`` / ``reports_data``.

Removed HTTP surface:
  * POST /api/launch/scan      — redundant: ``launch_assessment`` already spawns the SAME loopback ``scan``
    CLI for a ``mode=url`` loopback target (the wired, tested path), so a separate route duplicated it.
  * GET  /api/authority/<slug> — the unified UI reads the same governance picture via ``/api/charter/<slug>``
    (``charter_status``); ``authority_full`` stays (used by ``charter_status`` + ``framework.v2.api.reads``).
  * GET  /api/session/<id>     — the unified UI uses ``/api/sessions`` (plural) + the POST mutations;
    ``session_detail`` stays (used by the dossier/report assembly in ``actions.py``).

Pins: the removed routes now 404, the surviving read + mutation routes still work, and the provider functions
are still importable + behave — so the cleanup dropped a ROUTE, not a capability.
"""

from __future__ import annotations

import threading
import urllib.error
import urllib.request
from contextlib import contextmanager

from framework.v2.console import actions, api, server


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


def _get_status(url):
    try:
        with urllib.request.urlopen(url, timeout=5) as r:  # noqa: S310 (loopback test)
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def _post(url, *, csrf=True, data=b"{}"):
    req = urllib.request.Request(url, method="POST", data=data)
    if csrf:
        req.add_header("X-Requested-With", "vigil-ui")
    req.add_header("Sec-Fetch-Site", "same-origin")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310 (loopback test)
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def test_removed_routes_404(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path))
    with _running() as base:
        # POST /api/launch/scan is gone: a same-origin request passes the CSRF guard, then finds no route.
        st, body = _post(base + "/api/launch/scan", data=b'{"target":"http://127.0.0.1/"}')
        assert st == 404 and b"unknown action" in body
        # the two removed GET prefix routes → 404 unknown endpoint
        assert _get_status(base + "/api/authority/acme") == 404
        assert _get_status(base + "/api/session/whatever") == 404


def test_surviving_routes_still_work(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path))
    with _running() as base:
        assert _get_status(base + "/api/sessions") == 200        # plural session LIST survives
        assert _get_status(base + "/api/charter/acme") == 200    # the governance picture survives
        # a session MUTATION still routes (the guard passes → it is NOT a 404)
        st, _ = _post(base + "/api/session/create", data=b'{"name":"x"}')
        assert st != 404


def test_provider_functions_remain():
    # dropped the ROUTE, not the capability — the providers still exist + behave
    assert "note" in api.authority_full("")                          # kept: used by charter_status + reads.py
    assert api.session_detail("nope-nonexistent-xyz").get("error")   # kept: used by dossier/report assembly
    assert "loopback" in actions.launch_scan("http://not-loopback.example/")["error"]  # kept + tested
