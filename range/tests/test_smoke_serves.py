"""The range comes up on loopback, serves the themed portal + control plane, and logs the gov plane."""

from __future__ import annotations

import os
import time
import urllib.error
import urllib.request

import pytest
from conftest import free_port

from vigil_range.meridian import Config, serve
from vigil_range.meridian.app import stop_servers


@pytest.fixture()
def running(tmp_path):
    cfg = Config(base_dir=str(tmp_path), target_port=free_port(), control_port=free_port())
    target, control = serve(cfg, hardened=False, block=False)
    time.sleep(0.3)
    try:
        yield cfg
    finally:
        stop_servers(target, control)


def _get(url: str, ua: str = "pytest/1.0") -> tuple[int, str]:
    req = urllib.request.Request(url, headers={"User-Agent": ua})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def test_home_serves_marker_and_banner(running):
    status, body = _get(f"http://127.0.0.1:{running.target_port}/")
    assert status == 200
    assert "MERIDIAN National Permits" in body  # the range-registry readiness marker
    assert "INTENTIONALLY VULNERABLE" in body


def test_health_and_robots_and_404(running):
    base = f"http://127.0.0.1:{running.target_port}"
    assert _get(base + "/healthz")[0] == 200
    s, body = _get(base + "/robots.txt")
    assert s == 200 and "Disallow: /admin" in body
    assert _get(base + "/nope")[0] == 404


def test_control_plane_is_separate_and_unlogged(running):
    s, body = _get(f"http://127.0.0.1:{running.control_port}/")
    assert s == 200 and "Range Control" in body
    # the gov access.log records target-plane traffic; control-plane traffic must NOT appear there.
    _get(f"http://127.0.0.1:{running.target_port}/")
    time.sleep(0.1)
    with open(running.access_log, encoding="utf-8") as fh:
        log = fh.read()
    assert "GET / HTTP" in log
    assert str(running.control_port) not in log and "Range Control" not in log


def test_access_log_is_written_in_clf(running):
    _get(f"http://127.0.0.1:{running.target_port}/healthz")
    time.sleep(0.1)
    assert os.path.exists(running.access_log)
    line = open(running.access_log, encoding="utf-8").readline()
    assert '"GET ' in line and '"pytest/1.0"' in line
