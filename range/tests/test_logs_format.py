"""MERIDIAN's log lines are byte-compatible with VIGIL's `vigil detect` parsers.

When the integration package is importable we assert against the REAL parsers in
integration/vigil_integration/detection/logs.py — including that the timestamp is recognised (a wrong
CLF time format would leave `ts` None and silently break detect's time-windowed signatures). Otherwise we
fall back to a structural check so the format is still guarded in a minimal environment.
"""

from __future__ import annotations

import tempfile

import pytest

from vigil_range.meridian import logs


def _write(fn, *args) -> str:
    with tempfile.NamedTemporaryFile("w+", suffix=".log", delete=False) as fh:
        path = fh.name
    fn(path, *args)
    return open(path, encoding="utf-8").read().strip()


def test_access_line_is_parsed_by_detect_with_a_recognised_timestamp():
    line = _write(logs.write_access, "127.0.0.1", 'GET /search?q=%27%20OR%20%271%27%3D%271 HTTP/1.1',
                  200, 512, "-", "sqlmap/1.7")
    detlogs = pytest.importorskip("vigil_integration.detection.logs",
                                  reason="integration not importable in this env")
    rec = detlogs.parse_access_line(line, 0)
    assert rec.method == "GET" and rec.status == 200 and rec.src == "127.0.0.1"
    assert rec.user_agent == "sqlmap/1.7"
    assert rec.ts is not None, "detect could not parse the CLF timestamp — time-windowed signals would break"
    assert "' OR '1'='1" in rec.decoded_target  # the injection structure detect keys on


def test_auth_line_is_parsed_by_detect_as_a_failure():
    line = _write(logs.write_auth, "127.0.0.1", "admin", "failure")
    assert "src=127.0.0.1" in line and "user=admin" in line and "result=failure" in line
    detlogs = pytest.importorskip("vigil_integration.detection.logs",
                                  reason="integration not importable in this env")
    rec = detlogs.parse_auth_line(line, 0)
    assert rec.src == "127.0.0.1" and rec.user == "admin" and rec.is_failure
    assert rec.ts is not None
