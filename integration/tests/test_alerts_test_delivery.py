"""NTF enablement tail — `vigil alerts --test-delivery` proves the alerting path reaches a human BEFORE an
operator relies on it. A healthy box pushes nothing, so without this a broken destination (an expired webhook, a
mail wrapper that fails) is discovered only when a REAL alarm fails to arrive.

Driven through the REAL `vigil` CLI against REAL destinations: an exec target (a script that writes what it is fed)
and a loopback HTTP webhook receiver.
"""
from __future__ import annotations

import json
import stat
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from vigil_integration import cli
from vigil_integration import unit_alerts as ua


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch, tmp_path):
    for k in ("VIGIL_ALERT_WEBHOOK_URL", "VIGIL_ALERT_EXEC"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("VIGIL_ALERT_STATE_DIR", str(tmp_path / "hb"))


def _exec_target(tmp_path: Path, *, exit_code: int = 0) -> tuple[str, Path]:
    out = tmp_path / "received.json"
    script = tmp_path / "notify.sh"
    script.write_text(f"#!/bin/sh\ncat > '{out}'\nexit {exit_code}\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return str(script), out


class _Receiver(BaseHTTPRequestHandler):
    got: list = []
    status = 204

    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("Content-Length", "0"))
        type(self).got.append(json.loads(self.rfile.read(n)))
        self.send_response(type(self).status)
        self.end_headers()

    def log_message(self, *a):
        pass


def _webhook(status=204):
    _Receiver.got, _Receiver.status = [], status
    srv = HTTPServer(("127.0.0.1", 0), _Receiver)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/hook"


def test_delivers_a_labelled_test_alert_through_every_configured_destination(tmp_path, monkeypatch, capsys):
    cmd, received = _exec_target(tmp_path)
    srv, url = _webhook()
    try:
        monkeypatch.setenv("VIGIL_ALERT_EXEC", cmd)
        monkeypatch.setenv("VIGIL_ALERT_WEBHOOK_URL", url)
        assert cli.main(["alerts", "--test-delivery", "--state-dir", str(tmp_path / "hb")]) == 0
    finally:
        srv.shutdown()
    for payload in (json.loads(received.read_text()), _Receiver.got[0]):
        assert payload["kind"] == ua.TEST_DELIVERY_KIND and payload["severity"] == "info"
        assert "TEST" in payload["detail"] and "no action" in payload["detail"]
    assert "2/2 destination(s) accepted" in capsys.readouterr().out
    hb = ua.read_delivery_heartbeat(tmp_path / "hb")
    assert hb and hb.get("epoch")                                     # a real delivery refreshes the dead-man
    log = (tmp_path / "hb" / "alert-delivery.jsonl").read_text()
    assert ua.TEST_DELIVERY_KIND in log                               # recorded like any delivery
    assert not list((tmp_path / "hb").glob("*.service.json"))         # no unit heartbeat written


def test_a_failing_destination_is_reported_and_exits_1(tmp_path, monkeypatch, capsys):
    cmd, _ = _exec_target(tmp_path, exit_code=3)
    srv, url = _webhook(status=500)
    try:
        monkeypatch.setenv("VIGIL_ALERT_EXEC", cmd)
        monkeypatch.setenv("VIGIL_ALERT_WEBHOOK_URL", url)
        assert cli.main(["alerts", "--test-delivery", "--state-dir", str(tmp_path / "hb")]) == 1
    finally:
        srv.shutdown()
    out = capsys.readouterr().out
    assert "0/2 destination(s) accepted" in out and "FIX the failures" in out
    assert "exited 3" in out and "webhook" in out and "500" in out
    assert ua.read_delivery_heartbeat(tmp_path / "hb") is None        # a failed test does not fake a delivery
    assert "alert-delivery-failed" in (tmp_path / "hb" / "alert-delivery.jsonl").read_text()


def test_a_partial_failure_is_still_a_failure(tmp_path, monkeypatch, capsys):
    cmd, received = _exec_target(tmp_path)
    srv, url = _webhook(status=403)
    try:
        monkeypatch.setenv("VIGIL_ALERT_EXEC", cmd)
        monkeypatch.setenv("VIGIL_ALERT_WEBHOOK_URL", url)
        assert cli.main(["alerts", "--test-delivery", "--state-dir", str(tmp_path / "hb"), "--json"]) == 1
    finally:
        srv.shutdown()
    res = json.loads(capsys.readouterr().out)
    assert res["ok"] is False and res["succeeded"] == 1 and res["attempted"] == 2 and len(res["failures"]) == 1
    assert received.is_file()


def test_no_destination_configured_exits_2_and_says_how(tmp_path, capsys):
    assert cli.main(["alerts", "--test-delivery", "--state-dir", str(tmp_path / "hb")]) == 2
    err = capsys.readouterr().err
    assert "VIGIL_ALERT_WEBHOOK_URL" in err and "VIGIL_ALERT_EXEC" in err
    assert not (tmp_path / "hb" / "alert-delivery.jsonl").exists()   # nothing pretended to deliver


def test_plain_alerts_behaviour_is_unchanged_without_the_flag(tmp_path, monkeypatch):
    seen = {}
    monkeypatch.setattr(ua, "cmd_test_delivery", lambda **k: seen.setdefault("called", True) and 99)
    cli.main(["alerts", "--status", "--state-dir", str(tmp_path / "hb")])
    assert "called" not in seen
