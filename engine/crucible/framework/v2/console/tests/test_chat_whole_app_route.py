"""The Chat routes a WHOLE-APP / find-all request (against a loopback URL) to the autonomous SUITE engine
(`framework.v2 engage --autonomous`: crawl→discover→multi-probe→prove), while a single-endpoint request
stays on the single-loop agentic engage. A remote target is never auto-routed to suite (loopback-only)."""
from __future__ import annotations

from pathlib import Path

import pytest

from framework.v2.console import actions as actions_mod
from framework.v2.console import chat

CHAT = "wholeapp-chat"


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path / "live"))
    monkeypatch.setattr(actions_mod, "console_dir", lambda: tmp_path / ".console")
    (tmp_path / ".console" / "runs").mkdir(parents=True, exist_ok=True)
    yield tmp_path


def _capture_launch(monkeypatch):
    seen = {}

    def _fake(body):
        seen["body"] = body
        return {"run_id": "r1", "slug": str(body.get("slug") or "s"), "stream": "blackboard",
                "engine": "" if body.get("mode") == "suite" else "integration", "mode": body.get("mode")}

    monkeypatch.setattr(actions_mod, "launch_assessment", _fake)
    return seen


def test_whole_app_message_routes_to_the_autonomous_suite(monkeypatch):
    seen = _capture_launch(monkeypatch)
    out = chat.chat_send({"chat_id": CHAT, "message": "engage http://127.0.0.1:19010/ and find all vulnerabilities",
                          "mode": "url", "target": "http://127.0.0.1:19010/"})
    b = seen["body"]
    assert b["mode"] == "suite", "a whole-app/find-all request must launch the autonomous suite engine"
    assert b["scan_mode"] == "deep"
    assert b["slug"].startswith("wholeapp-"), "a fresh greenfield slug per whole-app run"
    assert "recon" in b.get("tools", [])
    assert out["status"] == "running"
    assert "whole" in out["reply"].lower() and "crawl" in out["reply"].lower()


def test_scan_all_verb_routes_to_suite(monkeypatch):
    seen = _capture_launch(monkeypatch)
    chat.chat_send({"chat_id": CHAT, "message": "/scan-all http://127.0.0.1:19010/",
                    "mode": "url", "target": "http://127.0.0.1:19010/"})
    assert seen["body"]["mode"] == "suite"


def test_single_endpoint_request_stays_single_loop(monkeypatch):
    seen = _capture_launch(monkeypatch)
    chat.chat_send({"chat_id": CHAT, "message": "engage http://127.0.0.1:19010/auth/continue?next=x",
                    "mode": "url", "target": "http://127.0.0.1:19010/auth/continue?next=x"})
    assert seen["body"]["mode"] == "url", "a single-endpoint request must NOT become a whole-app suite scan"
    assert seen["body"].get("agentic") is True


def test_remote_whole_app_is_not_auto_routed_to_suite(monkeypatch):
    # loopback-only: a remote 'find all' must never auto-launch the autonomous suite (it needs a signed charter).
    seen = _capture_launch(monkeypatch)
    chat.chat_send({"chat_id": CHAT, "message": "find all vulnerabilities on this",
                    "mode": "url", "target": "http://evil.example/"})
    assert seen["body"]["mode"] != "suite"


def test_helpers_unit():
    assert chat._wants_whole_app_scan("please find all vulnerabilities")
    assert chat._wants_whole_app_scan("/scan-all http://127.0.0.1:8080/")
    assert not chat._wants_whole_app_scan("engage http://127.0.0.1:8080/login")
    assert chat._is_loopback_url("http://127.0.0.1:19010/x")
    assert chat._is_loopback_url("http://localhost:8080/")
    assert chat._is_loopback_url("http://[::1]:8080/")
    assert not chat._is_loopback_url("http://evil.example/")
    # red-pen: attacker-registrable names that merely START with 127. are NOT loopback
    assert not chat._is_loopback_url("http://127.0.0.1.evil.com/")
    assert not chat._is_loopback_url("http://127.evil.com/")
    assert not chat._is_loopback_url("http://127.0.0.1@evil.com/")


def test_whole_app_route_refused_when_restricted(monkeypatch):
    # red-pen HIGH: a whole-app suite launch must be CONTAINED by restricted mode (emergency stop), like the
    # agentic path — the suite branch now consults _launch_contained_reason before provisioning/spawning.
    import vigil_integration.restricted_mode as rm
    monkeypatch.setattr(rm, "is_restricted", lambda base_dir: True)
    spawned = {"n": 0}
    monkeypatch.setattr(actions_mod, "_vigil_bin", lambda: "vigil")
    monkeypatch.setattr(actions_mod, "_spawn_background",
                        lambda *a, **k: spawned.__setitem__("n", spawned["n"] + 1))
    out = actions_mod.launch_assessment({"mode": "suite", "target": "http://127.0.0.1:19010/",
                                         "objective": "x", "scan_mode": "deep", "slug": "wholeapp-x",
                                         "session_id": "s", "tools": ["recon"]})
    assert out.get("error") and "restricted" in out["error"].lower(), out
    assert spawned["n"] == 0, "a restricted-mode whole-app launch must NOT spawn"
