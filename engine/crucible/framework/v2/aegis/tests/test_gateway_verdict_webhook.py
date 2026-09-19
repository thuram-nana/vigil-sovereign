"""P4 — the AEGIS gateway's OUTBOUND verdict sink.

The gateway already streams verdicts to the UI (a JSONL the console tails) and stderr. This wires the
missing external sink: an ``on_verdict`` that ALSO POSTs each verdict to an operator-configured
SIEM / webhook / Slack, via the bounded, redirects-disabled ``report.push.push_via_urllib``. These lock:
the body is the SAME browser-safe projection the file sink emits (no oracle-context leaks), webhook vs
slack format, the auth header comes from the env (never argv), it is FAIL-OPEN (a send error never reaches
the data plane), and the fan-out composes + isolates multiple sinks.
"""

from __future__ import annotations

from framework.v2.aegis import cli as C
from framework.v2.aegis.models import Verdict


def _verdict(decision="lead", attack_class="prompt_injection", action="observe"):
    # a "lead" needs no certificate (unlike "confirmed"); the sink serialises whatever verdict it is handed.
    return Verdict(decision=decision, attack_class=attack_class, confidence=0.7, action=action)


def _capture(monkeypatch):
    sent: dict = {}

    def _fake_push(url, headers, body, *, timeout=10.0):
        sent["url"] = url
        sent["headers"] = dict(headers or {})
        sent["body"] = body
        return {"status": 200}

    # the sink does `from ..report.push import push_via_urllib` at call time, so patching the module attr
    # before the sink is built binds the fake.
    monkeypatch.setattr("framework.v2.report.push.push_via_urllib", _fake_push)
    return sent


def test_webhook_sink_posts_browser_safe_verdict(monkeypatch):
    monkeypatch.delenv("AEGIS_VERDICT_WEBHOOK_AUTHORIZATION", raising=False)
    sent = _capture(monkeypatch)
    v = _verdict()
    C._make_webhook_verdict_sink("https://siem.example/hook", "webhook")(v)
    assert sent["url"] == "https://siem.example/hook"
    assert sent["body"]["kind"] == "aegis.verdict"
    # the body is EXACTLY the browser-safe projection the file sink uses — no oracle-context / internal leak.
    assert sent["body"]["verdict"] == C._ui_safe_verdict(v)
    assert sent["body"]["verdict"]["decision"] == "lead"
    assert "Authorization" not in sent["headers"]      # no auth env set


def test_slack_sink_posts_compact_text(monkeypatch):
    monkeypatch.delenv("AEGIS_VERDICT_WEBHOOK_AUTHORIZATION", raising=False)
    sent = _capture(monkeypatch)
    C._make_webhook_verdict_sink("https://hooks.slack.example/x", "slack")(_verdict())
    assert set(sent["body"]) == {"text"}
    assert "AEGIS verdict" in sent["body"]["text"] and "prompt_injection" in sent["body"]["text"]


def test_auth_header_from_env_not_argv(monkeypatch):
    monkeypatch.setenv("AEGIS_VERDICT_WEBHOOK_AUTHORIZATION", "Bearer sekret-token")
    sent = _capture(monkeypatch)
    C._make_webhook_verdict_sink("https://siem.example/hook", "webhook")(_verdict())
    assert sent["headers"].get("Authorization") == "Bearer sekret-token"


def test_webhook_sink_is_fail_open(monkeypatch):
    def _boom(url, headers, body, *, timeout=10.0):
        raise RuntimeError("network down")
    monkeypatch.setattr("framework.v2.report.push.push_via_urllib", _boom)
    # a send error must NOT raise into the data plane (gateway fail-open doctrine)
    C._make_webhook_verdict_sink("https://x.example/h", "webhook")(_verdict())


def test_compose_fans_out_and_isolates_failures():
    calls: list[str] = []

    def _ok(v):
        calls.append("ok")

    def _bad(v):
        calls.append("bad")
        raise RuntimeError("boom")

    def _also(v):
        calls.append("also")

    C._compose_verdict_sinks(_ok, _bad, _also)(_verdict())   # must not raise despite _bad
    assert calls == ["ok", "bad", "also"]                    # all ran; the failure was isolated
    assert C._compose_verdict_sinks(_ok) is _ok              # single sink returned as-is
    assert C._compose_verdict_sinks(None, None) is None      # nothing configured -> None
