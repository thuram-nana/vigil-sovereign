"""report.push — the OUTBOUND report push (webhook / Slack), gated + opt-in + proven-fact-disciplined.

Pins: the payload separates facts from leads (facts_only drops leads); dry-run never sends; a send error
is best-effort (never raised); and the production sender POSTs to EXACTLY the sink URL with a
correlatable UA, refusing redirects and non-http. Loopback only — nothing leaves the test host.
"""

from __future__ import annotations

import pytest

from .conftest import make_fact, make_lead
from framework.v2.report.push import (
    PushConfig,
    build_push_payload,
    push_report,
    push_via_urllib,
)

_FINDINGS = [make_fact(), make_lead()]


# ---------------------------------------------------------------------------
# payload shaping — proven-fact discipline
# ---------------------------------------------------------------------------


def test_webhook_payload_marks_facts_and_leads():
    doc = build_push_payload(_FINDINGS, PushConfig(sink="webhook", url="https://h/x"))
    assert doc["summary"]["facts"] == 1 and doc["summary"]["leads"] == 1
    by_fact = {f["provenance"]["is_fact"] for f in doc["findings"]}
    assert by_fact == {True, False}   # the fact and the lead are distinguishable, never conflated


def test_facts_only_drops_leads():
    doc = build_push_payload(_FINDINGS, PushConfig(sink="webhook", url="https://h/x", facts_only=True))
    assert len(doc["findings"]) == 1 and doc["findings"][0]["provenance"]["is_fact"] is True


def test_slack_payload_is_a_text_message():
    msg = build_push_payload(_FINDINGS, PushConfig(sink="slack", url="https://h/x"))
    assert set(msg) == {"text"}
    assert "FACT" in msg["text"] and "lead" in msg["text"]


# ---------------------------------------------------------------------------
# push_report — send injection, dry-run, best-effort
# ---------------------------------------------------------------------------


def test_push_delivers_via_injected_send():
    sent = {}

    def send(url, headers, body):
        sent.update(url=url, headers=headers, body=body)
        return {"status": 202}

    r = push_report(_FINDINGS, PushConfig(sink="webhook", url="https://hooks/x"), send=send)
    assert r.pushed and r.status == 202 and r.facts == 1 and r.leads == 1
    assert sent["url"] == "https://hooks/x" and len(sent["body"]["findings"]) == 2


def test_dry_run_never_sends_but_returns_payload():
    called = []
    r = push_report(_FINDINGS, PushConfig(sink="webhook", url="https://h/x", dry_run=True),
                    send=lambda *a: called.append(1) or {"status": 200})
    assert not called and r.pushed is False and r.payload is not None


def test_non_2xx_is_not_pushed():
    r = push_report(_FINDINGS, PushConfig(sink="webhook", url="https://h/x"),
                    send=lambda *a: {"status": 500})
    assert r.pushed is False and r.status == 500


def test_send_error_is_best_effort_never_raises():
    def boom(*a):
        raise RuntimeError("network down")
    r = push_report(_FINDINGS, PushConfig(sink="webhook", url="https://h/x"), send=boom)
    assert r.pushed is False and "network down" in r.note


def test_malformed_finding_is_best_effort_never_raises():
    """Review w9dag6plf (LOW): grading/payload-build must be INSIDE the best-effort guard, so a malformed
    --from-json finding returns a PushResult(pushed=False) instead of raising (never sinks the run)."""
    bad = [{"finding_slug": "x", "severity": "High"}]  # missing required FindingPayload fields
    r = push_report(bad, PushConfig(sink="webhook", url="https://h/x"), send=lambda *a: {"status": 200})
    assert r.pushed is False and "payload build failed" in r.note
    # a non-dict list element (a realistic malformed export) likewise never raises
    r2 = push_report(["just-a-string"], PushConfig(sink="webhook", url="https://h/x"),
                     send=lambda *a: {"status": 200})
    assert r2.pushed is False


# ---------------------------------------------------------------------------
# push_via_urllib — the production gated sender (loopback only)
# ---------------------------------------------------------------------------


def test_gated_sender_refuses_non_http():
    with pytest.raises(ValueError):
        push_via_urllib("ftp://sink/x", {}, {"a": 1})
    with pytest.raises(ValueError):
        push_via_urllib("file:///etc/passwd", {}, {})


def test_gated_sender_posts_with_correlatable_ua(httpserver):
    from werkzeug.wrappers import Response
    seen = {}

    def handler(request):
        seen["ua"] = request.headers.get("User-Agent")
        seen["ct"] = request.headers.get("Content-Type")
        seen["auth"] = request.headers.get("X-Auth")
        seen["body"] = request.get_json(silent=True)
        return Response("ok", status=200)

    httpserver.expect_request("/hook", method="POST").respond_with_handler(handler)
    url = httpserver.url_for("/hook")
    res = push_via_urllib(url, {"X-Auth": "tok"}, {"hello": "world"})
    assert res["status"] == 200
    assert "OBSIDIAN/1.0" in seen["ua"] and "authorized owner-test" in seen["ua"]   # correlatable
    assert seen["ct"] == "application/json" and seen["auth"] == "tok"               # operator auth carried
    assert seen["body"] == {"hello": "world"}


def test_gated_sender_refuses_redirects(httpserver):
    from werkzeug.wrappers import Response
    hit_target = {"n": 0}
    httpserver.expect_request("/redirect").respond_with_response(
        Response(status=302, headers={"Location": httpserver.url_for("/internal")}))
    httpserver.expect_request("/internal").respond_with_handler(
        lambda r: hit_target.update(n=hit_target["n"] + 1) or Response("secret", status=200))
    import urllib.error
    # a refused redirect surfaces as an error (never silently follows to /internal)
    try:
        push_via_urllib(httpserver.url_for("/redirect"), {}, {})
    except urllib.error.HTTPError:
        pass
    assert hit_target["n"] == 0, "the sender followed a redirect (SSRF risk)"
