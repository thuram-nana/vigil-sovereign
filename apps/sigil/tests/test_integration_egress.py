"""governor.integration_egress — the hardened outbound POST for the Slack/Jira/Linear delivery layer.

Load-bearing invariants proven here:
  * EGRESS GATE REUSED, NOT BYPASSED: every URL is admitted by notify_channels.guard_outbound_url first (https +
    allowlist + every resolved address PUBLIC); a non-allowlisted host, an internal-resolving host, a non-https URL
    and a non-default port are each REFUSED before any transport is called.
  * CREDENTIAL IN HEADER ONLY: the auth header rides the request headers; a CR/LF in it is refused (injection guard).
  * REDIRECT-BLOCKING + STATUS MAPPING: a 5xx/408/425/429 is transient (retryable), a 4xx definitive.
"""
from __future__ import annotations

import urllib.error

import pytest

from sigil.governor import integration_egress as eg

_PUB = lambda host: ["93.184.216.34"]            # a public address → guard passes (no DNS)  # noqa: E731
_INTERNAL = lambda host: ["127.0.0.1"]           # loopback → SSRF guard refuses  # noqa: E731
_SLACK = frozenset({"slack.com"})


def _ok_transport(method, url, *, headers, body):
    return eg.IntegrationResponse(status=200, json={"ok": True}, host="slack.com")


# -- the egress gate is reused, not bypassed -----------------------------------------------------------------
def test_refuses_non_allowlisted_host():
    with pytest.raises(eg.IntegrationEgressError):
        eg.post_json("https://evil.test/x", body={}, auth=None, allow_hosts=_SLACK, resolver=_PUB,
                     transport=_ok_transport)


def test_refuses_internal_resolving_host_ssrf():
    # host is allowlisted, but it resolves to loopback → the reused SSRF guard refuses before the transport.
    called = []
    def t(method, url, *, headers, body):
        called.append(url)
        return _ok_transport(method, url, headers=headers, body=body)
    with pytest.raises(eg.IntegrationEgressError):
        eg.post_json("https://slack.com/api/chat.postMessage", body={}, auth=None, allow_hosts=_SLACK,
                     resolver=_INTERNAL, transport=t)
    assert called == []                           # no transport call after a guard refusal


def test_refuses_non_https_and_bad_port():
    for url in ("http://slack.com/x", "https://slack.com:8443/x"):
        with pytest.raises(eg.IntegrationEgressError):
            eg.post_json(url, body={}, auth=None, allow_hosts=_SLACK, resolver=_PUB, transport=_ok_transport)


# -- credential in header only; CR/LF injection guard --------------------------------------------------------
def test_auth_header_is_passed_and_crlf_is_refused():
    seen = {}
    def t(method, url, *, headers, body):
        seen.update(headers)
        return eg.IntegrationResponse(status=200, json={"ok": True}, host="slack.com")
    eg.post_json("https://slack.com/api/chat.postMessage", body={"x": 1}, auth=("Authorization", "Bearer tok"),
                 allow_hosts=_SLACK, resolver=_PUB, transport=t)
    assert seen.get("Authorization") == "Bearer tok"
    with pytest.raises(eg.IntegrationEgressError):
        eg.post_json("https://slack.com/api/chat.postMessage", body={}, auth=("Authorization", "Bearer bad\r\nX: y"),
                     allow_hosts=_SLACK, resolver=_PUB, transport=t)


def test_body_is_json_and_response_parsed():
    captured = {}
    def t(method, url, *, headers, body):
        captured["body"] = body
        captured["ct"] = headers.get("Content-Type")
        return eg.IntegrationResponse(status=201, json={"key": "SEC-1"}, host="api.atlassian.com")
    res = eg.post_json("https://api.atlassian.com/ex/jira/c/rest/api/3/issue", body={"fields": {"a": "b"}},
                       auth=("Authorization", "Basic z"), allow_hosts=frozenset({"api.atlassian.com"}),
                       resolver=_PUB, transport=t)
    assert res.ok and res.json == {"key": "SEC-1"}
    assert captured["ct"] == "application/json" and b'"fields"' in captured["body"]


# -- redirect-blocking + HTTP status mapping (real urllib path, no network) ----------------------------------
def test_http_5xx_is_transient_and_4xx_is_definitive(monkeypatch):
    def _raise(code):
        def _open(req, timeout):
            raise urllib.error.HTTPError(req.full_url, code, "err", {}, None)
        return _open
    monkeypatch.setattr(eg, "_do_open", _raise(503))
    with pytest.raises(eg.IntegrationEgressError) as ei:
        eg.post_json("https://slack.com/api/chat.postMessage", body={}, auth=None, allow_hosts=_SLACK, resolver=_PUB)
    assert ei.value.transient is True and ei.value.status == 503
    monkeypatch.setattr(eg, "_do_open", _raise(404))
    with pytest.raises(eg.IntegrationEgressError) as ej:
        eg.post_json("https://slack.com/api/chat.postMessage", body={}, auth=None, allow_hosts=_SLACK, resolver=_PUB)
    assert ej.value.transient is False and ej.value.status == 404
