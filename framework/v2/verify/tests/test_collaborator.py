"""
The self-hostable OOB collaborator — the operator-run relay records inbound
interactions and the scanner-side client polls them, so blind classes confirm on
REMOTE targets while the scanner's only egress stays the allowlisted relay.

All traffic here is loopback; the relay simply plays the role of the operator's
allowlisted host.
"""

from __future__ import annotations

import urllib.error
import urllib.request

import json

import pytest

from framework.v2.scanner.checks import OOBCheck
from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate
from framework.v2.verify.collaborator import _POLL_PREFIX, _RELAY_KEY_HEADER, RelayClient, RelayServer
from framework.v2.verify.confirmation import confirm_finding
from framework.v2.verify.verifier import OracleVerifier


def _fetch(url: str) -> None:
    try:
        urllib.request.urlopen(url, timeout=5).read()  # noqa: S310 (loopback)
    except urllib.error.URLError:
        pass


def test_relay_records_and_client_polls_the_interaction() -> None:
    with RelayServer(secret="s3cret") as relay:
        client = RelayClient(relay.base_url, "s3cret")
        token, callback = client.register_token()
        assert callback == f"{relay.base_url}/{token}"
        assert client.poll(token) == []              # nothing yet
        _fetch(f"{callback}/probe?x=1")              # the "target" fetches the callback
        hits = client.poll(token)
        assert hits and hits[0].token == token and hits[0].method == "GET"


def test_poll_requires_the_secret() -> None:
    with RelayServer(secret="right") as relay:
        client_bad = RelayClient(relay.base_url, "wrong")
        token, callback = client_bad.register_token()
        _fetch(f"{callback}/x")
        # wrong secret -> the relay returns 403, the client fails safe to []
        assert client_bad.poll(token) == []
        # right secret (sent in the X-Relay-Key HEADER now) sees the recorded hit
        assert RelayClient(relay.base_url, "right").poll(token)


def test_poll_secret_is_accepted_via_header_and_legacy_query() -> None:
    # X6: the secret authenticates via the X-Relay-Key HEADER (kept out of access logs); the
    # legacy ?key= query is still accepted server-side for back-compat.
    with RelayServer(secret="s3cret") as relay:
        client = RelayClient(relay.base_url, "s3cret")
        token, _ = client.register_token()
        poll_url = f"{relay.base_url}{_POLL_PREFIX}{token}"
        # header auth (no ?key= in the URL) → 200
        req = urllib.request.Request(poll_url, headers={_RELAY_KEY_HEADER: "s3cret"})
        with urllib.request.urlopen(req, timeout=5) as r:      # noqa: S310 (loopback)
            assert r.status == 200 and json.loads(r.read()) == []
        # legacy query auth still works (back-compat)
        with urllib.request.urlopen(f"{poll_url}?key=s3cret", timeout=5) as r:  # noqa: S310
            assert r.status == 200
        # neither → 403
        try:
            urllib.request.urlopen(poll_url, timeout=5)        # noqa: S310
            assert False, "expected 403"
        except urllib.error.HTTPError as e:
            assert e.code == 403


def test_relay_client_requires_https_for_remote() -> None:
    # X6: a non-loopback relay must use https — the poll secret + interaction data must not cross
    # the network in the clear. Loopback http and remote https are both fine.
    with pytest.raises(ValueError):
        RelayClient("http://relay.example.com:9000", "s3cret")
    RelayClient("http://127.0.0.1:9000", "s3cret")               # loopback http OK
    RelayClient("http://127.0.0.2:9000", "s3cret")               # 127.0.0.0/8 loopback OK
    RelayClient("http://[::1]:9000", "s3cret")                   # IPv6 loopback OK
    RelayClient("https://relay.example.com", "s3cret")           # remote https OK


def test_poll_failure_is_safe_empty() -> None:
    # a relay that isn't there must never crash a scan or fabricate a hit
    client = RelayClient("http://127.0.0.1:1", "s")
    assert client.poll("deadbeef") == []


def test_blind_ssrf_confirms_through_the_relay() -> None:
    """End to end: an OOBCheck driven by the RelayClient confirms blind SSRF when
    the (loopback stand-in for a remote) target fetches the minted callback."""
    with RelayServer(secret="k") as relay:
        client = RelayClient(relay.base_url, "k")
        check = OOBCheck(id="ssrf-oob", bug_class="ssrf", payload_template="{callback}")

        # a `send` that models a server-side fetch of whatever URL is injected
        def ssrf_send(req: HttpRequest) -> dict:
            from urllib.parse import parse_qs, urlsplit
            injected = parse_qs(urlsplit(req.url).query).get("url", [""])[0]
            if injected.startswith("http"):
                _fetch(injected)  # the target dereferences the attacker URL
            return {"status": 200, "body": "ok"}

        tmpl = RequestTemplate(HttpRequest(method="GET", url="http://target.example/f?url=x"))
        (pt,) = [p for p in tmpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,)) if p.name == "url"]
        ctx = check.probe(tmpl, pt, ssrf_send, client)
        assert ctx is not None
        confirmed = confirm_finding(
            finding={"bug_class": "ssrf", "title": "t", "severity": "High", "surface": "s", "summary": "x"},
            context=ctx, verifier=OracleVerifier(),
        )
        assert confirmed is not None and confirmed.confirmed_by.value == "oob_callback"
