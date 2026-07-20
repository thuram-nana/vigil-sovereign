"""Tests for verify.oob — real localhost callback round-trips via urllib."""

from __future__ import annotations

import urllib.request

import pytest

from ..oob import OOBReceiver, _token_of


def _get(url: str, data: bytes | None = None) -> int:
    req = urllib.request.Request(url, data=data)
    with urllib.request.urlopen(req, timeout=5) as resp:
        resp.read()
        return resp.status


def test_binds_loopback_only() -> None:
    with pytest.raises(ValueError):
        OOBReceiver(host="0.0.0.0")


def test_token_extraction() -> None:
    assert _token_of("/abc123/foo?x=1") == "abc123"
    assert _token_of("/abc123") == "abc123"
    assert _token_of("/") == ""


def test_roundtrip_records_hit() -> None:
    with OOBReceiver() as oob:
        assert oob.base_url.startswith("http://127.0.0.1:")
        token, url = oob.register_token()
        assert oob.poll(token) == []  # registered but not yet hit

        status = _get(url)
        assert status == 200

        hits = oob.poll(token)
        assert len(hits) == 1
        assert hits[0].token == token
        assert hits[0].method == "GET"
        assert hits[0].client_ip == "127.0.0.1"


def test_roundtrip_with_path_and_query_dns_style() -> None:
    with OOBReceiver() as oob:
        token, url = oob.register_token()
        _get(f"{url}/exfil/data?leak=secret")
        hits = oob.poll(token)
        assert len(hits) == 1
        assert hits[0].path == f"/{token}/exfil/data"
        assert hits[0].query == "leak=secret"


def test_post_with_body_is_recorded() -> None:
    with OOBReceiver() as oob:
        token, url = oob.register_token()
        _get(url, data=b"blind-payload-callback")
        hits = oob.poll(token)
        assert len(hits) == 1
        assert hits[0].method == "POST"


def test_multiple_hits_accumulate() -> None:
    with OOBReceiver() as oob:
        token, url = oob.register_token()
        for _ in range(3):
            _get(url)
        assert len(oob.poll(token)) == 3


def test_tokens_are_isolated() -> None:
    with OOBReceiver() as oob:
        t1, u1 = oob.register_token()
        t2, _ = oob.register_token()
        assert t1 != t2
        _get(u1)
        assert len(oob.poll(t1)) == 1
        assert oob.poll(t2) == []


def test_unregistered_token_polls_empty() -> None:
    with OOBReceiver() as oob:
        assert oob.poll("never-registered") == []


def test_server_stops_cleanly() -> None:
    oob = OOBReceiver().start()
    token, url = oob.register_token()
    _get(url)
    oob.stop()
    # After stop, accessing the port raises rather than silently listening.
    with pytest.raises(RuntimeError):
        oob.register_token()
