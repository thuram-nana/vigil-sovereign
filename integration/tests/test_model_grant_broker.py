"""PRICING M1c — the model-grant seam (``vigil_integration.live.model_grant_broker``).

The token on this seam is a bearer credential for one run's model spend, so the seam must keep it private (0600,
never in a repr), bind it to its launch (a grant for an old nonce never drives a re-lease), only ever point at a
loopback gateway, and refuse anything hostile on read without raising.

Integration leg (framework-free, sigil-free).
"""
from __future__ import annotations

import json
import os

import pytest

from vigil_integration.live import model_grant_broker as b

URL = "http://127.0.0.1:8742"


def test_a_grant_round_trips_privately(tmp_path):
    p = b.write_model_grant(tmp_path, "cust_abc", "n-1", "vmg1.body.sig", URL)
    assert oct(p.stat().st_mode & 0o777) == "0o600" and oct(p.parent.stat().st_mode & 0o777) == "0o700"
    got = b.read_model_grant(tmp_path, "cust_abc")
    assert (got.slug, got.nonce, got.token, got.gateway_url) == ("cust_abc", "n-1", "vmg1.body.sig", URL)
    assert "vmg1.body.sig" not in repr(got)


def test_a_grant_is_bound_to_its_launch(tmp_path):
    b.write_model_grant(tmp_path, "cust_abc", "n-1", "tok", URL)
    assert b.read_model_grant(tmp_path, "cust_abc", expect_nonce="n-1") is not None
    assert b.read_model_grant(tmp_path, "cust_abc", expect_nonce="n-2") is None
    assert b.remove_model_grant(tmp_path, "cust_abc", expect_nonce="n-2") is False      # another launch's: kept
    assert b.remove_model_grant(tmp_path, "cust_abc", expect_nonce="n-1") is True
    assert b.read_model_grant(tmp_path, "cust_abc") is None
    assert b.remove_model_grant(tmp_path, "cust_abc") is False                          # idempotent


@pytest.mark.parametrize("slug", ["", "../x", "a/b", "a\\b", "x\x00y", ".."])
def test_an_unsafe_slug_is_refused(tmp_path, slug):
    with pytest.raises(ValueError):
        b.write_model_grant(tmp_path, slug, "n", "t", URL)
    assert b.read_model_grant(tmp_path, slug) is None


@pytest.mark.parametrize("url", ["http://127.0.0.1:8742", "http://127.0.0.1:8742/", "http://[::1]:9", "http://localhost:1"])
def test_the_loopback_forms_are_accepted(tmp_path, url):
    b.write_model_grant(tmp_path, "cust_abc", "n", "t", url)
    assert b.read_model_grant(tmp_path, "cust_abc").gateway_url == url


@pytest.mark.parametrize("url", ["https://api.anthropic.com", "http://10.0.0.5:8742", "http://evil.example:8742",
                                 "ftp://127.0.0.1:1", "", "http://127.0.0.1:8742@evil.example/",
                                 "http://127.0.0.1:8742.evil.example", "http://localhost:8742/v1", "http://[::1]:0",
                                 "http://127.0.0.1:99999", "http://127.0.0.1:8742?x=1", "http://127.0.0.1:"])
def test_only_a_loopback_gateway_is_accepted(tmp_path, url):
    with pytest.raises(ValueError):
        b.write_model_grant(tmp_path, "cust_abc", "n", "t", url)
    p = b.grant_path(tmp_path, "cust_abc")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"schema": b.MODEL_GRANT_SCHEMA, "slug": "cust_abc", "nonce": "n", "token": "t",
                             "gateway_url": url}))
    assert b.read_model_grant(tmp_path, "cust_abc") is None                  # a planted remote URL is refused


def test_hostile_files_are_refused_never_raised(tmp_path, monkeypatch):
    b.write_model_grant(tmp_path, "cust_abc", "n", "t", URL)
    p = b.grant_path(tmp_path, "cust_abc")
    for content in ("{not json", "[1]", json.dumps({"schema": "other"}),
                    json.dumps({"schema": b.MODEL_GRANT_SCHEMA, "slug": "cust_other", "nonce": "n", "token": "t",
                                "gateway_url": URL}),
                    json.dumps({"schema": b.MODEL_GRANT_SCHEMA, "slug": "cust_abc", "nonce": "", "token": "t",
                                "gateway_url": URL}),
                    "x" * 20_000):
        p.write_text(content)
        assert b.read_model_grant(tmp_path, "cust_abc") is None
    p.unlink()
    os.symlink(tmp_path / "elsewhere.json", p)
    (tmp_path / "elsewhere.json").write_text(json.dumps({"schema": b.MODEL_GRANT_SCHEMA, "slug": "cust_abc",
                                                         "nonce": "n", "token": "t", "gateway_url": URL}))
    assert b.read_model_grant(tmp_path, "cust_abc") is None                  # never follows a symlink
    p.unlink()
    valid = json.dumps({"schema": b.MODEL_GRANT_SCHEMA, "slug": "cust_abc", "nonce": "n", "token": "t",
                        "gateway_url": URL})
    inside = b.grants_root(tmp_path) / "planted.json"
    inside.write_text(valid)
    os.symlink(inside, p)
    assert b.read_model_grant(tmp_path, "cust_abc") is None                  # ... even to a valid grant beside it
    real = b.grant_path
    monkeypatch.setattr(b, "grant_path", lambda base, slug: b.grants_root(base) / f"{slug}.json")
    assert b.read_model_grant(tmp_path, "cust_abc") is None   # ... even one planted after the path was checked
    monkeypatch.setattr(b, "grant_path", real)
    p.unlink()
    p.write_text(valid[:-1] + " " * 20_000 + "}")
    assert b.read_model_grant(tmp_path, "cust_abc") is None                  # oversized, however valid
    p.unlink()
    os.mkfifo(p)
    held = os.open(p, os.O_RDWR | os.O_NONBLOCK)                            # a FIFO already holding a valid grant
    try:
        os.write(held, valid.encode())
        assert b.read_model_grant(tmp_path, "cust_abc") is None              # only a regular file is read
    finally:
        os.close(held)
    os.unlink(p)
    os.mkfifo(p)
    assert b.read_model_grant(tmp_path, "cust_abc") is None                  # an empty FIFO never blocks the read
    os.unlink(p)
    for nonce, token in (("", "t"), ("n", ""), ("n", "  ")):
        with pytest.raises(ValueError):
            b.write_model_grant(tmp_path, "cust_abc", nonce, token, URL)
