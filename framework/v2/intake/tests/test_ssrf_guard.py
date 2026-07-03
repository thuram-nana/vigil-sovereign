"""
Tests for the intake SSRF guard (`assert_public_target`) and its wiring
into the Fetcher and the intake entry point.

No request ever leaves the host: the reject cases raise before any
socket opens; the allow cases run against localhost `pytest-httpserver`.
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest
from pytest_httpserver import HTTPServer

from framework.v2.common import ethics, paths
from framework.v2.intake import intake as intake_mod
from framework.v2.intake.http import Fetcher, SSRFRefused, assert_public_target


# ---------------------------------------------------------------------------
# assert_public_target — scheme filtering
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_INFO",
        "ftp://internal.example/x",
        "data:text/plain,hi",
    ],
)
def test_non_http_schemes_are_refused(url: str) -> None:
    with pytest.raises(SSRFRefused):
        assert_public_target(url)


@pytest.mark.parametrize("url", ["http://example.com/", "https://example.com/"])
def test_http_schemes_allowed_for_public_names(url: str) -> None:
    # resolve=False so the test needs no DNS; a public hostname passes.
    assert_public_target(url, resolve=False) is None


# ---------------------------------------------------------------------------
# assert_public_target — private / metadata IP literals
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",   # cloud metadata
        "http://127.0.0.1/",                          # loopback
        "http://127.0.0.1:6379/",                     # loopback + port
        "http://10.0.0.5/",                           # RFC1918
        "http://192.168.1.1/",                        # RFC1918
        "http://172.16.0.1/",                         # RFC1918
        "http://0.0.0.0/",                            # unspecified
        "http://[::1]/",                              # IPv6 loopback
        "http://[fd00::1]/",                          # IPv6 unique-local (private)
        "http://[::ffff:127.0.0.1]/",                 # IPv4-mapped loopback
    ],
)
def test_private_and_metadata_ip_literals_refused(url: str) -> None:
    with pytest.raises(SSRFRefused):
        assert_public_target(url)  # literal IPs need no DNS


def test_public_ip_literal_allowed() -> None:
    assert_public_target("http://93.184.216.34/") is None


# ---------------------------------------------------------------------------
# assert_public_target — DNS-rebinding of a hostname to a private IP
# ---------------------------------------------------------------------------


def test_hostname_resolving_to_private_ip_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Simulate an authorised hostname whose A-record has been flipped to
    the cloud-metadata address (DNS rebinding). getaddrinfo returns the
    private IP; the guard must refuse."""

    def fake_getaddrinfo(host, port, *a, **k):
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "",
                 ("169.254.169.254", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(SSRFRefused):
        assert_public_target("https://authorized.example/")


def test_unresolvable_hostname_is_not_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An NXDOMAIN is not an SSRF; the guard stays silent and lets the
    request fail on its own."""

    def boom(host, port, *a, **k):
        raise socket.gaierror("Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    assert assert_public_target("https://does-not-exist.example/") is None


# ---------------------------------------------------------------------------
# Fetcher wiring — the guard fires before the socket opens
# ---------------------------------------------------------------------------


def test_fetcher_refuses_metadata_ip_before_request() -> None:
    f = Fetcher(base_url="http://169.254.169.254")
    with pytest.raises(SSRFRefused):
        f.get("/latest/meta-data/")
    # nothing was recorded because the request was refused pre-flight
    assert f.used == 0


def test_fetcher_blocks_loopback_host_on_live_path(
    httpserver: HTTPServer,
) -> None:
    """The localhost httpserver binds to a loopback address; that is
    exactly what the guard blocks. Confirm the guard runs on the live
    fetch path by resolving `localhost` → 127.0.0.1 and refusing before
    the server is ever contacted."""
    httpserver.expect_request("/x").respond_with_data("ok")
    # httpserver is on loopback → the SSRF guard must refuse it.
    f = Fetcher(base_url=httpserver.url_for("/"))
    with pytest.raises(SSRFRefused):
        f.get("/x")
    assert len(httpserver.log) == 0


# ---------------------------------------------------------------------------
# intake.run entry-point guard
# ---------------------------------------------------------------------------


@pytest.fixture()
def _authorized(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    ledger = tmp_path / "auth.txt"
    monkeypatch.setattr(ethics, "authorization_ledger", lambda: ledger)
    tdir = tmp_path / "targets"
    tdir.mkdir()
    monkeypatch.setattr(paths, "targets_root", lambda: tdir)
    monkeypatch.setattr(paths, "target_dir", lambda slug: tdir / slug)

    def authorize(host: str) -> None:
        ledger.write_text(f"{ethics.now_iso()} | testbot | {host}\n")

    return authorize


def test_intake_run_refuses_metadata_ip(_authorized) -> None:
    _authorized("169.254.169.254")
    with pytest.raises(SSRFRefused):
        intake_mod.run("http://169.254.169.254/", record_to_memory=False)


def test_intake_run_refuses_non_http_scheme(_authorized) -> None:
    _authorized("internal.example")
    with pytest.raises(SSRFRefused):
        intake_mod.run("ftp://internal.example/", record_to_memory=False)
