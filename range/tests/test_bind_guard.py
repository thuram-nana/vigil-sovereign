"""The range binds LOOPBACK ONLY — stricter than VIGIL's own bind_ok (no private/LAN/tunnel address)."""

from __future__ import annotations

from vigil_range.launcher import is_loopback_host, run_up


def test_loopback_addresses_are_accepted():
    for host in ("127.0.0.1", "127.0.0.5", "::1", "localhost", "LOCALHOST"):
        assert is_loopback_host(host), host


def test_non_loopback_is_refused():
    # public, LAN/RFC1918, tunnel/CGNAT, unspecified, and a name that is not localhost — all refused.
    for host in ("0.0.0.0", "8.8.8.8", "192.168.1.10", "10.0.0.9", "172.16.5.5",
                 "100.64.0.1", "example.com", "::", "fe80::1", ""):
        assert not is_loopback_host(host), host


def test_run_up_refuses_a_public_bind(tmp_path, capsys):
    # run_up must refuse before binding anything when handed a non-loopback host.
    rc = run_up("meridian", base_dir=str(tmp_path), host="0.0.0.0")
    assert rc == 2
    assert "LOOPBACK ONLY" in capsys.readouterr().err
