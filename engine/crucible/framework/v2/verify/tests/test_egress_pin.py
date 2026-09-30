"""Tests for the engine-side never-liftable egress floor (common.egress_pin) and its wiring into the
engine's own capture connectors (reachability / tls / reachability_cloud).

The floor closes the residual named in ``egress_floor.py:23-35``: the engine capture paths used to string-
scope-check then raw-connect on a re-resolved name, so a metadata / link-local / RFC1918 destination (direct
or via DNS rebinding) could be dialled. These tests assert the floor REFUSES those and PINS the validated
address, and that each capture returns a fail-closed refusal (never an unguarded connect) when the floor
denies.
"""

from __future__ import annotations

import pytest

from framework.v2.common import egress_pin
from framework.v2.common.egress_pin import (
    EgressFloorRefused,
    _as_ip_literal,
    resolve_and_pin,
)


def _resolver(*addrs: str):
    """A fake getaddrinfo returning the given addresses for any name."""
    def fake(host, port, proto=0):  # noqa: ANN001
        return [(2, 1, 6, "", (a, port or 0)) for a in addrs]
    return fake


# --------------------------------------------------------------------------- floor logic


def test_metadata_is_refused_even_when_charter_lists_it():
    # Tier 1a is never liftable — a charter listing 169.254.169.254 cannot authorise it.
    with pytest.raises(EgressFloorRefused):
        resolve_and_pin("169.254.169.254", 80, allowed_ips=frozenset({"169.254.169.254"}))


def test_link_local_and_reserved_refused():
    for ip in ("169.254.1.1", "0.0.0.0", "224.0.0.1"):
        with pytest.raises(EgressFloorRefused):
            resolve_and_pin(ip, 80, allowed_ips=frozenset({ip}))


def test_rfc1918_refused_unless_exact_charter_literal():
    with pytest.raises(EgressFloorRefused):
        resolve_and_pin("10.0.0.5", 80, allowed_ips=frozenset())
    assert resolve_and_pin("10.0.0.5", 80, allowed_ips=frozenset({"10.0.0.5"})) == "10.0.0.5"


def test_loopback_refused_unless_scoped_and_opted_in():
    with pytest.raises(EgressFloorRefused):
        resolve_and_pin("127.0.0.1", 80, allowed_ips=frozenset())
    # charter-listed + offense opt-in (the MERIDIAN / loopback-engagement case)
    assert resolve_and_pin(
        "127.0.0.1", 80, allowed_ips=frozenset({"127.0.0.1"}),
        loopback_allowed_if_scoped=True) == "127.0.0.1"


def test_public_ip_allowed_and_returned():
    assert resolve_and_pin("93.184.216.34", 80, allowed_ips=frozenset()) == "93.184.216.34"


def test_dns_rebinding_to_metadata_is_refused():
    # A name that resolves to [public, metadata] is refused: EVERY resolved address must clear the floor.
    with pytest.raises(EgressFloorRefused):
        resolve_and_pin("evil.example", 80, allowed_ips=frozenset(),
                        resolver=_resolver("93.184.216.34", "169.254.169.254"))


def test_name_resolving_public_pins_the_ip():
    # The connection is pinned to the resolved IP, not the name — so a later re-resolve cannot swap it.
    assert resolve_and_pin("good.example", 80, allowed_ips=frozenset(),
                           resolver=_resolver("93.184.216.34")) == "93.184.216.34"


def test_empty_host_and_no_address_fail_closed():
    with pytest.raises(EgressFloorRefused):
        resolve_and_pin("", 80)
    with pytest.raises(EgressFloorRefused):
        resolve_and_pin("nowhere.example", 80, resolver=_resolver())


def test_resolver_error_fails_closed():
    def boom(host, port, proto=0):  # noqa: ANN001
        raise OSError("dns down")
    with pytest.raises(EgressFloorRefused):
        resolve_and_pin("x.example", 80, resolver=boom)


# --------------------------------------------------------------------------- charter literal extraction


def test_as_ip_literal_extracts_only_literals():
    assert _as_ip_literal("127.0.0.1") == "127.0.0.1"
    assert _as_ip_literal("http://10.0.0.5/app") == "10.0.0.5"
    assert _as_ip_literal("[::1]") == "::1"
    assert _as_ip_literal("https://[2001:db8::1]:8443/x") == "2001:db8::1"
    assert _as_ip_literal("example.com") is None
    assert _as_ip_literal("*.foo.com") is None
    assert _as_ip_literal("") is None


def test_charter_ip_literals_fails_closed_to_empty(monkeypatch):
    # No charter / parse error => empty set (stricter floor), never a raise.
    monkeypatch.setattr(egress_pin, "charter_ip_literals", egress_pin.charter_ip_literals)
    assert egress_pin.charter_ip_literals("definitely-no-such-slug-zzz") == frozenset()


# --------------------------------------------------------------------------- capture wiring (fail-closed)


def test_capture_handshake_refuses_when_floor_denies(monkeypatch):
    from framework.v2.verify import reachability
    monkeypatch.setattr(reachability, "_authorize", lambda *a, **k: None)  # isolate the floor step

    def deny(*a, **k):
        raise EgressFloorRefused("10.0.0.5 is private/internal")
    monkeypatch.setattr(egress_pin, "resolve_and_pin", deny)
    out = reachability.capture_handshake("victim.example", 80, slug="s", connect=None)
    assert out["connected"] is False and "egress floor" in out["error"]


def test_capture_tls_refuses_when_floor_denies(monkeypatch):
    from framework.v2.verify import tls
    monkeypatch.setattr(tls, "_authorize", lambda *a, **k: None)

    def deny(*a, **k):
        raise EgressFloorRefused("169.254.169.254 metadata")
    monkeypatch.setattr(egress_pin, "resolve_and_pin", deny)
    out = tls.capture_tls_handshake("victim.example", 443, slug="s", connect=None)
    assert out["connected"] is False and "egress floor" in out["error"]


def test_capture_anonymous_get_refuses_when_floor_denies(monkeypatch):
    from framework.v2.verify import reachability_cloud
    monkeypatch.setattr(reachability_cloud, "_authorize", lambda *a, **k: None)

    def deny(*a, **k):
        raise EgressFloorRefused("10.0.0.5 is private/internal")
    monkeypatch.setattr(egress_pin, "resolve_and_pin", deny)
    out = reachability_cloud.capture_anonymous_get("https://victim.example/", slug="s", connect=None)
    assert "egress floor" in out["error"]
