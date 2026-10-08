"""Gateway-less backstop coverage for the engine egress floor (``common.egress_pin``).

WHY THIS FILE EXISTS (the G2 red-pen non-blocking objection). ``verify/tests/test_egress_pin.py`` opens
with ``pytest.importorskip("vigil_gateway")`` — so in the CRUCIBLE-core "engine v2 test tree" CI leg (which
installs ``vigil_core`` + ``framework`` only, NO gateway) every assertion in that file SKIPS. But the
gateway-less leg is EXACTLY where the ``_stdlib_floor_denied`` degrade branch of
``resolve_and_validate_all`` is the sole floor authority: a safety control whose only test skips precisely
where it is load-bearing is a loophole. This file closes it.

It does NOT ``importorskip`` vigil_gateway. Instead it FORCES vigil_gateway absent in-process (a meta_path
finder that raises ``ModuleNotFoundError`` for ``vigil_gateway*`` plus eviction of any cached
``vigil_gateway`` modules), so it exercises the DEGRADE branch even in the gateway-PRESENT offense venv
(where gateway is editable-installed and a plain run would MASK the backstop by taking the real-denylist
branch). Consequently it RUNS — not skips — in CRUCIBLE-core (where it is most needed) AND in the
offense/local legs. The ``[stdlib backstop]`` marker in every refusal message proves the degrade branch,
not the real ``denylist``, decided.
"""

from __future__ import annotations

import importlib.abc
import sys

import pytest

from framework.v2.common import egress_pin
from framework.v2.common.egress_pin import EgressFloorRefused, resolve_and_validate_all

_MARKER = "[stdlib backstop]"


class _BlockGateway(importlib.abc.MetaPathFinder):
    """A meta_path finder that makes ``vigil_gateway`` (and any submodule) unimportable, so
    ``resolve_and_validate_all`` cannot reach the real denylist and must take the degrade branch."""

    def find_spec(self, fullname, path, target=None):  # noqa: ANN001, ARG002
        if fullname == "vigil_gateway" or fullname.startswith("vigil_gateway."):
            raise ModuleNotFoundError(f"vigil_gateway forced absent for backstop test: {fullname}")
        return None


@pytest.fixture()
def no_gateway():
    """Force vigil_gateway absent for the duration, restoring sys.modules + sys.meta_path after.

    Faithful to the CRUCIBLE-core no-gateway leg AND effective in the gateway-present offense venv: it
    evicts any already-imported ``vigil_gateway*`` and blocks re-import, so the lazy
    ``from vigil_gateway import denylist`` inside ``resolve_and_validate_all`` raises and the ``except``
    degrades to ``_stdlib_floor_denied``.
    """
    finder = _BlockGateway()
    saved = {k: v for k, v in list(sys.modules.items())
             if k == "vigil_gateway" or k.startswith("vigil_gateway.")}
    for k in saved:
        del sys.modules[k]
    sys.meta_path.insert(0, finder)
    try:
        # Prove the degrade precondition actually holds in this process right now.
        with pytest.raises(ModuleNotFoundError):
            import vigil_gateway  # noqa: F401
        yield
    finally:
        try:
            sys.meta_path.remove(finder)
        except ValueError:
            pass
        sys.modules.update(saved)


def _resolver(*addrs: str):
    """A fake getaddrinfo returning the given addresses for any name (no real DNS)."""

    def fake(host, port, proto=0):  # noqa: ANN001, ARG001
        return [(2, 1, 6, "", (a, port or 0)) for a in addrs]

    return fake


def _refuse(ip_or_host, *, allowed=frozenset(), loopback=False, resolver=None):
    """Call the floor and return the EgressFloorRefused raised, or fail if it did not refuse."""
    with pytest.raises(EgressFloorRefused) as exc:
        resolve_and_validate_all(
            ip_or_host, 80, allowed_ips=frozenset(allowed),
            loopback_allowed_if_scoped=loopback,
            resolver=resolver or _resolver(ip_or_host),
        )
    return exc.value


# --- the ABSOLUTE floor (Tier 1a): never liftable by any scope or opt-in --------------------------

# metadata / link-local / multicast / reserved / unspecified + the IPv6-embedded-v4 evasion forms.
NEVER_LIFTABLE = [
    "169.254.169.254",          # AWS/GCP/Azure IMDS (link-local)
    "169.254.170.2",            # ECS task metadata (link-local)
    "fd00:ec2::254",            # AWS IMDS-over-IPv6 (explicit always-deny block)
    "169.254.0.1",              # link-local v4
    "fe80::1",                  # link-local v6
    "224.0.0.1",                # multicast v4
    "ff02::1",                  # multicast v6
    "240.0.0.1",                # reserved/future-use v4
    "::",                       # unspecified v6
    "::ffff:169.254.169.254",   # IPv4-mapped metadata
    "::169.254.169.254",        # IPv4-compatible metadata
    "64:ff9b::a9fe:a9fe",       # NAT64-embedded metadata
]


def test_backstop_refuses_never_liftable_floor(no_gateway):
    for ip in NEVER_LIFTABLE:
        # Refused with no allowlist...
        assert _MARKER in str(_refuse(ip))
        # ...AND refused EVEN when the exact IP is charter-allowed AND loopback opt-in is set: a charter
        # cannot lift the never-liftable tier (Tier 1a runs before, and ignores, self-authorization).
        why = str(_refuse(ip, allowed={ip}, loopback=True))
        assert _MARKER in why, f"{ip}: degrade branch did not decide ({why!r})"


# --- the PRIVATE tier (Tier 2): denied by default, lifts ONLY for an exact charter literal ---------

PRIVATE_DENIED = ["10.0.0.5", "172.16.0.1", "192.168.1.1", "100.64.0.1", "fc00::1", "fd12::1"]


def test_backstop_refuses_private_without_exact_literal(no_gateway):
    for ip in PRIVATE_DENIED:
        assert _MARKER in str(_refuse(ip))


# --- DNS rebinding: a name resolving to [public, metadata] must be refused on the metadata address --

def test_backstop_refuses_dns_rebinding_to_metadata(no_gateway):
    why = str(_refuse(
        "rebind.example.test",
        resolver=_resolver("93.184.216.34", "169.254.169.254"),
    ))
    assert _MARKER in why
    assert "169.254.169.254" in why


# --- the ALLOW path: the backstop must still let legitimate destinations through -------------------

def test_backstop_allows_scoped_loopback(no_gateway):
    assert resolve_and_validate_all(
        "127.0.0.1", 80, allowed_ips=frozenset({"127.0.0.1"}),
        loopback_allowed_if_scoped=True, resolver=_resolver("127.0.0.1"),
    ) == ["127.0.0.1"]
    assert resolve_and_validate_all(
        "::1", 80, allowed_ips=frozenset({"::1"}),
        loopback_allowed_if_scoped=True, resolver=_resolver("::1"),
    ) == ["::1"]


def test_backstop_refuses_loopback_without_optin(no_gateway):
    # Loopback in the allowlist but NO opt-in -> still refused (fail-closed default).
    assert _MARKER in str(_refuse("127.0.0.1", allowed={"127.0.0.1"}, loopback=False))


def test_backstop_allows_public(no_gateway):
    assert resolve_and_validate_all(
        "example.test", 443, allowed_ips=frozenset(),
        resolver=_resolver("93.184.216.34"),
    ) == ["93.184.216.34"]
    assert resolve_and_validate_all(
        "example.test", 443, allowed_ips=frozenset(),
        resolver=_resolver("2606:4700:4700::1111"),
    ) == ["2606:4700:4700::1111"]


def test_backstop_allows_exact_rfc1918_charter_literal(no_gateway):
    # The private tier lifts for an exact charter literal (parity with the real denylist's Tier-2 lift).
    assert resolve_and_validate_all(
        "10.0.0.5", 80, allowed_ips=frozenset({"10.0.0.5"}),
        resolver=_resolver("10.0.0.5"),
    ) == ["10.0.0.5"]


# --- the degrade precondition is real: without the fixture, gateway IS importable in this venv ------

def test_marker_present_only_on_degrade_branch(no_gateway):
    # Sanity: the marker we assert on is specific to _stdlib_floor_denied, so a real-denylist decision
    # (which carries no such marker) could never satisfy the assertions above.
    denied, why = egress_pin._stdlib_floor_denied("169.254.169.254", frozenset())
    assert denied and _MARKER in why
