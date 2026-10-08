"""Drift guard: the gateway-less stdlib backstop MUST NOT silently diverge from its authority.

``common.egress_pin`` hand-copies ``vigil_gateway.denylist``'s never-liftable + private tiers into a pure-
stdlib mirror (``_BACKSTOP_ALWAYS_DENY_V{4,6}`` / ``_BACKSTOP_PRIVATE_NETS``) so the engine keeps a floor
when gateway is absent. A hand copy rots: a sibling edit to ``denylist._ALWAYS_DENY_*`` that is NOT mirrored
would silently create a fail-OPEN in the gateway-less plane (the backstop would stop refusing something the
authority refuses). This test pins the mirror to the authority so that drift trips here.

It NEEDS the authority, so it lives in ``integration/tests`` (runs in the P5 / offense leg where gateway is
on the path) behind a module-level ``importorskip`` — it skips cleanly if ever run gateway-less, where test
``common/tests/test_egress_backstop.py`` already covers the degrade behaviour without the authority.
"""

from __future__ import annotations

from ipaddress import ip_address, ip_network

import pytest

# This leg of P5 runs integration/tests in a SOVEREIGN sub-process where ``framework`` is ABSENT (but
# ``vigil_gateway`` is present) — so importorskip("framework") must come FIRST, or the hard
# ``from framework...`` below is a collection ERROR, not a skip, in that pass. It runs in the OFFENSE pass
# where both are importable. (The offense venv has framework installed, which MASKS this locally — only the
# sovereign sub-process or a framework meta_path block is faithful.)
pytest.importorskip("framework")
pytest.importorskip("vigil_gateway")

from framework.v2.common import egress_pin  # noqa: E402
from vigil_gateway import denylist  # noqa: E402

# The two loopback entries the backstop deliberately EXCLUDES from its Tier-1a set (it splits loopback into
# Tier-1b so an opted-in caller can lift a charter-scoped loopback target), mirroring the authority's own
# ``_ALWAYS_DENY_NONLOOPBACK_NETS`` split.
_LOOPBACK = {ip_network("127.0.0.0/8"), ip_network("::1/128")}


def test_always_deny_mirror_matches_authority_minus_loopback():
    backstop = {ip_network(c) for c in egress_pin._BACKSTOP_ALWAYS_DENY_V4} | {
        ip_network(c) for c in egress_pin._BACKSTOP_ALWAYS_DENY_V6}
    authority = {ip_network(c) for c in denylist._ALWAYS_DENY_V4} | {
        ip_network(c) for c in denylist._ALWAYS_DENY_V6}
    # Order-independent set equality: a dropped mirror entry (fail-open) OR an unexpected extra one trips it.
    assert backstop == authority - _LOOPBACK, (
        "backstop Tier-1a drifted from denylist._ALWAYS_DENY_* (minus loopback): "
        f"missing={sorted(map(str, (authority - _LOOPBACK) - backstop))} "
        f"extra={sorted(map(str, backstop - (authority - _LOOPBACK)))}")
    # Cross-check against the authority's own non-loopback split, independently derived.
    assert backstop == set(denylist._ALWAYS_DENY_NONLOOPBACK_NETS)


def test_private_mirror_matches_authority():
    assert set(egress_pin._BACKSTOP_PRIVATE_NETS) == set(denylist._PRIVATE_NETS), (
        "backstop Tier-2 private set drifted from denylist._PRIVATE_NETS: "
        f"missing={sorted(map(str, set(denylist._PRIVATE_NETS) - set(egress_pin._BACKSTOP_PRIVATE_NETS)))} "
        f"extra={sorted(map(str, set(egress_pin._BACKSTOP_PRIVATE_NETS) - set(denylist._PRIVATE_NETS)))}")


def test_backstop_actually_refuses_every_authority_floor_entry():
    """Behavioural fail-open catch. For every always-denied authority net (minus loopback), the backstop
    must REFUSE a representative address. This is stronger than set equality: if the authority ever grows a
    GLOBALLY-ROUTABLE always-deny entry not covered by the backstop's explicit CIDR set NOR its
    ipaddress predicate fallbacks (is_link_local/is_multicast/is_reserved/is_unspecified/is_private), set
    equality would flag it here AND this assertion would fail outright — that is the latent fail-open the
    guard exists to catch.
    """
    authority = {ip_network(c) for c in denylist._ALWAYS_DENY_V4} | {
        ip_network(c) for c in denylist._ALWAYS_DENY_V6}
    for net in authority - _LOOPBACK:
        rep = next(iter(net.hosts()), net.network_address)
        denied, why = egress_pin._stdlib_floor_denied(str(rep), frozenset())
        assert denied, f"backstop FAILED OPEN on authority floor entry {net} (rep {rep}): {why!r}"
        # Never liftable: not even an exact charter literal + loopback opt-in may lift Tier-1a.
        denied2, why2 = egress_pin._stdlib_floor_denied(
            str(rep), frozenset({str(rep)}), loopback_allowed_if_scoped=True)
        assert denied2, f"backstop LIFTED a never-liftable entry {net} (rep {rep}): {why2!r}"


def test_loopback_is_the_only_excluded_authority_entry():
    # Document + pin the exclusion: the backstop's Tier-1a is the authority's always-deny set with EXACTLY
    # the two loopback nets removed. If a future authority edit removed/renamed a loopback net, this fails.
    authority = {ip_network(c) for c in denylist._ALWAYS_DENY_V4} | {
        ip_network(c) for c in denylist._ALWAYS_DENY_V6}
    backstop = {ip_network(c) for c in egress_pin._BACKSTOP_ALWAYS_DENY_V4} | {
        ip_network(c) for c in egress_pin._BACKSTOP_ALWAYS_DENY_V6}
    assert (authority - backstop) == _LOOPBACK
    # And loopback itself is reachable only via the opt-in path (parity with the authority).
    denied, _ = egress_pin._stdlib_floor_denied("127.0.0.1", frozenset())
    assert denied
    ok, _ = egress_pin._stdlib_floor_denied(
        "127.0.0.1", frozenset({"127.0.0.1"}), loopback_allowed_if_scoped=True)
    assert not ok
    assert ip_address("127.0.0.1")  # keep ip_address import load-bearing / lint-clean
