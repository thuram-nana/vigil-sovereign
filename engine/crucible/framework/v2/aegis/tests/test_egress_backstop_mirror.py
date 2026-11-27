"""AS-2d — the egress backstop, MIRRORED onto the AEGIS broker's origin egress.

``common/tests/test_egress_backstop.py`` proves the engine's shared egress FLOOR
(``common.egress_pin.resolve_and_validate_all``) degrades to its pure-stdlib structural backstop — never
fail-open — in the gateway-less leg. The AS-2d broker's origin hop (``broker.resolve_broker_target``) dials
the tenant's origin through that SAME shared floor with ``allowed_ips=frozenset()`` and
``loopback_allowed_if_scoped=False``. This file EXTENDS the backstop coverage to that broker seam: it forces
``vigil_gateway`` absent in-process (so the ``_stdlib_floor_denied`` degrade branch is the sole authority,
exactly as in the CRUCIBLE-core no-gateway CI leg) and proves the broker refuses a metadata / IMDS /
link-local / RFC1918 / loopback origin — loopback is never edge identity (R15) — while still forwarding a
genuine public origin. The ``[stdlib backstop]`` marker in each refusal proves the degrade branch, not the
real ``denylist``, decided.

The broker's egress is NOT charter-scoped: it passes ``allowed_ips=frozenset()``, so NO scope listing (and no
loopback opt-in) can lift the floor for an origin — the origin is always a real, globally-routable host.
"""
from __future__ import annotations

import hashlib
import importlib.abc
import sys
from datetime import datetime, timezone

import pytest
from vigil_core.authority_v2 import (
    AuthoritySubject,
    MonitoringAuthorityV2,
    MonitoringCapability,
    MonitoringLease,
    OriginTuple,
    SubjectKind,
)

from framework.v2.aegis.broker import BrokerRefused, resolve_broker_target

_MARKER = "[stdlib backstop]"
ORG = "org_a"
ORIGIN_HOST = "origin.example.com"


class _BlockGateway(importlib.abc.MetaPathFinder):
    """Make ``vigil_gateway`` (and any submodule) unimportable, so the shared floor cannot reach the real
    denylist and must take the ``_stdlib_floor_denied`` degrade branch (mirrors ``test_egress_backstop``)."""

    def find_spec(self, fullname, path, target=None):  # noqa: ANN001, ARG002
        if fullname == "vigil_gateway" or fullname.startswith("vigil_gateway."):
            raise ModuleNotFoundError(f"vigil_gateway forced absent for backstop-mirror test: {fullname}")
        return None


@pytest.fixture()
def no_gateway():
    finder = _BlockGateway()
    saved = {k: v for k, v in list(sys.modules.items())
             if k == "vigil_gateway" or k.startswith("vigil_gateway.")}
    for k in saved:
        del sys.modules[k]
    sys.meta_path.insert(0, finder)
    try:
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
    def fake(host, port, proto=0):  # noqa: ANN001, ARG001
        return [(2, 1, 6, "", (a, port or 0)) for a in addrs]

    return fake


def _grant(origin: str = ORIGIN_HOST, port: int = 443) -> MonitoringAuthorityV2:
    def dt(ts: float) -> datetime:
        return datetime.fromtimestamp(ts, tz=timezone.utc)

    return MonitoringAuthorityV2(
        subject=AuthoritySubject(kind=SubjectKind.HOST, org_id=ORG, host="h.example.com"),
        capabilities=[MonitoringCapability.OBSERVE], epoch=1, not_before=dt(0), not_after=dt(4.0e9),
        lease=MonitoringLease(not_before=dt(0), not_after=dt(4.0e9)), instance_id="gw",
        origin=OriginTuple(host=origin, port=port),
        origin_binding_sha256=hashlib.sha256(f"{origin}:{port}".encode()).hexdigest())


def _refuse(addr: str) -> str:
    """Resolve the broker target with an origin that maps to ``addr``; return the refusal reason text."""
    with pytest.raises(BrokerRefused) as exc:
        resolve_broker_target(_grant(), uid=ORG, resolver=_resolver(addr))
    return str(exc.value)


# --- the ABSOLUTE floor (Tier 1a): never liftable ------------------------------------------------------
NEVER_LIFTABLE = [
    "169.254.169.254",          # AWS/GCP/Azure IMDS (link-local)
    "169.254.170.2",            # ECS task metadata (link-local)
    "fd00:ec2::254",            # AWS IMDS-over-IPv6
    "fe80::1",                  # link-local v6
    "224.0.0.1",                # multicast v4
    "240.0.0.1",                # reserved v4
    "::ffff:169.254.169.254",   # IPv4-mapped metadata evasion form
]


def test_broker_refuses_never_liftable_origin(no_gateway):
    for addr in NEVER_LIFTABLE:
        why = _refuse(addr)
        assert _MARKER in why, f"{addr}: broker egress did not go through the stdlib backstop ({why!r})"
        assert "egress refused" in why


# --- loopback (R15: never edge identity) + the PRIVATE tier --------------------------------------------
def test_broker_refuses_loopback_and_private_origin(no_gateway):
    # loopback is never edge identity — refused even though it is the operator's own box.
    for addr in ("127.0.0.1", "::1"):
        assert _MARKER in _refuse(addr)
    # RFC1918 / CGNAT / ULA origins are refused (the broker passes allowed_ips=frozenset(), so no lift).
    for addr in ("10.0.0.5", "172.16.0.1", "192.168.1.1", "100.64.0.1", "fc00::1"):
        assert _MARKER in _refuse(addr)


# --- DNS rebinding: a name resolving to [public, metadata] is refused on the metadata address ----------
def test_broker_refuses_dns_rebinding_origin(no_gateway):
    with pytest.raises(BrokerRefused) as exc:
        resolve_broker_target(_grant(), uid=ORG, resolver=_resolver("93.184.216.34", "169.254.169.254"))
    why = str(exc.value)
    assert _MARKER in why and "169.254.169.254" in why


# --- the ALLOW path: a genuine public origin still forwards --------------------------------------------
def test_broker_allows_public_origin(no_gateway):
    t4 = resolve_broker_target(_grant(), uid=ORG, resolver=_resolver("93.184.216.34"))
    assert t4.addresses == ("93.184.216.34",) and t4.sni == ORIGIN_HOST
    t6 = resolve_broker_target(_grant(), uid=ORG, resolver=_resolver("2606:4700:4700::1111"))
    assert t6.addresses == ("2606:4700:4700::1111",)


def test_broker_degrade_marker_is_real(no_gateway):
    # Sanity: the marker we assert on is specific to the stdlib degrade branch, so the assertions above
    # could not be satisfied by a real-denylist decision (which carries no such marker).
    from framework.v2.common import egress_pin
    denied, why = egress_pin._stdlib_floor_denied("169.254.169.254", frozenset())
    assert denied and _MARKER in why
