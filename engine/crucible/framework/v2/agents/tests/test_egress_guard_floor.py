"""WS1.1b — the never-liftable L3/L4 egress FLOOR + anti-rebinding pin wired into the sovereign httpx
transport (``agents.egress_guard._FloorPinnedBackend`` / ``SovereignHttpxTransport``).

Before this, ``SovereignHttpxTransport`` checked only the NAME (protected-domain categorical floor +
allowlist) and handed the request to a plain ``httpx.HTTPTransport`` that RE-RESOLVED the name and dialled
whatever IP it got — so a charter-scoped name resolving to the cloud metadata IP / an RFC1918 / link-local /
multicast / CGNAT address (directly or via a DNS-rebinding answer) egressed freely. These tests assert the
floor now REFUSES those (no socket opened), ALLOWS a normal public IP, ALLOWS a charter-scoped loopback with
dual-stack fallback across the validated set, and that the floor is never-liftable (a charter cannot list
metadata) and dials ONLY validated addresses, never the re-resolvable name.
"""

from __future__ import annotations

import socket
import threading

import httpcore
import httpx
import pytest

# The floor's denylist lives in ``vigil_gateway`` (shared primitive). The CRUCIBLE-core-on-vigil_core CI job
# runs the framework tree WITHOUT gateway on the path (the two-env boundary), where the floor's allow cases
# would fail-closed for lack of the module, not for a real defect. Skip when gateway is absent — same pattern
# as ``verify/tests/test_egress_pin.py``; this runs locally + on the offense leg, the only place the floor's
# real behaviour is meaningful. Production is unaffected: egress_pin imports vigil_gateway lazily.
pytest.importorskip("vigil_gateway")

from framework.v2.agents.egress_guard import (  # noqa: E402
    EgressAllowlist,
    SovereignHttpxTransport,
    _FloorPinnedBackend,
)
from framework.v2.common.errors import SovereigntyViolation  # noqa: E402
from framework.v2.kernel.sovereignty import SovereigntyPolicy, set_policy  # noqa: E402


def _resolver(*addrs: str):
    """A fake getaddrinfo returning the given addresses (in order) for any name."""
    def fake(host, port, proto=0):  # noqa: ANN001
        return [(socket.AF_INET6 if ":" in a else socket.AF_INET, 1, 6, "", (a, port or 0)) for a in addrs]
    return fake


def _backend(*addrs: str, slug: str = "") -> _FloorPinnedBackend:
    return _FloorPinnedBackend(slug=slug, resolver=_resolver(*addrs), inner=httpcore.SyncBackend())


# --------------------------------------------------------------------------- backend: refusals (no socket)


@pytest.mark.parametrize("ip", [
    "169.254.169.254",   # cloud metadata
    "169.254.1.1",       # link-local
    "10.0.0.5",          # RFC1918
    "192.168.1.10",      # RFC1918
    "172.16.0.9",        # RFC1918
    "100.64.0.1",        # CGNAT (RFC6598)
    "224.0.0.1",         # multicast
    "0.0.0.0",           # reserved
])
def test_backend_refuses_denied_ip_before_any_socket(ip):
    # A name resolving to a denied address is refused with a SovereigntyViolation and ZERO packets.
    with pytest.raises(SovereigntyViolation) as exc:
        _backend(ip).connect_tcp("target.example", 80, timeout=1.0)
    assert "egress floor" in str(exc.value).lower()


def test_backend_refuses_dns_rebinding_public_then_metadata():
    # EVERY resolved address must clear the floor: a [public, metadata] answer is refused wholesale.
    with pytest.raises(SovereigntyViolation):
        _backend("93.184.216.34", "169.254.169.254").connect_tcp("rebind.example", 80, timeout=1.0)


def test_floor_is_never_liftable_even_if_a_charter_lists_metadata():
    # The floor is never-liftable: a scope listing (modelled directly as allowed_ips containing the metadata
    # IP) cannot authorise metadata/link-local/reserved. The backend only ever feeds baseline|charter
    # literals as allowed_ips, but even forcing metadata INTO allowed_ips does not lift it.
    from framework.v2.common.egress_pin import EgressFloorRefused, resolve_and_validate_all

    with pytest.raises(EgressFloorRefused):
        resolve_and_validate_all(
            "meta.example", 80, allowed_ips=frozenset({"169.254.169.254"}),
            loopback_allowed_if_scoped=True, resolver=_resolver("169.254.169.254"))


# --------------------------------------------------------------------------- backend: allow + pin + fallback


def _loopback_listener() -> tuple[socket.socket, int]:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]

    def accept_loop():
        try:
            while True:
                conn, _ = srv.accept()
                conn.close()
        except OSError:
            pass
    threading.Thread(target=accept_loop, daemon=True).start()
    return srv, port


def test_backend_dials_validated_loopback_with_dual_stack_fallback():
    # localhost-style: resolves [::1, 127.0.0.1]; the v6 loopback is NOT listening but the v4 one IS.
    # The floor validates both (loopback baseline), dials ::1 (refused), then falls back to the validated
    # 127.0.0.1 and connects — proving fallback over the validated set, never a name re-resolve.
    srv, port = _loopback_listener()
    try:
        b = _backend("::1", "127.0.0.1")
        stream = b.connect_tcp("localhost", port, timeout=2.0)
        stream.close()
    finally:
        srv.close()


def test_backend_connects_to_the_validated_public_ip_not_the_name():
    # A public name is pinned to the resolved public IP. We point the fake resolver at a loopback listener's
    # port to prove the backend dials the resolver's address (the pin), not a re-resolution of the name.
    srv, port = _loopback_listener()
    try:
        # 127.0.0.1 is reachable; it clears the floor via the loopback baseline. The point here is that the
        # dialled address is the one the resolver returned, pinned — not the name.
        b = _backend("127.0.0.1")
        stream = b.connect_tcp("www.example.test", port, timeout=2.0)
        stream.close()
    finally:
        srv.close()


# --------------------------------------------------------------------------- end-to-end through the client


def test_transport_floor_refuses_metadata_end_to_end():
    # A full httpx.Client built by the transport (production path, inner=None) with an injected resolver:
    # a GET to a charter-scoped name resolving to metadata raises before any byte leaves the host.
    set_policy(SovereigntyPolicy(strict=True))
    allow = EgressAllowlist(target_hosts=("target.example",))
    transport = SovereignHttpxTransport(allow, slug="", resolver=_resolver("169.254.169.254"))
    client = httpx.Client(transport=transport)
    try:
        with pytest.raises(SovereigntyViolation):
            client.get("http://target.example/latest/meta-data/")
    finally:
        client.close()


def test_transport_floor_refuses_metadata_even_in_permissive_mode():
    # The floor is a never-liftable control: it fires in permissive mode too (the NAME allowlist does not).
    set_policy(SovereigntyPolicy(strict=False))
    allow = EgressAllowlist(target_hosts=("target.example",))
    transport = SovereignHttpxTransport(allow, slug="", resolver=_resolver("169.254.169.254"))
    client = httpx.Client(transport=transport)
    try:
        with pytest.raises(SovereigntyViolation):
            client.get("http://target.example/")
    finally:
        client.close()


def test_transport_floor_allows_and_reaches_a_validated_loopback_end_to_end():
    # A real HTTP exchange over the pinned backend: the name resolves to a validated loopback address and
    # the request completes, proving the floor does not block legitimate (validated) egress.
    set_policy(SovereigntyPolicy(strict=True))
    from pytest_httpserver import HTTPServer

    srv = HTTPServer(host="127.0.0.1", port=0)
    srv.start()
    srv.expect_request("/ok").respond_with_data("pong")
    try:
        allow = EgressAllowlist(target_hosts=("127.0.0.1",))
        transport = SovereignHttpxTransport(allow, slug="", resolver=_resolver("127.0.0.1"))
        client = httpx.Client(transport=transport)
        try:
            resp = client.get(f"http://127.0.0.1:{srv.port}/ok")
            assert resp.status_code == 200 and resp.text == "pong"
        finally:
            client.close()
    finally:
        srv.stop()


def test_init_fails_closed_if_backend_slot_absent(monkeypatch):
    # Defence-in-depth: if the httpx pool shape changes so the floor backend cannot be installed, the
    # transport refuses to construct rather than silently shipping an unpinned client.
    import framework.v2.agents.egress_guard as eg

    class _NoPool(httpx.HTTPTransport):
        def __init__(self):  # noqa: D401
            super().__init__()
            object.__setattr__(self, "_pool", object())  # a pool with no _network_backend attr

    monkeypatch.setattr(eg.httpx, "HTTPTransport", _NoPool)
    with pytest.raises(SovereigntyViolation):
        SovereignHttpxTransport(EgressAllowlist(target_hosts=("target.example",)), slug="")
