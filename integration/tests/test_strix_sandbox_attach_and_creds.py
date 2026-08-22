"""sx-s2 — the two pre-flight strengthenings that sit on the launch refuse gate.

1. ATTACHED+REACHABLE. ``container_state == running`` + ``network_exists`` is not enough for the sandbox to
   reach the gateway: a gateway on only the egress net, or a sandbox net recreated after the gateway
   started, both pass those two checks yet leave the ``--internal`` sandbox with NO reachable peer. The
   pre-flight now also verifies the gateway is CONNECTED to the sandbox network, and refuses (fail-closed)
   otherwise — unless the operator explicitly accepts ungated egress.

2. SHORT-LIVED CREDENTIAL. The proxy token minted + persisted at gateway bring-up is read back here and
   handed to the in-sandbox Caido, so it presents the exact secret the gateway was started with.

Plane: integration. Imports only ``vigil_integration.strix_sandbox`` (stdlib at module load; ``vigil_gateway``
is reached function-locally). No ``framework``/``strix``/``sigil`` import, so this runs in the P5 leg without
an importorskip and needs no ci.yml offense-leg entry.
"""
from __future__ import annotations

from vigil_integration import strix_sandbox


class _Net:
    """An injectable networking double modelling the four states the pre-flight distinguishes."""

    sandbox_network = "vigil_sandbox"

    def __init__(self, *, state: str = "running", present: bool = True, attached: bool = True):
        self._state, self._present, self._attached = state, present, attached

    def container_state(self) -> str:
        return self._state

    def network_exists(self, name: str | None = None) -> bool:
        return self._present

    def gateway_attached(self) -> bool:
        return self._attached

    def strix_env(self) -> dict:
        return {"STRIX_DOCKER_SANDBOX_NETWORK": self.sandbox_network}

    def sandbox_gateway_ip(self) -> str:
        return "172.31.240.2"


def test_preflight_refuses_a_running_but_detached_gateway():
    r = strix_sandbox.preflight(networking=_Net(attached=False))
    assert not r.ok and not r.gated
    assert "not attached" in (r.refusal or "").lower()
    assert r.env == {}                                  # no pinning env leaks out of a refusal


def test_preflight_pins_when_gateway_is_attached():
    r = strix_sandbox.preflight(networking=_Net(attached=True))
    assert r.ok and r.gated
    assert r.env["STRIX_DOCKER_SANDBOX_NETWORK"] == "vigil_sandbox"
    assert r.env["VIGIL_GATEWAY_PROXY_HOST"] == "172.31.240.2"


def test_detach_refusal_is_overridable_but_loud_and_ungated():
    r = strix_sandbox.preflight(allow_ungated=True, networking=_Net(attached=False))
    assert r.ok and r.overridden and not r.gated        # proceeds, but explicitly NOT gated
    assert r.env == {}                                  # an ungated continue pins nothing
    assert "UNGATED egress" in strix_sandbox.warning_banner(r)


def test_attachment_read_failure_is_a_refusal_not_a_proceed():
    class _Raises(_Net):
        def gateway_attached(self):
            raise RuntimeError("docker unreachable")

    r = strix_sandbox.preflight(networking=_Raises())
    assert not r.ok and "could not be read" in (r.refusal or "")


def test_proxy_env_presents_the_persisted_minted_token(monkeypatch):
    monkeypatch.delenv("VIGIL_GATEWAY_PROXY_TOKEN", raising=False)
    monkeypatch.setattr(strix_sandbox, "_persisted_proxy_token", lambda: "minted-tok")
    env = strix_sandbox._proxy_env(_Net())
    assert env["VIGIL_GATEWAY_PROXY_TOKEN"] == "minted-tok"


def test_env_token_wins_over_the_persisted_file(monkeypatch):
    monkeypatch.setattr(strix_sandbox, "_persisted_proxy_token", lambda: "minted-tok")
    monkeypatch.setenv("VIGIL_GATEWAY_PROXY_TOKEN", "env-tok")
    assert strix_sandbox._proxy_env(_Net())["VIGIL_GATEWAY_PROXY_TOKEN"] == "env-tok"


def test_no_token_anywhere_presents_none(monkeypatch):
    monkeypatch.delenv("VIGIL_GATEWAY_PROXY_TOKEN", raising=False)
    monkeypatch.setattr(strix_sandbox, "_persisted_proxy_token", lambda: "")
    env = strix_sandbox._proxy_env(_Net())
    assert "VIGIL_GATEWAY_PROXY_TOKEN" not in env        # we invent no credential


def test_persisted_token_resolver_is_total():
    # never raises regardless of whether a token file exists in this checkout — 'no token' is a str, not a crash
    assert isinstance(strix_sandbox._persisted_proxy_token(), str)
