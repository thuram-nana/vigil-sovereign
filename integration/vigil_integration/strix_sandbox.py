"""S2 — the Strix sandbox must be pinned to VIGIL's gated network BEFORE the agent starts.

THE DEFECT THIS CLOSES. ``vendor/strix/strix/runtime/docker_client.py`` reads
``STRIX_DOCKER_SANDBOX_NETWORK`` to decide which Docker network the agent container joins, and
``gateway.docker.SandboxNetworking.strix_env()`` produces exactly that mapping — but nothing in VIGIL ever
called the producer or set the variable. ``_apply_sandbox_network`` was therefore a no-op and every Strix
sandbox was created on Docker's **default bridge**, with a default route to the operator LAN, the internet
and 169.254.169.254. The gateway, its ``internal: true`` network and the nftables backstop were all built,
tested and unreferenced. FATAL-1 was closed in shipped code and open in the default configuration.

WHAT THIS MODULE DOES. One pre-flight the Strix launch path calls before spawning:

  * the gateway container is ``running``  (not merely present, not "compose exited 0")
  * the engagement's sandbox network exists
  * on success it returns the env that PINS the sandbox to that network — the producer finally has a caller
  * on failure it REFUSES, so a run cannot silently degrade from gated to ungated egress

FAIL-CLOSED, WITH ONE LOUD DOOR. Refusing by default would strand an operator whose gateway is not up, so
this mirrors the escape hatch ``vigil up --services`` already established (W0-6): an explicit
``--allow-ungated-egress`` / ``VIGIL_ALLOW_UNGATED_STRIX_EGRESS`` continues with a prominent warning and
records that the run accepted ungated egress. The default is refusal; the override is never silent.

HONEST BOUND. Pinning the network is necessary, not sufficient. It puts the sandbox on the gated topology;
it does not by itself prove every packet is filtered — the L3/L4 nftables backstop and the Caido upstream
are S3. What this closes is the specific hole where the sandbox never joined the gated network at all.

Plane: integration. Imports ``vigil_gateway`` (which VIGIL owns) and the standard library only — no
``sigil`` import, so the two-env boundary is untouched.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Optional

#: Explicit operator opt-in to running the Strix sandbox with UNGATED egress.
UNGATED_ENV = "VIGIL_ALLOW_UNGATED_STRIX_EGRESS"

_TRUE = {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class SandboxPreflight:
    """The verdict. ``env`` is empty unless the sandbox is genuinely pinned to the gated network."""

    ok: bool
    env: dict[str, str] = field(default_factory=dict)
    refusal: Optional[str] = None
    gateway_state: str = "unknown"
    network: str = ""
    network_present: bool = False
    overridden: bool = False

    @property
    def gated(self) -> bool:
        """True only when the sandbox is actually pinned — an override proceeds but is NOT gated."""
        return self.ok and not self.overridden and bool(self.env)


def _override_requested(explicit: Optional[bool]) -> bool:
    if explicit is not None:
        return bool(explicit)
    return str(os.environ.get(UNGATED_ENV, "")).strip().lower() in _TRUE


def preflight(*, allow_ungated: Optional[bool] = None, networking: Any = None) -> SandboxPreflight:
    """Decide whether a Strix sandbox may start, and with what network pinning.

    ``networking`` is injectable for tests; production resolves ``SandboxNetworking`` itself. Never raises:
    any failure to introspect Docker is a REFUSAL, because "we could not tell" must not become "proceed".
    """
    overridden = _override_requested(allow_ungated)

    try:
        if networking is None:
            from vigil_gateway.docker import SandboxNetworking  # VIGIL-owned; not the vendored agent
            networking = SandboxNetworking()
    except Exception as exc:  # noqa: BLE001 — an unusable gateway package is a refusal, never a bypass
        return _refuse(f"the gateway package could not be loaded ({type(exc).__name__}: {exc})",
                       overridden=overridden)

    network = str(getattr(networking, "sandbox_network", "") or "")
    try:
        state = str(networking.container_state())
    except Exception as exc:  # noqa: BLE001
        return _refuse(f"the gateway container state could not be read ({type(exc).__name__}: {exc})",
                       overridden=overridden, network=network)

    try:
        present = bool(networking.network_exists(network))
    except Exception as exc:  # noqa: BLE001
        return _refuse(f"the sandbox network could not be inspected ({type(exc).__name__}: {exc})",
                       overridden=overridden, gateway_state=state, network=network)

    if state != "running":
        return _refuse(
            f"the VIGIL egress gateway is not running (state: {state!r}). The Strix sandbox would be "
            f"created on Docker's default bridge with a route to the operator LAN, the internet and the "
            f"cloud metadata endpoint (169.254.169.254). Start it with `vigil services up`.",
            overridden=overridden, gateway_state=state, network=network, network_present=present)

    if not present:
        return _refuse(
            f"the gated sandbox network {network!r} does not exist, so the sandbox cannot be pinned to it. "
            f"Create it with `vigil services up`.",
            overridden=overridden, gateway_state=state, network=network, network_present=False)

    return SandboxPreflight(ok=True, env=dict(networking.strix_env()), gateway_state=state,
                            network=network, network_present=True, overridden=False)


def _refuse(reason: str, *, overridden: bool, gateway_state: str = "unknown",
            network: str = "", network_present: bool = False) -> SandboxPreflight:
    """A refusal — or, when the operator explicitly opted in, a LOUD ungated continue with NO pinning env."""
    if overridden:
        return SandboxPreflight(
            ok=True, env={}, refusal=None, gateway_state=gateway_state, network=network,
            network_present=network_present, overridden=True)
    return SandboxPreflight(ok=False, env={}, refusal=reason, gateway_state=gateway_state,
                            network=network, network_present=network_present, overridden=False)


def warning_banner(result: SandboxPreflight) -> str:
    """The loud line printed when a run proceeds with ungated egress. Never printed on the gated path."""
    if not result.overridden:
        return ""
    return (f"WARNING: {UNGATED_ENV} is set — the Strix sandbox is running with UNGATED egress "
            f"(gateway state: {result.gateway_state!r}). Traffic is NOT confined to the signed scope. "
            f"FATAL-1 accepted for this run.")
