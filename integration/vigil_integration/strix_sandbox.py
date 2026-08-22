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
  * ...AND the gateway proxy's coordinates, so the in-sandbox Caido can forward through it (S3). Pinning
    alone would ISOLATE the agent: the sandbox network is created ``--internal``, which installs no route
    out (measured: a container on it cannot reach 1.1.1.1:443 or 8.8.8.8:53, while the same probe on a
    default bridge reaches both). Without an upstream, Caido would have nowhere to send the request.
  * on failure it REFUSES, so a run cannot silently degrade from gated to ungated egress

FAIL-CLOSED, WITH ONE LOUD DOOR. Refusing by default would strand an operator whose gateway is not up, so
this mirrors the escape hatch ``vigil up --services`` already established (W0-6): an explicit
``--allow-ungated-egress`` / ``VIGIL_ALLOW_UNGATED_STRIX_EGRESS`` continues with a prominent warning and
records that the run accepted ungated egress. The default is refusal; the override is never silent.

WHAT PINNING ACTUALLY BUYS (measured, not assumed). The sandbox network is created ``--internal``, so
Docker installs NO route out of it. A container on such a network could reach neither 1.1.1.1:443 nor
8.8.8.8:53 in a live check, while the identical probe on a default bridge reached both. Pinning is
therefore genuine L3 deny-default egress, not merely "joins a network" — the only reachable peer is the
gateway on the same network.

HONEST BOUND. Deny-default is not the same as filtered-and-audited. Once traffic is forwarded to the
gateway it is subject to the gateway's own scope authorization; the L3/L4 nftables backstop that hardens
the gateway's egress leg, and the bypass battery that proves the boundary empirically, are the remainder
of S3.

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

    # gateway ATTACHED+reachable: running + network-exists is not enough — a gateway attached only to the
    # egress net (or a sandbox net recreated after the gateway started) passes both yet leaves the
    # ``--internal`` sandbox with NO reachable peer. Verify the gateway is actually connected to the sandbox
    # network before pinning onto it. Fail-closed: an unreadable membership is a refusal, never a proceed.
    # (Injected test fakes without the method default to attached — production ``SandboxNetworking`` always
    # implements it, so this only affects the older seams, never the real launch path.)
    attached_fn = getattr(networking, "gateway_attached", None)
    if callable(attached_fn):
        try:
            attached = bool(attached_fn())
        except Exception as exc:  # noqa: BLE001 — cannot tell ⇒ refuse
            return _refuse(f"the gateway's attachment to the sandbox network could not be read "
                           f"({type(exc).__name__}: {exc})",
                           overridden=overridden, gateway_state=state, network=network, network_present=True)
        if not attached:
            return _refuse(
                f"the VIGIL egress gateway is running but is NOT attached to the gated sandbox network "
                f"{network!r}, so the sandbox would be pinned onto an isolated network with no reachable "
                f"peer (its one permitted exit). Recreate the topology with `vigil services up`.",
                overridden=overridden, gateway_state=state, network=network, network_present=True)

    env = dict(networking.strix_env())
    env.update(_proxy_env(networking))
    return SandboxPreflight(ok=True, env=env, gateway_state=state,
                            network=network, network_present=True, overridden=False)


def _proxy_env(networking: Any) -> dict[str, str]:
    """The gateway proxy coordinates the in-sandbox Caido needs in order to forward through it.

    The host is the gateway's PINNED address on the sandbox network (it binds only that interface, never
    0.0.0.0), so this is the one peer an ``--internal`` sandbox can reach. The token is the Basic
    proxy-auth secret: the env wins, else the credential MINTED at gateway bring-up and persisted under
    ``.vigil-live/gateway-proxy-token`` — so the sandbox's Caido presents the exact secret the gateway was
    started with (the two ends never drift). When neither is present the gateway demands no client auth and
    we pass nothing rather than inventing a credential.
    """
    try:
        host = str(networking.sandbox_gateway_ip())
    except Exception:  # noqa: BLE001 — a missing helper must not block a gated launch
        return {}
    out = {
        "VIGIL_GATEWAY_PROXY_HOST": host,
        "VIGIL_GATEWAY_PROXY_PORT": str(os.environ.get("VIGIL_GATEWAY_PROXY_PORT", "") or "48081"),
    }
    token = str(os.environ.get("VIGIL_GATEWAY_PROXY_TOKEN", "") or "").strip() or _persisted_proxy_token()
    if token:
        out["VIGIL_GATEWAY_PROXY_TOKEN"] = token
    return out


def _persisted_proxy_token() -> str:
    """The short-lived proxy token minted at gateway bring-up (``.vigil-live/gateway-proxy-token``), or "".

    Resolved from the repo root (this file is ``<repo>/integration/vigil_integration/strix_sandbox.py``) so
    it is CWD-independent and matches exactly where the launch path writes it. Total: never raises — a
    missing/unreadable token means 'no client auth', never a blocked launch."""
    try:
        from pathlib import Path as _Path
        from vigil_gateway.docker import PROXY_TOKEN_RELPATH, load_proxy_token  # VIGIL-owned; never sigil
        repo = _Path(__file__).resolve().parents[2]
        return load_proxy_token(repo / PROXY_TOKEN_RELPATH) or ""
    except Exception:  # noqa: BLE001 — any failure to read the token is 'no token', never a refusal
        return ""


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
