"""VIGIL S3 — point Caido at the VIGIL egress gateway.

Deliberately SDK-FREE. ``caido_bootstrap`` imports ``caido_sdk_client`` at module scope, and that optional
dependency is NOT installed in the required "strix Claude-runtime (P8)" CI job — so a test that reached
this logic through that module could only ``importorskip``, i.e. never actually run where it matters. (The
job's own log shows the sibling suites skipping for the same reason.) Keeping the egress wiring in a module
that needs nothing but the standard library means its tests RUN in CI rather than silently skipping, which
for a control that decides whether an agent's traffic is filtered is the difference between a gate and a
decoration.
"""
from __future__ import annotations

import json
import logging
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from strix.runtime.base import BaseSandboxSession

logger = logging.getLogger(__name__)


# --- VIGIL S3: forward Caido's traffic through the VIGIL egress gateway -------------------------------
#
# The sandbox network is created ``--internal``, so Docker installs NO route out of it: the ONLY peer the
# agent can reach is the gateway pinned on that network. Caido must therefore be told to forward through
# it, or every request the agent makes dies at the missing route. ``caido-cli`` has no upstream flag (its
# --help carries none), but Caido's GraphQL API exposes ``createUpstreamProxyHttp``, so the upstream is
# configured here, right after the project is selected.
#
# Fail-closed: when VIGIL has told us a gateway exists and we cannot point Caido at it, we RAISE. Starting
# an agent that silently cannot reach anything — or worse, that is later "fixed" by removing the isolation
# — is not an acceptable degradation.
_UPSTREAM_HOST_ENV = "VIGIL_GATEWAY_PROXY_HOST"
_UPSTREAM_PORT_ENV = "VIGIL_GATEWAY_PROXY_PORT"
_UPSTREAM_TOKEN_ENV = "VIGIL_GATEWAY_PROXY_TOKEN"
_UPSTREAM_AUTH_USER = "vigil"   # the fixed username half of the gateway's Basic proxy credential


def _upstream_mutation_body(host: str, port: int, token: str) -> str:
    """The GraphQL body that points Caido at the gateway.

    ``__typename`` is the selection set deliberately: it is valid on every object type, so the mutation
    does not break if Caido renames a payload field. Auth is omitted entirely when the deployment set no
    token — the gateway then demands no client credential, and inventing one would fail the handshake.
    """
    connection = {"host": host, "port": port, "isTLS": False}
    variables: dict = {"input": {"enabled": True, "connection": connection}}
    if token:
        variables["input"]["auth"] = {"basic": {"username": _UPSTREAM_AUTH_USER, "password": token}}
    return json.dumps({
        "query": ("mutation VigilUpstream($input: CreateUpstreamProxyHttpInput!) { "
                  "createUpstreamProxyHttp(input: $input) { __typename } }"),
        "variables": variables,
    })


async def configure_vigil_upstream(
    session: BaseSandboxSession,
    *,
    container_url: str,
    access_token: str,
) -> bool:
    """Point Caido at the VIGIL egress gateway. Returns False when no gateway was configured."""
    host = (os.environ.get(_UPSTREAM_HOST_ENV) or "").strip()
    port_raw = (os.environ.get(_UPSTREAM_PORT_ENV) or "").strip()
    if not host:
        # No gateway configured for this run (e.g. an explicitly ungated run). Byte-identical to before.
        logger.debug("no %s set — leaving Caido without an upstream proxy", _UPSTREAM_HOST_ENV)
        return False
    try:
        port = int(port_raw or "48081")
    except ValueError:
        raise RuntimeError(f"{_UPSTREAM_PORT_ENV}={port_raw!r} is not a port number") from None

    body = _upstream_mutation_body(host, port, (os.environ.get(_UPSTREAM_TOKEN_ENV) or "").strip())
    result = await session.exec(
        "curl", "-fsS", "-X", "POST",
        "-H", "Content-Type: application/json",
        "-H", f"Authorization: Bearer {access_token}",
        "-d", body,
        f"{container_url}/graphql",
        timeout=20,
    )
    if not result.ok():
        stderr = result.stderr.decode("utf-8", errors="replace")[:300]
        raise RuntimeError(
            f"could not point Caido at the VIGIL gateway {host}:{port} (curl exit {result.exit_code}: "
            f"{stderr}). The sandbox network is internal, so the agent has no other route out."
        )
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"unparseable upstream-proxy response: {exc}: {result.stdout!r}") from None
    if payload.get("errors"):
        raise RuntimeError(
            f"Caido refused the VIGIL upstream proxy {host}:{port}: {payload['errors']}"
        )
    logger.info("Caido upstream proxy set to the VIGIL gateway at %s:%d", host, port)
    return True
