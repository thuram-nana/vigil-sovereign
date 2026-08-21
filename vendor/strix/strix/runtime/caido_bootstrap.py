"""Caido client bootstrap.

The Caido CLI runs as an in-container sidecar listening on
``127.0.0.1:48080`` *inside* the sandbox. We grab a guest token by
``session.exec()``-ing curl from inside the container, then construct
a host-side :class:`caido_sdk_client.Client` against the runtime's
exposed-port URL for all subsequent SDK calls.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
from typing import TYPE_CHECKING

from caido_sdk_client import Client, TokenAuthOptions
from caido_sdk_client.types import CreateProjectOptions


if TYPE_CHECKING:
    from agents.sandbox.session import BaseSandboxSession


logger = logging.getLogger(__name__)


_LOGIN_AS_GUEST_BODY = (
    '{"query":"mutation LoginAsGuest { loginAsGuest { token { accessToken } } }"}'
)


async def _login_as_guest(
    session: BaseSandboxSession,
    *,
    container_url: str,
    attempts: int = 10,
) -> str:
    """``session.exec`` curl to fetch a guest token; retry until ready.

    Caido's GraphQL listener may not be up the instant the container
    starts. The retry loop also doubles as the Caido readiness probe —
    no separate TCP healthcheck needed.
    """
    last_err: str | None = None
    for i in range(1, attempts + 1):
        result = await session.exec(
            "curl",
            "-fsS",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-d",
            _LOGIN_AS_GUEST_BODY,
            f"{container_url}/graphql",
            timeout=15,
        )
        if result.ok():
            try:
                payload = json.loads(result.stdout)
                token = (
                    payload.get("data", {})
                    .get("loginAsGuest", {})
                    .get("token", {})
                    .get("accessToken")
                )
                if token:
                    return str(token)
                last_err = f"loginAsGuest returned no token: {payload}"
            except json.JSONDecodeError as exc:
                last_err = f"unparseable response: {exc}: {result.stdout!r}"
        else:
            stderr = result.stderr.decode("utf-8", errors="replace")[:200]
            last_err = f"curl exit {result.exit_code}: {stderr}"
        logger.debug("loginAsGuest attempt %d/%d failed: %s", i, attempts, last_err)
        await asyncio.sleep(min(2.0 * i, 8.0))

    raise RuntimeError(f"loginAsGuest failed after {attempts} attempts: {last_err}")


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


async def _configure_vigil_upstream(
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


async def bootstrap_caido(
    session: BaseSandboxSession,
    *,
    host_url: str,
    container_url: str,
) -> Client:
    """Connect to the in-container Caido sidecar and select a fresh project."""
    logger.info("Bootstrapping Caido client (host=%s, container=%s)", host_url, container_url)

    access_token = await _login_as_guest(session, container_url=container_url)

    client = Client(host_url, auth=TokenAuthOptions(token=access_token))
    await client.connect()

    try:
        project = await client.project.create(
            CreateProjectOptions(name="sandbox", temporary=True),
        )
        await client.project.select(project.id)
        # VIGIL S3: with the sandbox on an --internal network the gateway is the only reachable peer, so
        # Caido must forward through it. Inside the same try: a failure here must close the client too.
        await _configure_vigil_upstream(
            session, container_url=container_url, access_token=access_token)
    except BaseException:
        # The connected client never reaches the session bundle if project
        # setup fails, so close it here to avoid leaking the transport.
        with contextlib.suppress(Exception):
            await client.aclose()
        raise
    logger.info("Caido project selected: %s", project.id)
    return client
