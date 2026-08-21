"""VIGIL S3 — Caido must forward through the VIGIL egress gateway, or the agent has no route out.

The sandbox network VIGIL pins the container to is created ``--internal``: Docker installs no route out of
it, so the ONLY peer the agent can reach is the gateway on that network (measured — a container on such a
network reached neither 1.1.1.1:443 nor 8.8.8.8:53, while the same probe on a default bridge reached both).
``caido-cli`` has no upstream flag, so the upstream is configured over Caido's GraphQL API at bootstrap.

These tests use a fake session; nothing here starts Caido or touches the network.
"""
from __future__ import annotations

import asyncio
import json

import pytest

from strix.runtime.vigil_upstream import (
    configure_vigil_upstream as _configure_vigil_upstream,
    _upstream_mutation_body,
)

HOST_ENV = "VIGIL_GATEWAY_PROXY_HOST"
PORT_ENV = "VIGIL_GATEWAY_PROXY_PORT"
TOKEN_ENV = "VIGIL_GATEWAY_PROXY_TOKEN"


class _Result:
    def __init__(self, code=0, stdout='{"data":{"createUpstreamProxyHttp":{"__typename":"X"}}}', stderr=b""):
        self.exit_code, self.stdout, self.stderr = code, stdout, stderr

    def ok(self):
        return self.exit_code == 0


class _Session:
    """Captures the argv the bootstrap would run inside the container."""

    def __init__(self, result=None):
        self.calls = []
        self._result = result or _Result()

    async def exec(self, *argv, timeout=None):
        self.calls.append(argv)
        return self._result


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in (HOST_ENV, PORT_ENV, TOKEN_ENV):
        monkeypatch.delenv(var, raising=False)


# --- the mutation body ---------------------------------------------------------------------------------

def test_the_mutation_points_caido_at_the_gateway():
    body = json.loads(_upstream_mutation_body("172.31.240.2", 48081, ""))
    conn = body["variables"]["input"]["connection"]
    assert conn == {"host": "172.31.240.2", "port": 48081, "isTLS": False}
    assert body["variables"]["input"]["enabled"] is True
    assert "createUpstreamProxyHttp" in body["query"]


def test_no_token_means_no_auth_block_rather_than_an_invented_credential():
    """The gateway demands client auth only when a token is configured; a fabricated one would fail."""
    assert "auth" not in json.loads(_upstream_mutation_body("h", 1, ""))["variables"]["input"]


def test_a_token_becomes_the_gateway_s_basic_credential():
    auth = json.loads(_upstream_mutation_body("h", 1, "s3cr3t"))["variables"]["input"]["auth"]
    assert auth == {"basic": {"username": "vigil", "password": "s3cr3t"}}, (
        "the gateway's Basic proxy credential is the fixed user 'vigil' plus the token"
    )


def test_the_selection_set_survives_a_payload_rename():
    """__typename is valid on every object type, so the mutation does not break if Caido renames a field."""
    assert "__typename" in json.loads(_upstream_mutation_body("h", 1, ""))["query"]


# --- the bootstrap step --------------------------------------------------------------------------------

def test_no_gateway_configured_is_a_no_op(monkeypatch):
    """An explicitly ungated run must behave exactly as before: no mutation, no failure."""
    session = _Session()
    assert asyncio.run(_configure_vigil_upstream(
        session, container_url="http://127.0.0.1:48080", access_token="t")) is False
    assert session.calls == [], "no upstream call should be made when no gateway is configured"


def test_a_configured_gateway_is_applied_with_the_bearer_token(monkeypatch):
    monkeypatch.setenv(HOST_ENV, "172.31.240.2")
    monkeypatch.setenv(PORT_ENV, "48081")
    session = _Session()
    assert asyncio.run(_configure_vigil_upstream(
        session, container_url="http://127.0.0.1:48080", access_token="tok123")) is True
    argv = session.calls[0]
    assert "Authorization: Bearer tok123" in argv, "the mutation must be authenticated"
    assert argv[-1].endswith("/graphql")


@pytest.mark.parametrize("result,needle", [
    (_Result(code=7, stderr=b"connection refused"), "could not point Caido"),
    (_Result(stdout='{"errors":[{"message":"nope"}]}'), "refused the VIGIL upstream proxy"),
    (_Result(stdout="not json"), "unparseable"),
])
def test_a_failure_to_wire_the_upstream_raises_rather_than_running_blind(monkeypatch, result, needle):
    """Fail-closed: an agent that cannot reach the gateway has no route out at all — say so loudly."""
    monkeypatch.setenv(HOST_ENV, "172.31.240.2")
    with pytest.raises(RuntimeError) as excinfo:
        asyncio.run(_configure_vigil_upstream(
            _Session(result=result), container_url="http://127.0.0.1:48080", access_token="t"))
    assert needle in str(excinfo.value)


def test_a_nonsense_port_is_refused(monkeypatch):
    monkeypatch.setenv(HOST_ENV, "172.31.240.2")
    monkeypatch.setenv(PORT_ENV, "not-a-port")
    with pytest.raises(RuntimeError):
        asyncio.run(_configure_vigil_upstream(
            _Session(), container_url="http://127.0.0.1:48080", access_token="t"))


def test_negative_control_the_fake_session_would_have_recorded_a_call():
    """Proves the no-op assertion above is not vacuous: this session DOES record when called."""
    session = _Session()
    asyncio.run(session.exec("curl", "x"))
    assert session.calls, "the fake session does not record calls, so the no-op test proves nothing"
