"""S2 — a Strix sandbox may not start unless it is pinned to VIGIL's gated network.

The hole this closes: ``vendor/strix`` READS ``STRIX_DOCKER_SANDBOX_NETWORK`` and
``SandboxNetworking.strix_env()`` PRODUCES it, but nothing called the producer, so every sandbox was created
on Docker's default bridge — a route to the operator LAN, the internet and 169.254.169.254 — while the
gateway, its ``internal: true`` network and the nftables backstop sat built and unreferenced.

These tests drive the pre-flight with an injected fake, so they are deterministic and touch no Docker.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from vigil_integration.strix_sandbox import UNGATED_ENV, preflight, warning_banner

_REPO = Path(__file__).resolve().parents[2]
_ACTIONS = "engine/crucible/framework/v2/console/actions.py"


class _FakeNet:
    """Stands in for SandboxNetworking. `raises` makes an introspection call blow up."""

    def __init__(self, state="running", present=True, network="vigil_sandbox", raises=None):
        self.sandbox_network = network
        self._state, self._present, self._raises = state, present, raises

    def container_state(self, name="vigil-gateway"):
        if self._raises == "state":
            raise RuntimeError("docker unreachable")
        return self._state

    def network_exists(self, name=None):
        if self._raises == "network":
            raise RuntimeError("docker unreachable")
        return self._present

    def strix_env(self):
        return {"STRIX_DOCKER_SANDBOX_NETWORK": self.sandbox_network}

    def sandbox_gateway_ip(self):
        return "172.31.240.2"


def _fn_code(module_rel: str, func_name: str) -> str:
    """A function's code with its docstring removed — a wiring probe must never match prose."""
    src = (_REPO / module_rel).read_text(encoding="utf-8", errors="replace")
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func_name:
            body = list(node.body)
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                body = body[1:]
            return "\n".join(ast.get_source_segment(src, s) or "" for s in body)
    raise AssertionError(f"{func_name} not found in {module_rel}")


@pytest.fixture(autouse=True)
def _no_ambient_override(monkeypatch):
    """The override must never leak in from the developer's environment."""
    monkeypatch.delenv(UNGATED_ENV, raising=False)


# --- the happy path: the sandbox is genuinely pinned --------------------------------------------------

def test_a_running_gateway_and_present_network_pin_the_sandbox():
    result = preflight(networking=_FakeNet())
    assert result.ok and result.gated, "a healthy topology must produce a GATED verdict"
    assert result.env["STRIX_DOCKER_SANDBOX_NETWORK"] == "vigil_sandbox", (
        "the pin env is what makes the vendored runtime join the gated network"
    )
    assert warning_banner(result) == "", "the gated path must print no ungated warning"


# --- refusals: each precondition, separately ----------------------------------------------------------

@pytest.mark.parametrize("state", ["exited", "absent", "created", "dead", "unknown"])
def test_a_gateway_that_is_not_running_refuses_the_launch(state):
    result = preflight(networking=_FakeNet(state=state))
    assert not result.ok and not result.gated
    assert result.env == {}, "a refusal must never hand back a pin env"
    assert "not running" in (result.refusal or "")
    assert "169.254.169.254" in (result.refusal or ""), (
        "the refusal should say what the operator is actually exposed to"
    )


def test_a_missing_sandbox_network_refuses_the_launch():
    result = preflight(networking=_FakeNet(present=False))
    assert not result.ok and result.env == {}
    assert "does not exist" in (result.refusal or "")


@pytest.mark.parametrize("raises", ["state", "network"])
def test_an_uninspectable_docker_is_a_refusal_not_a_bypass(raises):
    """"We could not tell" must never become "proceed" — the fail-closed rule."""
    result = preflight(networking=_FakeNet(raises=raises))
    assert not result.ok and result.env == {}
    assert "could not" in (result.refusal or "").lower()


# --- the override: loud, explicit, and never silently gated -------------------------------------------

def test_the_explicit_override_proceeds_ungated_and_says_so():
    result = preflight(allow_ungated=True, networking=_FakeNet(state="exited"))
    assert result.ok, "an explicit opt-in continues"
    assert not result.gated, "an override is NOT a gated run and must not claim to be"
    assert result.env == {}, "an override must not fabricate a pin that was never established"
    banner = warning_banner(result)
    assert "UNGATED" in banner and "FATAL-1" in banner


def test_the_override_is_readable_from_the_environment(monkeypatch):
    monkeypatch.setenv(UNGATED_ENV, "1")
    assert preflight(networking=_FakeNet(state="exited")).overridden is True


@pytest.mark.parametrize("value", ["0", "false", "no", "off", "", "maybe"])
def test_a_non_affirmative_override_value_still_refuses(monkeypatch, value):
    """Negative control: the override must require an affirmative value, not merely a set variable."""
    monkeypatch.setenv(UNGATED_ENV, value)
    assert preflight(networking=_FakeNet(state="exited")).ok is False


def test_negative_control_the_override_does_not_rescue_a_healthy_run_into_ungated():
    """With a healthy topology the run is gated regardless of the override — the pin still happens."""
    result = preflight(allow_ungated=True, networking=_FakeNet())
    assert result.ok and result.gated and result.env, (
        "an operator who set the override should still get a GATED run when the gateway is up"
    )


# --- the wiring: both spawn sites consult the gate ----------------------------------------------------

@pytest.mark.parametrize("site", ["launch_assessment", "retry_run"])
def test_both_strix_spawn_sites_consult_the_sandbox_gate(site):
    code = _fn_code(_ACTIONS, site)
    assert "_strix_sandbox_gate()" in code, f"{site} spawns Strix without the sandbox pre-flight"
    assert "_sbx_refusal" in code and "return" in code, f"{site} does not abort on a refusal"


@pytest.mark.parametrize("site", ["launch_assessment", "retry_run"])
def test_the_pin_env_reaches_the_child_environment(site):
    code = _fn_code(_ACTIONS, site)
    assert "**_sbx_env" in code, (
        f"{site} computes the pin but never merges it into the child env — the sandbox would still land "
        f"on the default bridge"
    )


def test_the_console_gate_fails_closed_when_the_preflight_cannot_load():
    """A missing/broken integration package must refuse, not silently spawn an ungated agent."""
    code = _fn_code(_ACTIONS, "_strix_sandbox_gate")
    assert "except Exception" in code and "refus" in code.lower(), (
        "the console-side gate must turn an import failure into a refusal"
    )
    assert "return {}, (" in code or 'return {},' in code


def test_negative_control_the_producer_and_consumer_are_the_real_seam():
    """Anchors the whole slice to live code rather than to names invented by the test."""
    gw = (_REPO / "gateway/vigil_gateway/docker.py").read_text(encoding="utf-8")
    assert 'STRIX_NETWORK_ENV = "STRIX_DOCKER_SANDBOX_NETWORK"' in gw
    assert "def strix_env" in gw
    runtime = (_REPO / "vendor/strix/strix/runtime/docker_client.py").read_text(encoding="utf-8")
    assert "STRIX_DOCKER_SANDBOX_NETWORK" in runtime, "the vendored runtime is what reads the pin"


# --- S3: the gated sandbox must also be told how to reach OUT through the gateway ---------------------

def test_a_gated_run_carries_the_gateway_proxy_coordinates():
    """Pinning alone ISOLATES the agent: the sandbox network is --internal, so the gateway is the only
    reachable peer. Without these coordinates Caido has nowhere to forward and the agent reaches nothing.
    """
    env = preflight(networking=_FakeNet()).env
    assert env.get("VIGIL_GATEWAY_PROXY_HOST") == "172.31.240.2", (
        "the child must learn the gateway's pinned sandbox-network address"
    )
    assert env.get("VIGIL_GATEWAY_PROXY_PORT"), "the child must learn the gateway proxy port"


def test_the_proxy_token_is_passed_only_when_the_deployment_sets_one(monkeypatch):
    """The gateway demands client auth only when a token is configured; inventing one would fail. A token
    has two legitimate sources — the env, and the short-lived credential MINTED + persisted by `vigil
    services up` — so this pins the ENV source hermetically by neutralising the persisted-file source (that
    source is exercised in test_strix_sandbox_attach_and_creds.py). With NEITHER, no token is passed."""
    import vigil_integration.strix_sandbox as _sbx
    monkeypatch.setattr(_sbx, "_persisted_proxy_token", lambda: "")   # isolate: no minted-file token
    monkeypatch.delenv("VIGIL_GATEWAY_PROXY_TOKEN", raising=False)
    assert "VIGIL_GATEWAY_PROXY_TOKEN" not in preflight(networking=_FakeNet()).env
    monkeypatch.setenv("VIGIL_GATEWAY_PROXY_TOKEN", "s3cr3t")
    assert preflight(networking=_FakeNet()).env.get("VIGIL_GATEWAY_PROXY_TOKEN") == "s3cr3t"


def test_a_refused_run_carries_no_proxy_coordinates_either():
    """Negative control: a refusal must hand back nothing an caller could mistake for a working route."""
    assert preflight(networking=_FakeNet(state="exited")).env == {}
