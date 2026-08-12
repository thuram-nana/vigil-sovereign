"""The docker bring-up (`vigil services up`): build the image if absent, then create the networks +
gateway container if none exist — idempotent, re-runnable.

The lifecycle is exercised against a FAKE docker (a fake subprocess.run keyed on the docker subcommand),
so the create-if-absent logic is CI-testable without a daemon. A real `docker build` + smoke is opt-in
(`VIGIL_GATEWAY_DOCKER_IT=1`) since CI runners have no reliable registry access; it was verified by hand.
"""
from __future__ import annotations

import os
import subprocess
from types import SimpleNamespace

import pytest

from vigil_gateway import docker as dmod
from vigil_gateway.docker import DEFAULT_IMAGE, EGRESS_NETWORK, SANDBOX_NETWORK, SandboxNetworking


class FakeDocker:
    """Canned docker responses keyed on the subcommand; records every invocation for assertions."""

    def __init__(self, *, image=False, sandbox_net=False, egress_net=False, container="absent",
                 build_rc=0, compose_rc=0):
        self.image, self.sandbox_net, self.egress_net = image, sandbox_net, egress_net
        self.container, self.build_rc, self.compose_rc = container, build_rc, compose_rc
        self.calls: list[list[str]] = []

    def run(self, args, capture_output=True, text=True, **kw):
        self.calls.append(list(args))
        sub = list(args[1:])   # drop the docker binary
        rc, out = 0, ""
        if sub[:2] == ["image", "inspect"]:
            rc = 0 if self.image else 1
        elif sub[:2] == ["network", "inspect"]:
            present = self.sandbox_net if sub[2] == SANDBOX_NETWORK else self.egress_net
            rc = 0 if present else 1
        elif sub[:1] == ["inspect"]:
            rc, out = (1, "") if self.container == "absent" else (0, self.container)
        elif sub[:1] == ["build"]:
            rc = self.build_rc
        elif sub[:1] == ["compose"]:
            rc = self.compose_rc
        return SimpleNamespace(returncode=rc, stdout=out, stderr=("boom" if rc else ""))

    def subcommands(self):
        return [c[1] for c in self.calls]   # the docker verb of each call


@pytest.fixture
def fake(monkeypatch):
    def _install(**kw):
        fd = FakeDocker(**kw)
        monkeypatch.setattr(dmod.shutil, "which", lambda name: "/usr/bin/docker")
        monkeypatch.setattr(dmod.subprocess, "run", fd.run)
        return fd
    return _install


# --------------------------- create-if-absent (idempotency) ---------------------------

def test_ensure_image_builds_only_when_absent(fake):
    fd = fake(image=False)
    assert SandboxNetworking().ensure_image("gateway") is True         # absent → a build runs
    assert "build" in fd.subcommands()

    fd2 = fake(image=True)
    assert SandboxNetworking().ensure_image("gateway") is False        # present → NO build
    assert "build" not in fd2.subcommands()


def test_ensure_image_raises_on_build_failure(fake):
    fake(image=False, build_rc=1)
    with pytest.raises(RuntimeError, match="docker build"):
        SandboxNetworking().ensure_image("gateway")


def test_container_state_parses_and_absent(fake):
    assert SandboxNetworking().container_state() == "absent"           # inspect rc!=0 → absent
    fake(container="running")
    assert SandboxNetworking().container_state() == "running"


def test_compose_up_builds_absent_image_then_composes(fake):
    fd = fake(image=False, container="running")
    res = SandboxNetworking().compose_up("compose.yml", context_dir="gateway")
    assert res == {"image_built": True, "gateway": "running"}
    subs = fd.subcommands()
    assert "build" in subs and "compose" in subs
    assert subs.index("build") < subs.index("compose")                # image first, then up


def test_compose_up_skips_build_when_image_present(fake):
    fd = fake(image=True, container="running")
    res = SandboxNetworking().compose_up("compose.yml", context_dir="gateway")
    assert res["image_built"] is False
    assert "build" not in fd.subcommands()


def test_compose_up_raises_on_compose_failure(fake):
    fake(image=True, compose_rc=1)
    with pytest.raises(RuntimeError, match="docker compose up"):
        SandboxNetworking().compose_up("compose.yml", context_dir="gateway")


def test_status_reports_create_if_absent_snapshot(fake):
    fake(image=True, sandbox_net=True, egress_net=False, container="running")
    st = SandboxNetworking().status()
    assert st["image"] is True
    assert st["networks"][SANDBOX_NETWORK] is True
    assert st["networks"][EGRESS_NETWORK] is False
    assert st["gateway"] == "running"


# ------------------------------- the committed compose --------------------------------

def test_committed_compose_matches_render_and_is_sane():
    import pathlib
    repo = pathlib.Path(__file__).resolve().parents[2]
    committed = (repo / "infra" / "docker" / "docker-compose.yml").read_text(encoding="utf-8")
    net = SandboxNetworking()
    # the committed artifact is exactly what render_compose emits (so it never drifts silently)
    assert committed == net.render_compose()
    # structural sanity (no yaml dep in the gateway test env)
    assert "0.0.0.0" not in committed                                   # never a public bind
    assert f"image: {DEFAULT_IMAGE}" in committed
    assert "internal: true" in committed                               # the sandbox net is deny-default
    assert f"ipv4_address: {net.sandbox_gateway_ip()}" in committed     # the pinned sandbox-net bind
    for netname in (SANDBOX_NETWORK, EGRESS_NETWORK):
        assert netname in committed


def test_render_compose_refuses_unsafe_charter_slug():
    net = SandboxNetworking()
    for bad in ('a"b', "a\nVIGIL_GATEWAY_PROXY_TOKEN: leaked", "a b", "a`b"):
        with pytest.raises(ValueError, match="simple slug"):   # no YAML injection via the slug
            net.render_compose(charter_slug=bad)
    assert "demo-target_1" in net.render_compose(charter_slug="demo-target_1")   # a real slug is fine
    # the sibling template var (gateway_image) is guarded the same way
    for bad_img in ('x:latest\n    privileged: true', 'a b', 'x"y', "x\ncap_add: [ALL]"):
        with pytest.raises(ValueError, match="image reference"):
            net.render_compose(gateway_image=bad_img)
    assert "myrepo/vigil-gateway:1.2.3" in net.render_compose(gateway_image="myrepo/vigil-gateway:1.2.3")


# --------------------------- opt-in real build + smoke --------------------------------

@pytest.mark.skipif(os.environ.get("VIGIL_GATEWAY_DOCKER_IT") != "1",
                    reason="opt-in: needs docker + a cached/pullable python base (VIGIL_GATEWAY_DOCKER_IT=1)")
def test_real_docker_build_and_fail_closed():
    import pathlib
    repo = pathlib.Path(__file__).resolve().parents[2]
    base = os.environ.get("VIGIL_GATEWAY_DOCKER_BASE", "python:3.13-slim")
    tag = "vigil-gateway:pytest"
    build = subprocess.run(["docker", "build", "--build-arg", f"PYTHON_BASE={base}", "-t", tag,
                            str(repo / "gateway")], capture_output=True, text=True)
    assert build.returncode == 0, build.stderr[-800:]
    try:
        # serve-proxy with no charter must fail closed (the scope source is required)
        run = subprocess.run(["docker", "run", "--rm", tag, "serve-proxy"], capture_output=True, text=True)
        assert "VIGIL_GATEWAY_CHARTER_SLUG is required" in (run.stdout + run.stderr)
    finally:
        subprocess.run(["docker", "image", "rm", "-f", tag], capture_output=True, text=True)


def test_docker_calls_are_timeout_bounded(monkeypatch):
    # BLOCK-1 (red-pen): every docker subprocess must carry a timeout so a wedged pull/build can never
    # hang the caller (e.g. the console request thread on a UI bring-up). Assert build/compose are bounded.
    from types import SimpleNamespace
    seen = []

    def _run(cmd, capture_output=True, text=True, **kw):
        seen.append(kw.get("timeout"))
        rc = 1 if cmd[1:3] == ["image", "inspect"] else 0     # image absent → build runs; build/compose ok
        return SimpleNamespace(returncode=rc, stdout="", stderr="")
    monkeypatch.setattr(dmod.shutil, "which", lambda n: "/usr/bin/docker")
    monkeypatch.setattr(dmod.subprocess, "run", _run)
    SandboxNetworking().compose_up("compose.yml", context_dir="gateway")
    assert seen and all(t is not None and t > 0 for t in seen)   # NO unbounded docker call
    assert max(seen) >= 300                                       # build/compose gets a generous bound
