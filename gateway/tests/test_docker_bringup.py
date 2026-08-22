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
                 build_rc=0, compose_rc=0, image_id="sha256:built", running_id="__match__"):
        self.image, self.sandbox_net, self.egress_net = image, sandbox_net, egress_net
        self.container, self.build_rc, self.compose_rc = container, build_rc, compose_rc
        self.image_id = image_id
        # By default the running container reports the SAME id we just built (so the pin verifies); pass an
        # explicit running_id to simulate a DIGEST MISMATCH (a tag repointed at other bytes).
        self.running_id = image_id if running_id == "__match__" else running_id
        self.calls: list[list[str]] = []
        self.envs: list = []                          # the env= each call was given (for interpolation asserts)

    def run(self, args, capture_output=True, text=True, env=None, **kw):
        self.calls.append(list(args))
        self.envs.append(env)
        sub = list(args[1:])   # drop the docker binary
        rc, out = 0, ""
        if sub[:2] == ["image", "inspect"]:
            if "-f" in sub:                            # `image inspect -f {{.Id}} <img>` → the content id
                rc, out = (0, self.image_id) if self.image else (1, "")
            else:                                      # `image inspect <img>` → existence
                rc = 0 if self.image else 1
        elif sub[:2] == ["network", "inspect"]:
            present = self.sandbox_net if sub[2] == SANDBOX_NETWORK else self.egress_net
            rc = 0 if present else 1
        elif sub[:1] == ["inspect"]:
            fmt = sub[sub.index("-f") + 1] if "-f" in sub else ""
            if self.container == "absent":
                rc, out = 1, ""
            elif "{{.Image}}" in fmt:                  # the running container's image id
                rc, out = 0, (self.running_id or "")
            else:                                      # `{{.State.Status}}` → the container state
                rc, out = 0, self.container
        elif sub[:1] == ["build"]:
            rc = self.build_rc
            if rc == 0:
                self.image = True        # a successful build creates the image (so image_id resolves after)
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


def _ctx(tmp_path):
    """A throwaway build context (a couple of files) so content-addressing has something real to hash."""
    ctx = tmp_path / "gateway"
    ctx.mkdir()
    (ctx / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    (ctx / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    return ctx


def test_compose_up_builds_absent_image_then_composes(fake, tmp_path):
    fd = fake(image=False, container="running")
    ctx = _ctx(tmp_path)
    res = SandboxNetworking().compose_up("compose.yml", context_dir=ctx, pin_path=tmp_path / "pin.json")
    # richer return: the build ran, the gateway is running, and the image tag is content-addressed
    assert res["image_built"] is True
    assert res["gateway"] == "running"
    assert res["image_tag"].startswith("vigil-gateway:ctx-")
    subs = fd.subcommands()
    assert "build" in subs and "compose" in subs
    assert subs.index("build") < subs.index("compose")                # image first, then up


def test_compose_up_skips_build_when_image_present(fake, tmp_path):
    # NEGATIVE CONTROL for "always rebuild": the content-addressed tag already exists (unchanged context) →
    # NO build runs. This is what makes an unchanged upgrade a no-op instead of a needless rebuild.
    fd = fake(image=True, container="running")
    ctx = _ctx(tmp_path)
    res = SandboxNetworking().compose_up("compose.yml", context_dir=ctx, pin_path=tmp_path / "pin.json")
    assert res["image_built"] is False
    assert "build" not in fd.subcommands()


def test_compose_up_sets_content_addressed_image_tag_env(fake, tmp_path):
    # The compose file interpolates VIGIL_GATEWAY_IMAGE_TAG into the gateway `image:`; compose_up MUST set
    # it to the content-addressed tag so `docker compose up -d` recreates the container when the tag flips.
    fd = fake(image=True, container="running")
    ctx = _ctx(tmp_path)
    from vigil_gateway.docker import IMAGE_TAG_ENV, content_addressed_tag
    expected = content_addressed_tag(ctx).split(":", 1)[1]
    SandboxNetworking().compose_up("compose.yml", context_dir=ctx, pin_path=tmp_path / "pin.json")
    compose_env = next(e for c, e in zip(fd.calls, fd.envs) if len(c) > 1 and c[1] == "compose")
    assert compose_env is not None and compose_env.get(IMAGE_TAG_ENV) == expected
    assert "PATH" in compose_env, "env must be a FULL environment, not a sparse override"


def test_compose_up_fails_closed_on_digest_mismatch(fake, tmp_path):
    # The running container is NOT the image we just built (a tag repointed at other bytes / a stale
    # container). compose_up must REFUSE (fail-closed) rather than leave a silent old egress gate up.
    fake(image=True, container="running", image_id="sha256:fresh", running_id="sha256:STALE")
    ctx = _ctx(tmp_path)
    with pytest.raises(RuntimeError, match="DIGEST MISMATCH"):
        SandboxNetworking().compose_up("compose.yml", context_dir=ctx, pin_path=tmp_path / "pin.json")


def test_compose_up_records_the_runtime_pin(fake, tmp_path):
    import json
    from vigil_gateway.docker import PIN_SCHEMA, context_digest
    fake(image=True, container="running", image_id="sha256:built")
    ctx = _ctx(tmp_path)
    pin_path = tmp_path / "pin.json"
    SandboxNetworking().compose_up("compose.yml", context_dir=ctx, pin_path=pin_path)
    rec = json.loads(pin_path.read_text())
    assert rec["schema"] == PIN_SCHEMA
    assert rec["context_digest"] == context_digest(ctx)     # the pin binds the CURRENT context…
    assert rec["image_id"] == "sha256:built"                # …to the built image id (what the check reads)


def test_compose_up_raises_on_compose_failure(fake, tmp_path):
    fake(image=True, compose_rc=1)
    with pytest.raises(RuntimeError, match="docker compose up"):
        SandboxNetworking().compose_up("compose.yml", context_dir=_ctx(tmp_path), pin_path=tmp_path / "pin.json")


def test_compose_up_waits_for_healthy(fake, tmp_path):
    # W0-6 defence-in-depth: `--wait` makes `docker compose up -d` block until the gateway is running/
    # healthy (per the compose healthcheck) and return non-zero otherwise, so a start-then-exit gateway is a
    # compose FAILURE here, not an exit-0-but-dead container. (The caller's container_state() check is the
    # belt to this suspenders — see integration/tests/test_up_egress_gate_failclosed.py.)
    fd = fake(image=True, container="running")
    SandboxNetworking().compose_up("compose.yml", context_dir=_ctx(tmp_path), pin_path=tmp_path / "pin.json")
    compose_calls = [c for c in fd.calls if len(c) > 1 and c[1] == "compose"]
    assert compose_calls, "expected a `docker compose` invocation"
    assert all("--wait" in c for c in compose_calls)                  # every compose-up blocks on readiness


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
    # the gateway image is CONTENT-ADDRESSED via env interpolation (issue #511): `vigil services up` sets
    # VIGIL_GATEWAY_IMAGE_TAG to the ctx-<digest> tag it built, so a source change forces a recreate.
    from vigil_gateway.docker import IMAGE_REPO, IMAGE_TAG_ENV
    assert f"image: {IMAGE_REPO}:${{{IMAGE_TAG_ENV}:-latest}}" in committed
    assert "internal: true" in committed                               # the sandbox net is deny-default
    assert f"ipv4_address: {net.sandbox_gateway_ip()}" in committed     # the pinned sandbox-net bind
    assert "healthcheck:" in committed and "start_period:" in committed  # W0-6 gate-readiness probe (--wait)
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


def test_docker_calls_are_timeout_bounded(monkeypatch, tmp_path):
    # BLOCK-1 (red-pen): every docker subprocess must carry a timeout so a wedged pull/build can never
    # hang the caller (e.g. the console request thread on a UI bring-up). Assert build/compose are bounded.
    from types import SimpleNamespace
    seen = []

    def _run(cmd, capture_output=True, text=True, env=None, **kw):
        seen.append(kw.get("timeout"))
        sub = cmd[1:]
        if sub[:2] == ["image", "inspect"]:
            # image absent (no `-f`) → build runs; `-f {{.Id}}` (image_id) returns a value so the pin verifies
            return SimpleNamespace(returncode=(0 if "-f" in sub else 1),
                                   stdout=("sha256:built" if "-f" in sub else ""), stderr="")
        if sub[:1] == ["inspect"]:                              # container state / running image id
            fmt = sub[sub.index("-f") + 1] if "-f" in sub else ""
            return SimpleNamespace(returncode=0, stdout=("sha256:built" if "{{.Image}}" in fmt else "running"),
                                   stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")   # build / compose ok
    monkeypatch.setattr(dmod.shutil, "which", lambda n: "/usr/bin/docker")
    monkeypatch.setattr(dmod.subprocess, "run", _run)
    ctx = tmp_path / "gateway"
    ctx.mkdir()
    (ctx / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    SandboxNetworking().compose_up("compose.yml", context_dir=ctx, pin_path=tmp_path / "pin.json")
    assert seen and all(t is not None and t > 0 for t in seen)   # NO unbounded docker call
    assert max(seen) >= 300                                       # build/compose gets a generous bound
