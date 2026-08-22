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


# ----------------------- S3 backstop: the privileged one-shot firewall sidecar ---------------------------
# The gateway launch path now loads the nftables L3/L4 backstop automatically, before the proxy (hence
# before Strix) comes up, via a one-shot PRIVILEGED sidecar — and the proxy fail-closes on its clean exit.

def test_render_compose_emits_the_firewall_backstop_sidecar():
    frag = SandboxNetworking().render_compose()
    assert "vigil-gateway-firewall:" in frag, "the backstop is loaded by a dedicated one-shot sidecar"
    sidecar = frag.split("vigil-gateway-firewall:")[1].split("\n  vigil-gateway:")[0]
    # it runs apply-firewall in the HOST netns with ONLY CAP_NET_ADMIN, then exits
    assert 'command: ["vigil-gateway", "apply-firewall"]' in sidecar
    assert "network_mode: host" in sidecar
    assert "NET_ADMIN" in sidecar and "- ALL" in sidecar           # cap_drop ALL, cap_add only NET_ADMIN
    assert 'restart: "no"' in sidecar                              # one-shot
    assert "no-new-privileges:true" in sidecar
    # it is handed the network coordinates apply-firewall needs (and no charter slug — it needs none)
    assert 'VIGIL_GATEWAY_GATEWAY_IP: "172.31.240.2"' in sidecar
    assert 'VIGIL_GATEWAY_SANDBOX_SUBNET: "172.31.240.0/24"' in sidecar
    # ...and the bridge IFACE, so govern() matches by interface (v4 AND v6). A v4-only source-subnet
    # match left IPv6 sandbox egress policy-accepted (red-pen sx-s3 IPv6 bypass).
    assert 'VIGIL_GATEWAY_SANDBOX_IFACE: "vigil-sbx0"' in sidecar
    # the iface name is only deterministic because the sandbox network PINS the bridge name
    net_block = frag.split("networks:")[1].split("\nservices:")[0]
    assert "com.docker.network.bridge.name: vigil-sbx0" in net_block


def test_the_proxy_fail_closes_on_the_backstop_completing():
    """FAIL-CLOSED wiring: the proxy depends_on the firewall sidecar COMPLETING SUCCESSFULLY, so a
    backstop that cannot load blocks the proxy too — `compose up --wait` then returns non-zero and the
    W0-6 bring-up leg refuses, rather than silently running the sandbox without the backstop."""
    frag = SandboxNetworking().render_compose()
    gw = frag.split("\n  vigil-gateway:")[1]
    assert "depends_on:" in gw
    assert "vigil-gateway-firewall:" in gw
    assert "condition: service_completed_successfully" in gw


def test_committed_compose_carries_the_backstop_sidecar():
    """The committed artifact (what `vigil up --services` actually runs) must carry the wiring, not just
    render_compose — guards against the compose file drifting from the code that generates it."""
    import pathlib
    repo = pathlib.Path(__file__).resolve().parents[2]
    committed = (repo / "infra" / "docker" / "docker-compose.yml").read_text(encoding="utf-8")
    assert "vigil-gateway-firewall:" in committed
    assert 'command: ["vigil-gateway", "apply-firewall"]' in committed
    assert "condition: service_completed_successfully" in committed
    # the IPv6-governance wiring must be in the committed artifact too, not just render_compose()
    assert 'VIGIL_GATEWAY_SANDBOX_IFACE: "vigil-sbx0"' in committed
    assert "com.docker.network.bridge.name: vigil-sbx0" in committed


# --------------- sx-s3 BLOCK: the sidecar runs as ROOT so cap_add NET_ADMIN is EFFECTIVE -----------------
# The image's default user is the unprivileged `vigil` (uid 10001). For a NON-root process a capability
# added with cap_add sits only in the container's permitted/bounding set — NOT in the EFFECTIVE set (there
# are no file-capabilities on `nft`), so `nft -f` fails EPERM and the backstop can NEVER load: a FAIL-OPEN
# (the sandbox could come up with egress ungoverned). The one-shot sidecar must therefore run as root
# (user: "0"); with cap_drop ALL + cap_add NET_ADMIN its effective set is then exactly {NET_ADMIN}.

def _firewall_sidecar_block(compose_text: str) -> str:
    assert "vigil-gateway-firewall:" in compose_text, "no firewall sidecar in the compose text"
    return compose_text.split("vigil-gateway-firewall:")[1].split("\n  vigil-gateway:")[0]


def _assert_firewall_is_root_with_only_net_admin(block: str) -> None:
    # runs as root so the added capability is EFFECTIVE — the crux of the sx-s3 fix. This assertion FAILS
    # if `user: "0"` is removed, which is exactly the fail-open the red-pen caught.
    assert 'user: "0"' in block, (
        'the firewall sidecar MUST set user: "0" (root) — for the non-root image user, cap_add NET_ADMIN '
        "is not in the effective set and `nft -f` fails EPERM, so the backstop can never load (fail-OPEN)"
    )
    # ...but still drops every other capability and adds ONLY NET_ADMIN (least privilege), and blocks
    # privilege escalation — root + drop-all + add-one yields CapEff={NET_ADMIN}, never a blanket privileged.
    assert "cap_drop:" in block and "- ALL" in block, "the sidecar must still cap_drop ALL"
    assert "cap_add:" in block and "NET_ADMIN" in block, "the sidecar must cap_add exactly NET_ADMIN"
    assert "no-new-privileges:true" in block, "the sidecar must forbid privilege escalation"
    assert "privileged: true" not in block, "root + drop-all + add NET_ADMIN — never a blanket privileged"


def test_render_compose_firewall_sidecar_runs_as_root_with_only_net_admin():
    _assert_firewall_is_root_with_only_net_admin(
        _firewall_sidecar_block(SandboxNetworking().render_compose()))


def test_committed_compose_firewall_sidecar_runs_as_root_with_only_net_admin():
    import pathlib
    repo = pathlib.Path(__file__).resolve().parents[2]
    committed = (repo / "infra" / "docker" / "docker-compose.yml").read_text(encoding="utf-8")
    _assert_firewall_is_root_with_only_net_admin(_firewall_sidecar_block(committed))


def _docker_usable() -> bool:
    import shutil as _sh
    if not _sh.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=20).returncode == 0
    except Exception:
        return False


@pytest.mark.skipif(not _docker_usable(),
                    reason="needs a working Docker daemon to prove the sidecar's caps against a real image")
def test_apply_firewall_fails_as_nonroot_but_succeeds_as_root_in_a_real_container():
    """The EMPIRICAL sx-s3 BLOCK proof — the CONTAINER path the deployment actually uses, not
    root-in-userns. Build the gateway image and run `apply-firewall` with the sidecar's EXACT caps
    (cap_drop ALL + cap_add NET_ADMIN): as the non-root user (uid 10001, the image default) it FAILS with
    EPERM (the added cap is not effective — the fail-open), and as root (user "0", what the compose now
    sets) it SUCCEEDS. Runs in the container's OWN net namespace (default bridge, NOT --network host) so
    the ruleset loads into a throwaway netns and never touches the host firewall; SANDBOX_IFACE is left
    unset so the ruleset matches by source-subnet (the pinned-iface fail-closed leg is tested separately).
    Skips (never fails vacuously) if the image can't be built here (no base/registry/apt).
    """
    import pathlib
    repo = pathlib.Path(__file__).resolve().parents[2]
    base = os.environ.get("VIGIL_GATEWAY_DOCKER_BASE", "python:3.11-slim")
    tag = "vigil-gateway:pytest-sx-s3"
    build = subprocess.run(
        ["docker", "build", "--build-arg", f"PYTHON_BASE={base}", "-t", tag, str(repo / "gateway")],
        capture_output=True, text=True, timeout=600)
    if build.returncode != 0:
        pytest.skip(f"could not build the gateway image here (no base/registry/apt): {build.stderr[-300:]}")
    env = ["-e", "VIGIL_GATEWAY_GATEWAY_IP=172.31.240.2",
           "-e", "VIGIL_GATEWAY_SANDBOX_SUBNET=172.31.240.0/24"]
    caps = ["--cap-drop", "ALL", "--cap-add", "NET_ADMIN"]
    try:
        # (a) the deployment's non-root default user — MUST fail EPERM (proves user:"0" is load-bearing)
        nonroot = subprocess.run(
            ["docker", "run", "--rm", "--user", "10001", *caps, *env, tag, "apply-firewall"],
            capture_output=True, text=True, timeout=120)
        assert nonroot.returncode != 0, (
            "apply-firewall UNEXPECTEDLY succeeded as a NON-root user — without user:\"0\" the compose "
            "sidecar would silently fail-OPEN in production (backstop never loads)"
        )
        assert "not permitted" in (nonroot.stdout + nonroot.stderr).lower(), (nonroot.stdout + nonroot.stderr)[-400:]
        # (b) root with the same drop-all + add-NET_ADMIN caps — MUST succeed (CapEff={NET_ADMIN})
        root = subprocess.run(
            ["docker", "run", "--rm", "--user", "0", *caps, *env, tag, "apply-firewall"],
            capture_output=True, text=True, timeout=120)
        assert root.returncode == 0, (
            f"apply-firewall FAILED as root with cap_add NET_ADMIN — the fix does not hold: "
            f"{(root.stdout + root.stderr)[-400:]}")
        assert "firewall applied" in root.stdout, root.stdout[-400:]
    finally:
        subprocess.run(["docker", "image", "rm", "-f", tag], capture_output=True, text=True)


# ------ sx-s3 MEDIUM: ensure_networks refuses a pre-existing sandbox net with a stale/absent bridge ------
# If vigil_sandbox already exists but was NOT created with the pinned bridge name, silently reusing it
# leaves the interface-governed backstop pointing at a bridge that does not exist (matches nothing).
# ensure_networks() must refuse rather than reuse it.

def test_ensure_networks_refuses_a_preexisting_sandbox_net_with_a_stale_bridge(monkeypatch):
    def _run(args, capture_output=True, text=True, **kw):
        sub = list(args[1:])
        if sub[:2] == ["network", "inspect"] and "-f" in sub:
            return SimpleNamespace(returncode=0, stdout="br-stale123\n", stderr="")   # WRONG pinned bridge
        if sub[:2] == ["network", "inspect"]:
            return SimpleNamespace(returncode=0, stdout="", stderr="")                # network exists
        raise AssertionError(f"unexpected docker call (should refuse before creating): {sub}")
    monkeypatch.setattr(dmod.shutil, "which", lambda n: "/usr/bin/docker")
    monkeypatch.setattr(dmod.subprocess, "run", _run)
    with pytest.raises(RuntimeError, match="bridge"):
        SandboxNetworking().ensure_networks()


def test_ensure_networks_accepts_a_correctly_pinned_sandbox_net(monkeypatch):
    created: list[str] = []

    def _run(args, capture_output=True, text=True, **kw):
        sub = list(args[1:])
        if sub[:2] == ["network", "inspect"] and "-f" in sub:
            return SimpleNamespace(returncode=0, stdout="vigil-sbx0\n", stderr="")    # correct pinned bridge
        if sub[:2] == ["network", "inspect"]:
            present = sub[2] == SANDBOX_NETWORK                                        # egress absent
            return SimpleNamespace(returncode=0 if present else 1, stdout="", stderr="")
        if sub[:2] == ["network", "create"]:
            created.append(sub[-1])
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        raise AssertionError(f"unexpected docker call: {sub}")
    monkeypatch.setattr(dmod.shutil, "which", lambda n: "/usr/bin/docker")
    monkeypatch.setattr(dmod.subprocess, "run", _run)
    SandboxNetworking().ensure_networks()                # must NOT raise
    assert SANDBOX_NETWORK not in created                # correctly pinned + present → not recreated
    assert EGRESS_NETWORK in created                     # egress was absent → created
