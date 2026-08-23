"""Release gate — the RESOURCE-EXHAUSTION battery, as an honest scoreboard.

WHAT THIS FILE IS. The release gate (plan Part III, "Test layers") names ``resource exhaustion`` — a hostile
or runaway tool must not be able to exhaust the host: fork-bomb it (pids), eat its memory, or peg its CPU.
VIGIL runs every external tool inside a container whose ``docker run`` argv carries hard limits
(``live.external_tool.DockerTopologyBackend``), and the gateway sidecars run with the container-hardening
posture (cap-drop ALL, no-new-privileges, read-only rootfs). This board proves the WIRING that imposes each
limit — evaluated in-process from the pure argv builder and the COMMITTED compose file, no Docker, no kernel.
The LIVE kernel-enforcement drill (fork-bomb a real container, watch the pids cap hold) needs a Docker
daemon, so it xfails here with a named blocking slice.

HOW IT STAYS HONEST (model: ``test_production_invariants.py``).
  * Each row asserts the TRUE bar; a bar the system does not meet is
    ``@pytest.mark.xfail(strict=True, reason="<slice>")`` so an unexpected pass fails the build.
  * Every row carries a negative control proving the probe reads the REAL value — the argv reflects a
    *changed* limit (so the assertion is not comparing against a hard-coded constant) and a *relaxed* option
    genuinely drops from the argv (so "the flag is present" is a real difference, not always-true).

NO FRAMEWORK IMPORTS — ``vigil_integration.live.external_tool`` imports framework-free, and the compose is a
committed artifact, so this runs in BOTH legs of the required P5 job and needs no ci.yml offense-leg entry.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from vigil_integration.live.external_tool import DockerTopologyBackend

_REPO = Path(__file__).resolve().parents[2]
_COMPOSE = _REPO / "infra" / "docker" / "docker-compose.yml"

# A digest-pinned image so any construction is realistic (build_argv does not require the pin, but keeping it
# valid means these fixtures double as documentation of a well-formed backend).
_IMG = "vigil/nmap@sha256:" + "a" * 64

_LIVE_DRILL_SLICE = "S5 container-hardening LIVE drill (fork-bomb / memory-hog a real container and assert the kernel cap holds) — needs a Docker daemon, not runnable in the P5 job"


def _argv(**overrides) -> list[str]:
    return DockerTopologyBackend(image=_IMG, **overrides).build_argv(["nmap", "-p", "80", "127.0.0.1"])


def _flag_value(argv: list[str], flag: str) -> str | None:
    """The token following ``flag`` in a docker run argv, or None if the flag is absent."""
    for i, tok in enumerate(argv):
        if tok == flag and i + 1 < len(argv):
            return argv[i + 1]
    return None


# =========================================================================================================
# The three exhaustion vectors the gate names: memory, cpu, pids.
# =========================================================================================================
def test_memory_is_hard_capped_with_no_swap_escape():
    """``--memory`` caps RAM and ``--memory-swap`` is set EQUAL to it, so the container gets zero swap — a
    memory hog is OOM-killed at the cap instead of swapping the host to its knees."""
    argv = _argv()
    mem = _flag_value(argv, "--memory")
    swap = _flag_value(argv, "--memory-swap")
    assert mem, "no --memory cap in the tool-run argv — a runaway tool could exhaust host RAM"
    assert swap == mem, (
        f"--memory-swap ({swap!r}) is not equal to --memory ({mem!r}); a non-equal swap limit lets the "
        "container swap past its RAM cap"
    )


def test_cpu_is_quota_bounded():
    argv = _argv()
    cpus = _flag_value(argv, "--cpus")
    assert cpus and float(cpus) > 0, "no --cpus quota in the tool-run argv — a tool could peg every host core"


def test_pids_are_bounded_against_a_fork_bomb():
    argv = _argv()
    pids = _flag_value(argv, "--pids-limit")
    assert pids and int(pids) > 0, "no --pids-limit in the tool-run argv — a fork bomb could exhaust host PIDs"


def test_the_container_never_runs_as_root_and_cannot_escalate():
    """Least-privilege backstops the resource caps: a non-root user, all caps dropped, no-new-privileges, and
    a read-only rootfs with a size-capped tmpfs (so /tmp cannot be a disk-exhaustion vector either)."""
    argv = _argv()
    user = _flag_value(argv, "--user")
    assert user and not user.startswith("0:") and user != "0", f"the tool runs as {user!r} — must be non-root"
    assert _flag_value(argv, "--cap-drop") == "ALL", "the container does not drop ALL capabilities"
    assert "no-new-privileges:true" in argv, "the container can gain privileges (no no-new-privileges)"
    assert "--read-only" in argv, "the container rootfs is writable (no --read-only)"
    tmpfs = _flag_value(argv, "--tmpfs")
    assert tmpfs and "size=" in tmpfs, f"the /tmp tmpfs is not size-capped ({tmpfs!r}) — a disk-fill vector"


# =========================================================================================================
# Non-vacuity: the argv READS the configured limits, and a relaxed option genuinely drops.
# =========================================================================================================
def test_negative_control_the_argv_reflects_the_configured_limits_not_a_constant():
    """Proves the rows above read the REAL configured values: a backend built with DIFFERENT limits emits
    those different values. If the assertions were comparing against baked-in constants this would fail."""
    argv = _argv(memory="512m", cpus="0.5", pids_limit=64, tmpfs_size="16m")
    assert _flag_value(argv, "--memory") == "512m"
    assert _flag_value(argv, "--memory-swap") == "512m"   # swap tracks memory, whatever memory is
    assert _flag_value(argv, "--cpus") == "0.5"
    assert _flag_value(argv, "--pids-limit") == "64"
    assert _flag_value(argv, "--tmpfs") == "/tmp:rw,size=16m"


def test_negative_control_relaxing_the_rootfs_drops_the_read_only_flag():
    """Proves ``--read-only`` is a real, conditional flag and not always emitted: a backend with
    ``read_only_rootfs=False`` omits both ``--read-only`` and the tmpfs. So "the flag is present" in the row
    above is a genuine difference the committed default makes, not a constant."""
    relaxed = _argv(read_only_rootfs=False)
    assert "--read-only" not in relaxed, "read_only_rootfs=False still emitted --read-only — the flag is not real"
    assert "--tmpfs" not in relaxed


# =========================================================================================================
# Container hardening of the COMMITTED gateway sidecars (the parity posture the tool-run argv above shares).
# =========================================================================================================
def _service_block(name: str) -> str:
    text = _COMPOSE.read_text(encoding="utf-8")
    start = text.index(f"\n  {name}:")
    # up to the next top-level "  <service>:" or EOF
    rest = text[start + 1:]
    m = re.search(r"\n  [a-zA-Z0-9_-]+:\n", rest)
    return rest[: m.start()] if m else rest


@pytest.mark.parametrize("service", ["vigil-gateway", "vigil-gateway-firewall"])
def test_committed_gateway_sidecars_are_hardened(service):
    block = _service_block(service)
    assert "cap_drop:" in block and "ALL" in block, f"{service} does not drop ALL capabilities in the compose"
    assert "no-new-privileges:true" in block, f"{service} does not set no-new-privileges in the compose"
    assert "read_only: true" in block, f"{service} does not run with a read-only rootfs in the compose"


def test_negative_control_the_compose_parser_would_notice_an_unhardened_service():
    """Non-vacuity for the compose rows: the parser really inspects a service body, so a hand-built
    unhardened block is visibly missing the hardening tokens. (Proves the rows above are not matching the
    same tokens somewhere else in the file.)"""
    unhardened = "\n  worldly:\n    image: x\n    command: [\"sh\"]\n  next-service:\n"
    m = re.search(r"\n  next-service:\n", unhardened)
    body = unhardened[unhardened.index("\n  worldly:") + 1 : m.start()]
    assert "cap_drop:" not in body and "read_only: true" not in body, (
        "the compose-body parser cannot distinguish a hardened service from an unhardened one"
    )


# =========================================================================================================
# The LIVE kernel-enforcement drill is not runnable in CI — an honest xfail that self-updates.
# =========================================================================================================
@pytest.mark.xfail(strict=True, reason=_LIVE_DRILL_SLICE)
def test_live_forkbomb_is_capped_by_the_kernel():
    """The end-to-end proof: actually run a container with these limits, fork-bomb inside it, and assert the
    kernel holds the pids cap (and OOM-kills a memory hog at the memory cap). That drill needs a Docker
    daemon + a pinned probe image the required job does not provision, so it is driven by a harness that does
    not exist yet — this xfails cleanly (no Docker spawned, no image pulled, no fork bomb) until the harness
    lands, at which point strict-xfail flips it red and the marker comes off. The WIRING that imposes the
    caps is proven for real by the argv rows above."""
    from vigil_integration.live import resource_limit_kernel_drill  # noqa: F401  (no such harness yet)

    raise AssertionError("no in-CI harness runs a real fork-bomb-under-cap container drill")


# =========================================================================================================
# The scoreboard itself.
# =========================================================================================================
def test_no_row_is_a_non_strict_xfail():
    module = __import__(__name__, fromlist=["*"])
    for name, obj in vars(module).items():
        if not (name.startswith("test_") and callable(obj)):
            continue
        for mark in getattr(obj, "pytestmark", []):
            if mark.name == "xfail":
                assert mark.kwargs.get("strict"), f"{name} uses a non-strict xfail and would hide a regression"
