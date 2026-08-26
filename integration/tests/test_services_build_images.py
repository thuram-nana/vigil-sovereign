"""WS1b (SOVEREIGN CONSOLE) — build the offence/defence engine images if-absent, best-effort.

`vigil up --services` and `vigil services up --all` now build vigil/strix-sandbox + vigil/aegis-gateway
when missing (via their compose profiles), so a strix/aegis engagement is ready at container-create time
without the operator remembering a separate `make strix` / `make aegis-image`. It is BEST-EFFORT: a build
failure is recorded, never raised — a missing engine image degrades a later engagement with a clear error,
it is NOT a security gate (the egress gateway is the one that fails closed).
"""
import re
import subprocess
from pathlib import Path
from types import SimpleNamespace

from vigil_integration import services as smod
from vigil_integration.services import ENGINE_IMAGES, RootServices

REPO = Path(__file__).resolve().parents[2]


def _fake_docker(monkeypatch, *, present, build_rc=0, build_err=""):
    calls = []

    def _run(cmd, capture_output=True, text=True, **kw):
        calls.append(cmd)
        if "inspect" in cmd:
            return SimpleNamespace(returncode=0 if present else 1, stdout="", stderr="")
        if "build" in cmd:
            return SimpleNamespace(returncode=build_rc, stdout="", stderr=build_err)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(smod.shutil, "which", lambda n: "/usr/bin/docker")
    monkeypatch.setattr(smod.subprocess, "run", _run)
    return calls


def test_present_image_is_never_rebuilt(monkeypatch, tmp_path):
    calls = _fake_docker(monkeypatch, present=True)
    out = RootServices(tmp_path).build_images_if_absent(["strix-sandbox"])
    assert out == {"strix-sandbox": "present"}
    assert not any("build" in c for c in calls)                      # the negative control: no build of a present image


def test_absent_image_is_built_via_its_compose_profile(monkeypatch, tmp_path):
    (tmp_path / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    calls = _fake_docker(monkeypatch, present=False, build_rc=0)
    out = RootServices(tmp_path).build_images_if_absent(["strix-sandbox"])
    assert out == {"strix-sandbox": "built"}
    build = [c for c in calls if "build" in c][0]
    assert "--profile" in build and "strix" in build and "strix-sandbox" in build   # the correct build-only leg


def test_a_build_failure_is_recorded_not_raised(monkeypatch, tmp_path):
    (tmp_path / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    _fake_docker(monkeypatch, present=False, build_rc=1, build_err="boom: no space left on device")
    out = RootServices(tmp_path).build_images_if_absent(["aegis-gateway"])          # must NOT raise
    assert out["aegis-gateway"].startswith("failed") and "boom" in out["aegis-gateway"]


def test_unknown_image_name_is_reported_not_built(monkeypatch, tmp_path):
    calls = _fake_docker(monkeypatch, present=True)
    assert RootServices(tmp_path).build_images_if_absent(["not-an-image"]) == {"not-an-image": "unknown"}
    assert not any("build" in c for c in calls)


def test_default_builds_both_engine_images(monkeypatch, tmp_path):
    (tmp_path / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    _fake_docker(monkeypatch, present=False, build_rc=0)
    out = RootServices(tmp_path).build_images_if_absent()                            # no arg → all engine images
    assert set(out) == set(ENGINE_IMAGES) and all(v == "built" for v in out.values())


def test_engine_image_tags_and_legs_match_the_compose_build_services():
    # Drift guard: isolate each ENGINE_IMAGES entry's OWN service block in the compose and assert its exact
    # image tag, its profile in that service's profile list, and a `build:` leg all CO-LOCATE there. A bare
    # substring check (`"strix" in compose`) would pass on a profile rename because `"strix"` is a substring
    # of `strix-sandbox` — so this keys on the exact `profiles: [...]` / `image:` lines inside the block.
    compose = (REPO / "docker-compose.yml").read_text(encoding="utf-8")
    for meta in ENGINE_IMAGES.values():
        m = re.search(rf"(?m)^  {re.escape(meta['service'])}:\n(.*?)(?=^  \w|^\w|\Z)", compose, re.S)
        assert m, f"{meta['service']} is not a top-level compose service"
        block = m.group(1)
        assert f"image: {meta['image']}" in block, f"{meta['service']} does not declare image {meta['image']}"
        assert f'profiles: ["{meta["profile"]}"]' in block, \
            f"{meta['service']} does not carry profile {meta['profile']!r} (a substring check would miss a rename)"
        assert "build:" in block, f"{meta['service']} has no build: leg — it is not a build-only image"


def test_a_raised_subprocess_error_is_recorded_not_raised(monkeypatch, tmp_path):
    # The exception-catch branch (not just a nonzero returncode): a build that TIMES OUT must be recorded,
    # never propagated (best-effort).
    (tmp_path / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")

    def _run(cmd, capture_output=True, text=True, **kw):
        if "inspect" in cmd:
            return SimpleNamespace(returncode=1, stdout="", stderr="")           # absent → tries to build
        raise subprocess.TimeoutExpired(cmd, kw.get("timeout"))

    monkeypatch.setattr(smod.shutil, "which", lambda n: "/usr/bin/docker")
    monkeypatch.setattr(smod.subprocess, "run", _run)
    out = RootServices(tmp_path).build_images_if_absent(["strix-sandbox"])        # must NOT raise
    assert out["strix-sandbox"].startswith("failed:")


def test_a_raising_progress_callback_is_swallowed(monkeypatch, tmp_path):
    # A best-effort helper must survive even a raising progress callback (e.g. print to a closed stderr →
    # ValueError, which is NOT OSError/SubprocessError) — the broadened except covers it.
    (tmp_path / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    _fake_docker(monkeypatch, present=False, build_rc=0)

    def _boom(*a, **k):
        raise ValueError("I/O operation on closed file")

    out = RootServices(tmp_path).build_images_if_absent(["strix-sandbox"], progress=_boom)   # must NOT raise
    assert out["strix-sandbox"].startswith("failed:")
