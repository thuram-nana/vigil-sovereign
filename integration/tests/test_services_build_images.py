"""WS1b (SOVEREIGN CONSOLE) — build the offence/defence engine images if-absent, best-effort.

`vigil up --services` and `vigil services up --all` now build vigil/strix-sandbox + vigil/aegis-gateway
when missing (via their compose profiles), so a strix/aegis engagement is ready at container-create time
without the operator remembering a separate `make strix` / `make aegis-image`. It is BEST-EFFORT: a build
failure is recorded, never raised — a missing engine image degrades a later engagement with a clear error,
it is NOT a security gate (the egress gateway is the one that fails closed).
"""
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
    assert out["aegis-gateway"].startswith("failed:") and "boom" in out["aegis-gateway"]


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
    # Drift guard: the tags ENGINE_IMAGES builds must be the ones the committed compose declares, or a
    # rename in one place silently builds/looks-for the wrong image.
    compose = (REPO / "docker-compose.yml").read_text(encoding="utf-8")
    for meta in ENGINE_IMAGES.values():
        assert meta["image"] in compose, f"{meta['image']} is not declared in docker-compose.yml"
        assert meta["service"] in compose, f"{meta['service']} is not a compose service"
        assert meta["profile"] in compose, f"profile {meta['profile']} not in docker-compose.yml"
