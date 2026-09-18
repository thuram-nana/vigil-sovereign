"""
S9c re-work — the INCONCLUSIVE-COVERAGE consumer is wired on the REAL operator-facing launch paths.

The prior slice wrote the artifact only when ``$VIGIL_PROOF_RUN_DIR`` was set, which ONLY the cloud
``launch_cloud`` verb did — so a fusion sensor's INCONCLUSIVE outcome no-op'd on the console web-engage /
suite spawn and on a retried cloud POSTURE run, and those runs rendered CLEAN over an unassessed surface.

These tests drive the REAL launch paths (``launch_assessment`` and ``retry_run``) with the subprocess
STUBBED, and assert the code ITSELF hands the fusion child this run's dir — WITHOUT the test setting
``$VIGIL_PROOF_RUN_DIR``. They then feed that captured run dir through the REAL producer + the REAL
dossier / console proof-list readers and assert the run is NOT clean and NAMES the surface.

FAIL-BEFORE / PASS-AFTER: on the inert wiring (dddc3651) the engage spawn and the non-Strix retry pass
``env_extra=None`` → the captured ``VIGIL_PROOF_RUN_DIR`` is absent → the first assertion fails (RED); the
child never writes the artifact so the dossier + proof list read CLEAN. After the fix both carry the run
dir (GREEN) and the readers refuse the clean reading.

A writer/reader-in-isolation test (test_dossier_inconclusive / test_proof_inconclusive) is exactly what
let the inert wiring pass green — this drives the wiring, not just the file contract.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from framework.v2 import engage_fusion as EF
from framework.v2.console import actions, api
from framework.v2.report import dossier as D


@pytest.fixture()
def isolate(tmp_path, monkeypatch):
    """Redirect the run registry to tmp and DELETE any ambient ``$VIGIL_PROOF_RUN_DIR`` — so the ONLY way
    an artifact can land in a run dir is the code's OWN wiring handing the child that dir, never the test."""
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path / ".console")
    monkeypatch.delenv("VIGIL_PROOF_RUN_DIR", raising=False)
    return tmp_path


def _capturing_spawn(monkeypatch):
    """Stub ``_spawn_background`` to record the (cmd, env_extra) the launch path decided to pass — the
    real wiring under test — instead of spawning a subprocess."""
    seen: dict = {}

    def _fake(run_id, rd, cmd, meta, *, capture_report, env_extra=None, env_remove=None):
        seen["run_id"] = run_id
        seen["rd"] = rd
        seen["cmd"] = cmd
        seen["env_extra"] = env_extra

    monkeypatch.setattr(actions, "_spawn_background", _fake)
    return seen


def _dossier_summary(rd: Path, tmp_path: Path, monkeypatch) -> dict:
    monkeypatch.setattr(D, "_build_proof_bundle",
                        lambda *a, **k: ({}, {"ok": False, "note": "proof bundle stubbed in test"}))
    return D.build_dossier(run_dir=str(rd), out_zip=str(tmp_path / "d.zip"), engagement_slug="acme")


# ---------------------------------------------------------------------------
# the console web/suite engage spawn — the primary operator-facing path
# ---------------------------------------------------------------------------


def test_suite_engage_spawn_threads_run_dir_and_run_is_not_clean(isolate, monkeypatch):
    tmp_path = isolate
    seen = _capturing_spawn(monkeypatch)

    # a suite engage over a loopback host routes to the gated `engage --autonomous` spawn (2079).
    r = actions.launch_assessment({"mode": "suite", "target": "http://127.0.0.1/", "scan_mode": "deep"})
    assert r.get("status") == "running", r
    assert "engage" in seen["cmd"] and "--autonomous" in seen["cmd"]

    # THE WIRING: the code itself must have handed the child THIS run's dir (not the test).
    env = seen["env_extra"] or {}
    child_run_dir = env.get("VIGIL_PROOF_RUN_DIR")
    assert child_run_dir, "the engage spawn must hand the fusion child a run dir (VIGIL_PROOF_RUN_DIR)"
    assert Path(child_run_dir) == seen["rd"]

    # simulate the child's fusion pass producing an INCONCLUSIVE surface INTO the dir the code chose,
    # via the REAL producer (no env, no hand-picked dir).
    ctx = SimpleNamespace(inconclusive_surfaces=[("cloud_live", "no ambient aws credentials")])
    assert EF.persist_inconclusive_surfaces(ctx, run_dir=child_run_dir) is True

    # the operator-facing DOSSIER is NOT clean and NAMES the surface.
    summary = _dossier_summary(Path(child_run_dir), tmp_path, monkeypatch)
    assert summary["coverage_incomplete"] is True
    assert any(s["sensor"] == "cloud_live" for s in summary["inconclusive_surfaces"])

    # the console PROOF LIST is NOT clean either.
    pl = api.proof_list(seen["run_id"])
    assert pl["coverage_incomplete"] is True and pl["clean"] is False


def test_remote_url_engage_spawn_threads_run_dir(isolate, monkeypatch):
    tmp_path = isolate
    monkeypatch.setattr(actions, "_has_verified_authority", lambda slug: True)
    seen = _capturing_spawn(monkeypatch)
    r = actions.launch_assessment({"mode": "url", "target": "https://app.example.com/", "slug": "acme"})
    assert r.get("status") == "running", r
    assert "engage" in seen["cmd"]
    env = seen["env_extra"] or {}
    assert env.get("VIGIL_PROOF_RUN_DIR") == str(seen["rd"])
    assert env.get("VIGIL_ENGAGEMENT") == "acme"


# ---------------------------------------------------------------------------
# retry_run — a retried CLOUD POSTURE (engage --fuse-only) run must NOT drop the artifact
# ---------------------------------------------------------------------------


def test_retried_cloud_posture_run_threads_run_dir(isolate, monkeypatch):
    tmp_path = isolate
    seen = _capturing_spawn(monkeypatch)

    # a finished cloud-posture run: `engage <slug> --fuse-only --spine` (no seed, fusion-capable).
    parent = "20260101-000000-900"
    slug = "cloudco"
    cmd = ["python", "-m", "framework.v2", "engage", slug, "--fuse-only", "--spine"]
    actions.run_dir(parent).mkdir(parents=True, exist_ok=True)     # the per-run dir _write_meta writes into
    actions._write_meta(parent, slug=slug, mode="cloud", cmd=cmd, status="done")

    res = actions.retry_run(parent)
    assert res.get("ok") is True, res
    env = seen["env_extra"] or {}
    child_run_dir = env.get("VIGIL_PROOF_RUN_DIR")
    assert child_run_dir, "a retried cloud POSTURE engage must hand the child a run dir (was inert)"
    assert Path(child_run_dir) == seen["rd"]

    # end-to-end: the retried run's dossier is not clean when the child surfaces an inconclusive.
    ctx = SimpleNamespace(inconclusive_surfaces=[("k8s_live", "no kubeconfig")])
    EF.persist_inconclusive_surfaces(ctx, run_dir=child_run_dir)
    pl = api.proof_list(seen["run_id"])
    assert pl["coverage_incomplete"] is True and pl["clean"] is False


# ---------------------------------------------------------------------------
# part (a): the framework threads the run dir ENV-INDEPENDENTLY into _run_fusion
# ---------------------------------------------------------------------------


def test_run_fusion_persists_via_threaded_run_dir_without_env(isolate, monkeypatch):
    """``engage._run_fusion`` writes the manifest under the run dir THREADED into it, with NO
    ``$VIGIL_PROOF_RUN_DIR`` set — the explicit thread is the authority, the env is only a fallback."""
    from framework.v2 import engage as E
    from framework.v2.worldmodel.graph import WorldModel

    monkeypatch.delenv("VIGIL_PROOF_RUN_DIR", raising=False)
    rd = isolate / "explicit-run"
    rd.mkdir()

    # the fusion pass collects an inconclusive surface onto the ctx (the real collection contract).
    def _fake_fuse(world, slug, ctx):
        ctx.inconclusive_surfaces = [("cloud_live", "no ambient aws credentials")]
        return []

    monkeypatch.setattr(EF, "fuse_sensors", _fake_fuse)
    E._run_fusion(WorldModel(), "acme", seq_base=1, sink=None, run_dir=str(rd))

    doc = json.loads((rd / "_inconclusive.json").read_text(encoding="utf-8"))
    assert doc["inconclusive"][0]["sensor"] == "cloud_live"
    # and the dossier over that dir is not clean.
    summary = _dossier_summary(rd, isolate, monkeypatch)
    assert summary["coverage_incomplete"] is True
