"""
S9c — the fusion INCONCLUSIVE-COVERAGE consumer (producer side).

A fusion sensor that returns INCONCLUSIVE (a declared surface it could NOT assess — a missing cloud/K8s
prerequisite) must not vanish into a silent CLEAN. ``fuse_sensors`` now COLLECTS each such surface onto the
backward-compatible ``ctx.inconclusive_surfaces`` side-channel, and the run level persists them to a
FRAMEWORK-OWNED, stdlib-readable run-dir artifact ``<run_dir>/_inconclusive.json`` the dossier consumes.

Proven here:
  * ``fuse_sensors`` exposes ``(sensor, missing_prerequisite)`` for every inconclusive task, and NOTHING for
    an assessed run (the negative control — no side-channel content, so no artifact, so byte-identical).
  * the writer's schema is deterministic (sorted, deduped, counted) and is written ONLY on a genuine
    inconclusive.
  * persist resolves the run dir from an explicit arg / ``ctx.run_dir`` / ``$VIGIL_PROOF_RUN_DIR`` and never
    raises and never writes when there is nothing to write (no surface, or no run dir).

``run_sensor`` and ``_reverify`` are faked so the pass is offline and needs no live SDK / charter — the
choke point under test is ``fuse_sensors``' COLLECTION + the run-level PERSIST, not the (already-tested)
gate or the oracle re-verification.

FAIL-BEFORE / PASS-AFTER: revert the collection hunk in ``fuse_sensors`` and ``ctx.inconclusive_surfaces``
is never set (the assertions raise AttributeError); revert the writer and the artifact is never produced.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from framework.v2 import engage_fusion as EF
from framework.v2.agents.tools import ToolResult
from framework.v2.sensors.base import SensorResult, inconclusive_result
from framework.v2.worldmodel.graph import WorldModel


def _inconclusive(sensor: str, missing: str) -> SensorResult:
    return SensorResult(result=inconclusive_result(sensor, missing=missing, detail="detail"))


def _assessed() -> SensorResult:
    return SensorResult(result=ToolResult(ok=True, output={"format": "native"}), observations=[])


@pytest.fixture
def fake_pipeline(monkeypatch):
    """Install a fake ``run_sensor`` returning a chosen SensorResult per sensor name, and neutralise the
    oracle re-verify (not under test here) so the assessed control is a clean no-op."""
    def _install(mapping: dict) -> None:
        def _fake_run_sensor(registry, sensor, args, tool_ctx, **kw):
            return mapping[sensor]
        monkeypatch.setattr(EF, "run_sensor", _fake_run_sensor)
        monkeypatch.setattr(EF, "_reverify", lambda *a, **k: 0)
    return _install


# ---------------------------------------------------------------------------
# fuse_sensors: collection onto the ctx side-channel
# ---------------------------------------------------------------------------


def test_fuse_collects_each_inconclusive_surface(fake_pipeline) -> None:
    fake_pipeline({
        "cloud_live": _inconclusive("cloud_live", "no ambient aws credentials"),
        "k8s_live": _inconclusive("k8s_live", "targets/<slug>/collector-hosts.txt"),
    })
    ctx = SimpleNamespace(base_seq=1, sink=None, fusion_tasks=[
        {"sensor": "cloud_live", "args": {}}, {"sensor": "k8s_live", "args": {}}])
    EF.fuse_sensors(WorldModel(), "alpha", ctx)
    assert ctx.inconclusive_surfaces == [
        ("cloud_live", "no ambient aws credentials"),
        ("k8s_live", "targets/<slug>/collector-hosts.txt"),
    ]


def test_assessed_run_collects_nothing_negative_control(fake_pipeline) -> None:
    """The gate is not a no-op that stamps every run inconclusive: an ASSESSED sensor sets an EMPTY
    side-channel, so nothing is persisted and the run renders byte-identically."""
    fake_pipeline({"cloud_import": _assessed()})
    ctx = SimpleNamespace(base_seq=1, sink=None, fusion_tasks=[{"sensor": "cloud_import", "args": {}}])
    EF.fuse_sensors(WorldModel(), "alpha", ctx)
    assert ctx.inconclusive_surfaces == []


def test_empty_plan_sets_no_side_channel(fake_pipeline) -> None:
    # an empty plan short-circuits before the loop and never touches the ctx (backward-compatible).
    fake_pipeline({})
    ctx = SimpleNamespace(base_seq=1, sink=None)
    assert EF.fuse_sensors(WorldModel(), "alpha", ctx) == []
    assert not hasattr(ctx, "inconclusive_surfaces")


# ---------------------------------------------------------------------------
# the writer: deterministic schema, written ONLY on a genuine inconclusive
# ---------------------------------------------------------------------------


def test_writer_schema_is_sorted_deduped_and_counted(tmp_path: Path) -> None:
    rd = tmp_path / "run"
    surfaces = [("cloud_import", "creds"), ("cloud_import", "creds"), ("k8s_live", "kubeconfig")]
    assert EF.write_inconclusive_artifact(str(rd), surfaces) is True
    doc = json.loads((rd / "_inconclusive.json").read_text(encoding="utf-8"))
    assert doc == {"inconclusive": [
        {"sensor": "cloud_import", "missing_prerequisite": "creds", "count": 2},
        {"sensor": "k8s_live", "missing_prerequisite": "kubeconfig", "count": 1},
    ]}


def test_writer_is_deterministic_regardless_of_input_order(tmp_path: Path) -> None:
    rd = tmp_path / "run"
    surfaces = [("cloud_import", "creds"), ("cloud_import", "creds"), ("k8s_live", "kubeconfig")]
    EF.write_inconclusive_artifact(str(rd), surfaces)
    first = (rd / "_inconclusive.json").read_bytes()
    EF.write_inconclusive_artifact(str(rd), list(reversed(surfaces)))   # different order, same bytes
    assert (rd / "_inconclusive.json").read_bytes() == first


def test_writer_writes_nothing_when_no_surface(tmp_path: Path) -> None:
    rd = tmp_path / "run"
    assert EF.write_inconclusive_artifact(str(rd), []) is False
    assert not (rd / "_inconclusive.json").exists()


# ---------------------------------------------------------------------------
# persist: run-dir resolution + fail-safe
# ---------------------------------------------------------------------------


def test_persist_resolves_run_dir_from_env(tmp_path: Path, monkeypatch) -> None:
    rd = tmp_path / "run"
    rd.mkdir()
    monkeypatch.setenv("VIGIL_PROOF_RUN_DIR", str(rd))
    ctx = SimpleNamespace(inconclusive_surfaces=[("cloud_live", "boto3")])
    assert EF.persist_inconclusive_surfaces(ctx) is True
    assert (rd / "_inconclusive.json").is_file()


def test_persist_prefers_explicit_run_dir_and_ctx_hook(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("VIGIL_PROOF_RUN_DIR", raising=False)
    rd = tmp_path / "explicit"
    rd.mkdir()
    ctx = SimpleNamespace(inconclusive_surfaces=[("k8s_live", "kubeconfig")], run_dir=str(tmp_path / "hook"))
    # explicit arg wins over ctx.run_dir
    assert EF.persist_inconclusive_surfaces(ctx, run_dir=str(rd)) is True
    assert (rd / "_inconclusive.json").is_file()
    assert not (tmp_path / "hook" / "_inconclusive.json").exists()


def test_persist_noop_when_no_surface_or_no_rundir(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("VIGIL_PROOF_RUN_DIR", raising=False)
    # no resolvable run dir → no write, no raise
    assert EF.persist_inconclusive_surfaces(SimpleNamespace(inconclusive_surfaces=[("a", "b")])) is False
    # no surfaces → no write even with a run dir
    rd = tmp_path / "run"
    rd.mkdir()
    assert EF.persist_inconclusive_surfaces(SimpleNamespace(inconclusive_surfaces=[]), run_dir=str(rd)) is False
    assert not (rd / "_inconclusive.json").exists()


def test_persist_is_total_on_a_ctx_without_the_side_channel() -> None:
    # a caller that never ran fusion (no side-channel) is a clean no-op, never a crash.
    assert EF.persist_inconclusive_surfaces(SimpleNamespace()) is False


# ---------------------------------------------------------------------------
# end-to-end: fuse then persist (exactly what _run_fusion / the autonomous seam do)
# ---------------------------------------------------------------------------


def test_fuse_then_persist_writes_the_named_surface(tmp_path: Path, monkeypatch, fake_pipeline) -> None:
    rd = tmp_path / "run"
    rd.mkdir()
    monkeypatch.setenv("VIGIL_PROOF_RUN_DIR", str(rd))
    fake_pipeline({"cloud_live": _inconclusive("cloud_live", "no ambient aws credentials")})
    ctx = SimpleNamespace(base_seq=1, sink=None, fusion_tasks=[{"sensor": "cloud_live", "args": {}}])
    EF.fuse_sensors(WorldModel(), "alpha", ctx)
    EF.persist_inconclusive_surfaces(ctx)                       # the run-level persist
    doc = json.loads((rd / "_inconclusive.json").read_text(encoding="utf-8"))
    assert doc["inconclusive"] == [
        {"sensor": "cloud_live", "missing_prerequisite": "no ambient aws credentials", "count": 1}]
