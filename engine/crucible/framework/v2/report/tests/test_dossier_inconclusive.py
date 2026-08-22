"""
S9c — the dossier CONSUMES the FRAMEWORK-OWNED sensor-inconclusive artifact.

A fusion sensor that returned INCONCLUSIVE (a declared surface it could NOT assess) writes
``<run_dir>/_inconclusive.json`` (``engage_fusion.write_inconclusive_artifact``). The dossier reads it with
STDLIB ONLY (``report.dossier._read_sensor_inconclusive``) and folds it into the SAME "NEVER reported clean"
determination as proof-degradation — but as a DISTINCT INCONCLUSIVE-COVERAGE state that NAMES each
unassessed sensor + its missing prerequisite.

Proven here:
  * a run with an inconclusive fusion sensor CANNOT render clean and NAMES the surface + missing prerequisite;
  * a fully-assessed run (no artifact) still renders the clean banner (byte-identical clean);
  * an absent artifact is not coverage-incomplete; a present-but-malformed artifact FAILS CLOSED (still not
    clean), never crashing and never silently clean;
  * the REAL framework writer's output round-trips through the dossier reader (the contract matches on both
    ends).

The proof-bundle step is stubbed (``vigil_integration`` is not on the offense-only test path); this test is
about the clean/verdict choke point, not bundling.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

from framework.v2 import engage_fusion as EF
from framework.v2.report import dossier as D

_CLEAN_BANNER = "no oracle-confirmed fact and no enumerated"   # the "banner none" text, lower-cased


def _build(rd: Path, tmp_path: Path, monkeypatch, slug: str = "acme"):
    monkeypatch.setattr(D, "_build_proof_bundle",
                        lambda *a, **k: ({}, {"ok": False, "note": "proof bundle stubbed in test"}))
    out = tmp_path / "d.zip"
    res = D.build_dossier(run_dir=str(rd), out_zip=str(out), engagement_slug=slug)
    return res, zipfile.ZipFile(out).read("index.html").decode("utf-8")


def _write_artifact(rd: Path, rows: list[dict]) -> None:
    (rd / "_inconclusive.json").write_text(json.dumps({"inconclusive": rows}), encoding="utf-8")


# ---------------------------------------------------------------------------
# the reader in isolation
# ---------------------------------------------------------------------------


def test_reader_absent_is_not_incomplete(tmp_path: Path) -> None:
    r = D._read_sensor_inconclusive(tmp_path)
    assert r["coverage_incomplete"] is False and r["surfaces"] == []


def test_reader_valid_names_surfaces_sorted(tmp_path: Path) -> None:
    _write_artifact(tmp_path, [
        {"sensor": "k8s_live", "missing_prerequisite": "kubeconfig", "count": 1},
        {"sensor": "cloud_live", "missing_prerequisite": "no ambient aws credentials", "count": 2},
    ])
    r = D._read_sensor_inconclusive(tmp_path)
    assert r["coverage_incomplete"] is True and r["unparsed"] is False
    assert [s["sensor"] for s in r["surfaces"]] == ["cloud_live", "k8s_live"]   # sorted, deterministic
    assert r["surfaces"][0]["missing_prerequisite"] == "no ambient aws credentials"


def test_reader_malformed_present_fails_closed(tmp_path: Path) -> None:
    (tmp_path / "_inconclusive.json").write_text("{ not valid json", encoding="utf-8")
    r = D._read_sensor_inconclusive(tmp_path)
    assert r["coverage_incomplete"] is True and r["unparsed"] is True


def test_reader_empty_file_is_not_incomplete(tmp_path: Path) -> None:
    (tmp_path / "_inconclusive.json").write_text("   ", encoding="utf-8")
    assert D._read_sensor_inconclusive(tmp_path)["coverage_incomplete"] is False


# ---------------------------------------------------------------------------
# the dossier: never clean, names the surface
# ---------------------------------------------------------------------------


def test_dossier_with_inconclusive_is_never_clean_and_names_surface(tmp_path: Path, monkeypatch) -> None:
    rd = tmp_path / "run"
    rd.mkdir()
    _write_artifact(rd, [{"sensor": "cloud_live",
                          "missing_prerequisite": "no ambient aws credentials", "count": 1}])
    res, idx = _build(rd, tmp_path, monkeypatch)
    assert res["ok"] and res["coverage_incomplete"] is True
    assert res["inconclusive_surfaces"][0]["sensor"] == "cloud_live"
    assert "INCONCLUSIVE COVERAGE" in idx
    assert "this run is NOT clean" in idx
    assert "cloud_live" in idx and "no ambient aws credentials" in idx   # the surface + prerequisite named
    assert _CLEAN_BANNER not in idx.lower(), "a coverage-incomplete run must NEVER show the clean banner"


def test_fully_assessed_run_still_renders_clean(tmp_path: Path, monkeypatch) -> None:
    rd = tmp_path / "run"
    rd.mkdir()                                   # NO _inconclusive.json → byte-identical clean path
    res, idx = _build(rd, tmp_path, monkeypatch)
    assert res["coverage_incomplete"] is False and res["inconclusive_surfaces"] == []
    assert "INCONCLUSIVE COVERAGE" not in idx
    assert _CLEAN_BANNER in idx.lower(), "an assessed empty run still shows the clean banner"


def test_malformed_artifact_dossier_fails_safe_not_clean(tmp_path: Path, monkeypatch) -> None:
    rd = tmp_path / "run"
    rd.mkdir()
    (rd / "_inconclusive.json").write_text("{ corrupt", encoding="utf-8")
    res, idx = _build(rd, tmp_path, monkeypatch)
    assert res["coverage_incomplete"] is True                    # fail-closed, never silently clean
    assert "INCONCLUSIVE COVERAGE" in idx and _CLEAN_BANNER not in idx.lower()


def test_roundtrip_real_writer_to_dossier_reader(tmp_path: Path, monkeypatch) -> None:
    rd = tmp_path / "run"
    rd.mkdir()
    # the REAL framework writer produces the artifact; the dossier consumes it -> contract matches both ends
    assert EF.write_inconclusive_artifact(str(rd), [("k8s_live", "cluster credentials")]) is True
    res, idx = _build(rd, tmp_path, monkeypatch)
    assert res["coverage_incomplete"] is True
    assert "k8s_live" in idx and "cluster credentials" in idx
    assert _CLEAN_BANNER not in idx.lower()
