"""VSCP-own isolation suite (runs in vscp-ci.yml). Mirrors the load-bearing proof in
integration/tests/test_vscp_isolation.py, calling the same package functions."""
from __future__ import annotations

from pathlib import Path

import pytest

from vscp import config as vscp_config
from vscp import findings_boundary as fb
from vscp import isolation as iso

_PKG = Path(__file__).resolve().parents[1] / "vscp"


def test_package_tree_has_no_forbidden_or_offallowlist_imports():
    assert iso.scan_tree_for_import_violations(_PKG) == []


def test_forbidden_roots_are_classified_as_violations():
    for forbidden in iso.FORBIDDEN_IMPORT_ROOTS:
        assert iso.classify_import_root(forbidden) is not None
    assert iso.classify_import_root("os") is None
    assert iso.classify_import_root("vigil_core") is None
    assert iso.classify_import_root("vscp") is None


def test_scanner_flags_a_planted_forbidden_import(tmp_path):
    (tmp_path / "leak.py").write_text("from sigil.spine import store\n", encoding="utf-8")
    found = iso.scan_tree_for_import_violations(tmp_path)
    assert [v.root for v in found] == ["sigil"]


def test_separate_db_and_signing_key(tmp_path, monkeypatch):
    monkeypatch.setenv("VSCP_HOME", str(tmp_path / "home"))
    cfg = vscp_config.VscpConfig.resolve()
    for root in vscp_config.product_data_roots():
        assert not cfg.db_path.is_relative_to(root)
        assert not cfg.signing_key_path.is_relative_to(root)


def test_config_refuses_product_overlap(tmp_path, monkeypatch):
    plane = tmp_path / "product"
    monkeypatch.setenv("VIGIL_BASE_DIR", str(plane))
    with pytest.raises(vscp_config.VscpIsolationError):
        vscp_config.VscpConfig.resolve(data_dir=str(plane / "vscp"))
    # disjoint layout is fine
    assert vscp_config.VscpConfig.resolve(data_dir=str(tmp_path / "ok")).data_dir.exists() is False


def test_reading_a_finding_is_refused():
    with pytest.raises(fb.FindingsAccessDenied):
        fb.read_assessment_finding("F1")
    assert fb.finding_boundary_gate({"finding_ref": "x"}).allow is False
    assert fb.finding_boundary_gate({"scope": "fleet"}).allow is True
