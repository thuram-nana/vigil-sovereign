"""W5-4 (#448) — the OFFENSE plane's install-manifest startup gate (``.vigil-live``).

Proves the offense wiring of the shared marker, boundary-clean (imports only ``vigil_core`` +
``vigil_integration.install_gate``, never ``framework``):

  * a fresh ``.vigil-live`` gets a manifest with no operator action (the gate returns None -> the command
    proceeds);
  * NEGATIVE CONTROL: the gate returns exit code 2 on a ``.vigil-live`` written by a build this one does not
    understand (a newer layout schema), for a normal command — and returns None (WARN + continue) for a
    recovery/diagnostic command;
  * the offense product version resolves to a non-empty release string.

Run: PYTHONPATH=integration pytest integration/tests/test_install_manifest_offense.py -q
"""
from __future__ import annotations

from vigil_core.install_manifest import build_manifest, manifest_path, write_manifest
from vigil_integration.install_gate import (
    VIGIL_LIVE_LAYOUT_SCHEMA,
    ensure_operable_or_exit,
    offense_product_version,
    offense_schema_versions,
)


def test_fresh_base_dir_gets_a_manifest_and_command_proceeds(tmp_path):
    rc = ensure_operable_or_exit(str(tmp_path), "engage")
    assert rc is None  # None -> the command proceeds
    assert manifest_path(tmp_path).is_file()


def test_intact_base_dir_proceeds(tmp_path):
    ensure_operable_or_exit(str(tmp_path), "engage")
    assert ensure_operable_or_exit(str(tmp_path), "engage") is None


def test_newer_layout_is_refused_for_a_normal_command(tmp_path):
    bumped = {"vigil_live_layout": VIGIL_LIVE_LAYOUT_SCHEMA + 1}
    write_manifest(tmp_path, build_manifest(product_version="9.9.9", schema_versions=bumped, install_id="f"))
    rc = ensure_operable_or_exit(str(tmp_path), "engage")
    assert rc == 2  # fail-closed exit code for a non-recovery command


def test_newer_layout_warns_but_allows_a_recovery_command(tmp_path, capsys):
    bumped = {"vigil_live_layout": VIGIL_LIVE_LAYOUT_SCHEMA + 1}
    write_manifest(tmp_path, build_manifest(product_version="9.9.9", schema_versions=bumped, install_id="f"))
    rc = ensure_operable_or_exit(str(tmp_path), "doctor")
    assert rc is None
    assert "WARNING" in capsys.readouterr().err


def test_corrupt_manifest_is_refused_for_a_normal_command(tmp_path):
    manifest_path(tmp_path).write_text("{not json", encoding="utf-8")
    assert ensure_operable_or_exit(str(tmp_path), "engage") == 2


def test_offense_product_version_is_a_nonempty_string():
    v = offense_product_version()
    assert isinstance(v, str) and v.strip()


def test_offense_schema_versions_are_ints():
    sv = offense_schema_versions()
    assert sv and all(isinstance(x, int) for x in sv.values())
