"""W5-4 (#448) — the SOVEREIGN plane's install-manifest startup gate (``~/.sigil``).

Proves the sovereign wiring of the shared marker:

  * ``config.install_manifest_schema_versions()`` reports the REAL per-artifact ``_MAX_*_SCHEMA`` constants
    (so a schema bump is reflected automatically, not a stale hand-copied number);
  * a fresh ``~/.sigil`` gets a manifest with no operator action, and an intact one verifies;
  * NEGATIVE CONTROL: the CLI startup gate (``cli._assert_install_manifest_or_exit``) EXITS 3 on a ``~/.sigil``
    written by a build this one does not understand (a newer tracked schema), for a normal command — and
    WARNS-but-continues for a recovery/diagnostic command, so the operator can still reach the fix.

Run: pytest apps/sigil/tests/test_install_manifest_startup.py -q
"""
from __future__ import annotations

import pytest

from sigil import config
from sigil import cli
from vigil_core.install_manifest import (
    InstallManifestRefused,
    build_manifest,
    manifest_path,
    read_manifest,
    write_manifest,
)


def test_schema_versions_are_the_real_max_constants():
    sv = config.install_manifest_schema_versions()
    from sigil.spine.checkpoint import _MAX_HEAD_SCHEMA
    from sigil.spine.floor import _MAX_FLOOR_SCHEMA
    from sigil.spine.manifest import _MAX_MANIFEST_SCHEMA
    from sigil.spine.models import SCHEMA_VERSION
    from sigil.spine.snapshot import _MAX_SNAPSHOT_SCHEMA
    assert sv["spine_record"] == int(SCHEMA_VERSION)
    assert sv["signed_head"] == int(_MAX_HEAD_SCHEMA)
    assert sv["anti_rollback_floor"] == int(_MAX_FLOOR_SCHEMA)
    assert sv["segment_manifest"] == int(_MAX_MANIFEST_SCHEMA)
    assert sv["snapshot_state"] == int(_MAX_SNAPSHOT_SCHEMA)
    assert all(isinstance(v, int) for v in sv.values())


def test_fresh_home_gets_a_manifest(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SIGIL_HOME", tmp_path)
    m, created = config.ensure_install_manifest()
    assert created is True
    assert manifest_path(tmp_path).is_file()
    # Product version equals the sovereign package version, and the tracked schemas match this build.
    assert m.product_version == config_version()
    assert read_manifest(tmp_path).schema_versions == config.install_manifest_schema_versions()


def test_intact_home_verifies(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SIGIL_HOME", tmp_path)
    config.ensure_install_manifest()
    _, created = config.ensure_install_manifest()
    assert created is False


def test_startup_gate_refuses_a_newer_home_for_a_normal_command(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SIGIL_HOME", tmp_path)
    # A ~/.sigil written by a build with a bumped spine schema this build does not understand.
    bumped = dict(config.install_manifest_schema_versions())
    bumped["spine_record"] += 1
    write_manifest(tmp_path, build_manifest(product_version="9.9.9", schema_versions=bumped,
                                            install_id="future"))
    with pytest.raises(SystemExit) as ei:
        cli._assert_install_manifest_or_exit("mesh")  # a normal (non-recovery) command
    assert ei.value.code == 3


def test_startup_gate_warns_but_allows_a_recovery_command(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(config, "SIGIL_HOME", tmp_path)
    bumped = dict(config.install_manifest_schema_versions())
    bumped["spine_record"] += 1
    write_manifest(tmp_path, build_manifest(product_version="9.9.9", schema_versions=bumped,
                                            install_id="future"))
    # A recovery/diagnostic command must NOT exit — the operator has to be able to reach the fix.
    cli._assert_install_manifest_or_exit("doctor")
    err = capsys.readouterr().err
    assert "WARNING" in err


def test_startup_gate_writes_on_fresh_home_for_any_command(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SIGIL_HOME", tmp_path)
    # Even a recovery command establishes the marker on a fresh install (no operator action).
    cli._assert_install_manifest_or_exit("doctor")
    assert manifest_path(tmp_path).is_file()


def config_version() -> str:
    from sigil import __version__
    return __version__
