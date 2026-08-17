"""Defect 3 regression: `vigil backup --crucible-root` must be HONORED, not silently overridden by
auto-discovery. Before the fix, `_cmd_backup` called `_resolve_crucible_root()` unconditionally and never
read `args.crucible_root`, so an explicit operator-supplied root was dropped and a different (auto-discovered)
crucible tree was backed up. This test drives `_cmd_backup` with a stubbed `create_offense_backup` and asserts
the forwarded `crucible_root` is the explicit one when set, and the discovered one only when the flag is unset.
"""
from __future__ import annotations

import argparse
from pathlib import Path

import vigil_integration.backup as backup
import vigil_integration.cli as cli


def _ns(tmp_path, **kw):
    d = dict(sovereign_only=False, offense_only=True, out=str(tmp_path / "out"),
             base_dir=str(tmp_path / "base"), crucible_root="", passphrase_env="VIGIL_BACKUP_PASSPHRASE",
             prune=False, keep_days=None, keep_last=None)
    d.update(kw)
    return argparse.Namespace(**d)


def test_backup_honors_explicit_crucible_root_over_autodiscovery(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_BACKUP_PASSPHRASE", "pw-for-the-test-123")
    # auto-discovery would return this; an EXPLICIT --crucible-root must WIN over it.
    monkeypatch.setattr(cli, "_resolve_crucible_root", lambda: Path("/auto/discovered"))
    captured: dict = {}

    def fake_create(dest, pw, *, base_dir, crucible_root=None):
        captured["crucible_root"] = crucible_root
        Path(dest).write_bytes(b"fake-offense-backup-bytes")   # so _plane_manifest can sha256 the part
        return {"files": 1, "secrets": 0, "scope": "x", "bytes": 25}
    monkeypatch.setattr(backup, "create_offense_backup", fake_create)

    # explicit flag → forwarded verbatim, NOT the discovered value
    assert cli._cmd_backup(_ns(tmp_path, crucible_root="/explicit/requested")) == 0
    assert captured["crucible_root"] == "/explicit/requested"

    # flag unset → falls back to auto-discovery
    captured.clear()
    assert cli._cmd_backup(_ns(tmp_path, crucible_root="")) == 0
    assert captured["crucible_root"] == "/auto/discovered"
