"""W7-3 — the recovery drill covers more than a freshly-minted backup (offense plane).

The shipped drill round-tripped ONLY a just-created backup. This proves the two paths a real disaster
recovery actually walks:

  * a backup that has been through RETENTION and PRUNING still restores — create three timestamped backups,
    prune the oldest away (real ``tools.backup.retention.prune``), and restore a SURVIVOR (the newest, and an
    older one via the deliberate ``--allow-rollback`` path), re-verifying each;
  * a backup fetched from the OFF-HOST push destination restores — ``vigil backup --push`` replicates the
    encrypted parts + signed manifest, and the drill restores FROM that pushed copy, not the local one;

and the negative control the acceptance criteria demand:

  * a CORRUPTED retained backup is DETECTED, not restored silently broken — a byte-flip of the retained
    encrypted part makes ``vigil restore`` exit non-zero and leaves the destination untouched (fail-closed),
    at BOTH the orchestrator-manifest sha layer and the inner sealed-body layer.

"Fails without this change": this file is the drill coverage; it exercises the retained/pushed/corruption
paths that were never drilled. The sovereign plane's drill + chain re-verification is the dual suite
apps/tests/test_backup_recovery_drill_sovereign.py (it runs in the sigil-governor CI job).

Needs framework (restore re-verifies the spine/evidence) → runs in the offense leg:
    PYTHONPATH=integration:engine/crucible:gateway:packages/core/vigil_core:. .venv-offense/bin/python \
        -m pytest integration/tests/test_backup_dr_drill_coverage.py -q
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

pytest.importorskip("framework.v2.evidence.cli")

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tools.backup import retention  # noqa: E402
from tools.backup.retention import prune  # noqa: E402

from vigil_integration.backup import (  # noqa: E402
    OffenseBackupError,
    create_offense_backup,
    restore_offense_backup,
)
from vigil_integration.cli import main  # noqa: E402
from test_backup_roundtrip import PW, SLUG, _seed_offense_home  # type: ignore  # noqa: E402


def _timestamps(monkeypatch, names: list[str]) -> None:
    """Force `vigil backup` to write the given timestamped subdir names in order (so the test controls which
    backup is oldest/newest and can prune deterministically)."""
    it = iter(names)
    monkeypatch.setattr(retention, "timestamp_name", lambda *a, **k: next(it))


def _backup(out_root: Path, base: Path, croot: Path, *push: str) -> int:
    argv = ["backup", "--offense-only", "--out", str(out_root), "--base-dir", str(base),
            "--crucible-root", str(croot)]
    argv += list(push)
    return main(argv)


def _restore(src_dir: Path, new_base: Path, *extra: str) -> int:
    return main(["restore", str(src_dir), "--offense-only", "--base-dir", str(new_base), *extra])


# --------------------------------------------------------------------------------------------------
# A backup that survived RETENTION + PRUNING still restores.
# --------------------------------------------------------------------------------------------------
def test_drill_restores_a_retained_pruned_backup(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_BACKUP_PASSPHRASE", PW)
    base = tmp_path / "src-base"
    _seed_offense_home(base)
    croot = tmp_path / "empty-crucible"
    croot.mkdir()
    out_root = tmp_path / "vigil-backups"

    # three real backups, oldest → newest (distinct timestamps).
    _timestamps(monkeypatch, ["20260101-000000", "20260102-000000", "20260103-000000"])
    for _ in range(3):
        assert _backup(out_root, base, croot) == 0

    # PRUNE: keep the last 2 → the oldest is really deleted; two survive "through" the prune.
    deleted = prune(out_root, keep_last=2)
    assert [p.name for p in deleted] == ["20260101-000000"]
    survivors = sorted(p.name for p in out_root.iterdir() if p.is_dir())
    assert survivors == ["20260102-000000", "20260103-000000"]

    # restore the NEWEST survivor → verified round-trip (no rollback flag needed).
    newest = out_root / "20260103-000000"
    assert _restore(newest, tmp_path / "restored-newest") == 0
    assert (tmp_path / "restored-newest" / f"{SLUG}.spine").is_file()

    # restore an OLDER survivor → this IS a rollback (older backup_seq than the anchor's latest), so it needs
    # the deliberate --allow-rollback; with it, the retained older backup restores + re-verifies too.
    older = out_root / "20260102-000000"
    assert _restore(older, tmp_path / "restored-older") != 0                      # refused without the flag
    # fail-closed: nothing of the backup was restored (the startup gate may stamp install-manifest.json, but
    # no spine/keys land) — the rollback refusal happened before any state was swapped in.
    assert not (tmp_path / "restored-older" / f"{SLUG}.spine").is_file()
    assert _restore(older, tmp_path / "restored-older2", "--allow-rollback") == 0
    assert (tmp_path / "restored-older2" / f"{SLUG}.spine").is_file()


# --------------------------------------------------------------------------------------------------
# A backup fetched from the OFF-HOST push destination restores.
# --------------------------------------------------------------------------------------------------
def test_drill_restores_the_pushed_off_host_copy(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_BACKUP_PASSPHRASE", PW)
    base = tmp_path / "src-base"
    _seed_offense_home(base)
    croot = tmp_path / "empty-crucible"
    croot.mkdir()
    out_root = tmp_path / "vigil-backups"
    remote = tmp_path / "off-host"

    _timestamps(monkeypatch, ["20260104-000000"])
    assert _backup(out_root, base, croot, "--push", str(remote)) == 0

    pushed = remote / "20260104-000000"
    assert (pushed / "MANIFEST.json").is_file() and (pushed / "MANIFEST.sig.json").is_file()
    assert (pushed / "offense.vglbk").is_file()

    # restore FROM the off-host copy into fresh dirs → verified round-trip (a real, restorable second copy).
    assert _restore(pushed, tmp_path / "restored-from-push") == 0
    assert (tmp_path / "restored-from-push" / f"{SLUG}.spine").is_file()


# --------------------------------------------------------------------------------------------------
# NEGATIVE CONTROL — a corrupted retained backup is DETECTED, not restored silently broken.
# --------------------------------------------------------------------------------------------------
def test_negative_control_corrupted_retained_backup_is_detected_by_the_cli(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_BACKUP_PASSPHRASE", PW)
    base = tmp_path / "src-base"
    _seed_offense_home(base)
    croot = tmp_path / "empty-crucible"
    croot.mkdir()
    out_root = tmp_path / "vigil-backups"

    _timestamps(monkeypatch, ["20260105-000000"])
    assert _backup(out_root, base, croot) == 0
    subdir = out_root / "20260105-000000"

    # corrupt the retained encrypted part (a same-length byte flip in the sealed body).
    part = subdir / "offense.vglbk"
    b = bytearray(part.read_bytes())
    b[-1] ^= 0xFF
    part.write_bytes(bytes(b))

    # the drill's `vigil restore` must exit non-zero and restore NOTHING (fail-closed) — the startup gate may
    # stamp install-manifest.json into the base dir, but no restored spine/keys land.
    new_base = tmp_path / "restored-corrupt"
    assert _restore(subdir, new_base) != 0
    assert not (new_base / f"{SLUG}.spine").is_file()
    assert not (new_base / "offense-spine.key").is_file()


def test_negative_control_inner_body_tamper_raises_and_leaves_destination_untouched(tmp_path, monkeypatch):
    # The inner sealed-body layer: call restore_offense_backup directly on a byte-flipped part → it RAISES and
    # the destination is untouched (the manifest-sha layer above would also catch it; this proves the AEAD/
    # manifest-signature layer beneath it has teeth on its own).
    monkeypatch.setenv("VIGIL_BACKUP_PASSPHRASE", PW)
    base = tmp_path / "src-base"
    _seed_offense_home(base)
    croot = tmp_path / "empty-crucible"
    croot.mkdir()
    dest = tmp_path / "bk" / "offense.vglbk"
    create_offense_backup(dest, PW, base_dir=base, crucible_root=str(croot))

    b = bytearray(dest.read_bytes())
    b[len(b) // 2] ^= 0x01                                   # flip a byte inside the sealed ciphertext
    dest.write_bytes(bytes(b))

    new_base = tmp_path / "restored-inner"
    with pytest.raises(OffenseBackupError):
        restore_offense_backup(dest, new_base, PW, crucible_root=str(croot))
    assert not new_base.exists() or not any(new_base.iterdir())
