"""W5-3 (#447) — every VERSIONED spine artifact REFUSES a schema newer than this build understands.

Refuse-newer used to exist for the signed head alone. This suite pins the generalization: the segment
manifest, the snapshot state, the anti-rollback floor and the encrypted backup each fail CLOSED on a
version above their ``_MAX_*_SCHEMA``, and each still ACCEPTS a same-or-older version (the negative control
proving the gate is not simply refusing everything).

The last test is STRUCTURAL: it reflects over ``sigil.spine`` for every Pydantic model that carries a
``schema_version`` field and asserts each is registered in ``schema_guard.SPINE_VERSIONED_MODELS`` — so a
NEW versioned artifact committed without a refuse-newer gate turns this (required) job red.

FAILS-WITHOUT-THE-CHANGE: on a tree lacking the gate, ``read_manifest`` / ``load_floor`` /
``SnapshotState.from_folded`` / ``restore_backup`` load a v(N+1) artifact silently (no raise), so every
``pytest.raises(SchemaTooNew|BackupError, ...)`` below fails — the failure is observed, not assumed.

Run: PYTHONPATH=apps/sigil:integration <venv>/bin/python -m pytest apps/sigil/tests/test_spine_refuse_newer.py -q
"""
from __future__ import annotations

import importlib
import inspect
import os
import pkgutil
import tempfile
from pathlib import Path

import pytest
from pydantic import BaseModel

from sigil import backup
from sigil.backup import BackupError, _MAX_BACKUP_SCHEMA, restore_backup
from sigil.config import SCOPE
from sigil.reuse import canonical_json, generate_keypair, sign
from sigil.spine import schema_guard
from sigil.spine.floor import Floor, _MAX_FLOOR_SCHEMA, load_floor
from sigil.spine.manifest import (
    Manifest,
    Segment,
    SpineLayout,
    _MAX_MANIFEST_SCHEMA,
    read_manifest,
    write_manifest,
)
from sigil.spine.schema_guard import SchemaTooNew, refuse_newer
from sigil.spine.snapshot import SnapshotState, _MAX_SNAPSHOT_SCHEMA
from vigil_core.sealing import seal


# --------------------------------------------------------------------------------------------------
# the shared helper itself — the crisp negative control that the gate is not a no-op
# --------------------------------------------------------------------------------------------------
def test_refuse_newer_helper_boundary() -> None:
    refuse_newer(5, 5, artifact="x")            # same version: accepted (no raise)
    refuse_newer(4, 5, artifact="x")            # older: accepted
    with pytest.raises(SchemaTooNew) as ei:     # newer by one: refused
        refuse_newer(6, 5, artifact="x")
    assert ei.value.found == 6 and ei.value.max_understood == 5


def test_refuse_newer_uncoercible_version_fails_closed() -> None:
    # a corrupt/hostile version that cannot be int()-coerced is treated as "too new", never silently passed
    with pytest.raises(SchemaTooNew):
        refuse_newer(None, 1, artifact="x")
    with pytest.raises(SchemaTooNew):
        refuse_newer("not-a-number", 1, artifact="x")


# --------------------------------------------------------------------------------------------------
# segment manifest
# --------------------------------------------------------------------------------------------------
def _layout(tmp_path: Path) -> SpineLayout:
    return SpineLayout.for_path(tmp_path / "spine.jsonl")


def _manifest(schema: int) -> Manifest:
    return Manifest(schema_version=schema, scope=SCOPE,
                    segments=[Segment(id=0, file="spine.segments/seg-00000000.jsonl", first_seq=0)])


def test_manifest_refuses_newer(tmp_path: Path) -> None:
    lay = _layout(tmp_path)
    write_manifest(lay, _manifest(_MAX_MANIFEST_SCHEMA + 1))
    with pytest.raises(SchemaTooNew):
        read_manifest(lay)


def test_manifest_accepts_current(tmp_path: Path) -> None:
    lay = _layout(tmp_path)
    write_manifest(lay, _manifest(_MAX_MANIFEST_SCHEMA))
    m = read_manifest(lay)
    assert m is not None and m.schema_version == _MAX_MANIFEST_SCHEMA


# --------------------------------------------------------------------------------------------------
# anti-rollback floor
# --------------------------------------------------------------------------------------------------
def _floor(schema: int) -> Floor:
    return Floor(schema_version=schema, scope=SCOPE, entry_count=1, last_seq=0,
                 base_seq=0, base_count=0, head_sig_hash="deadbeef")


def test_floor_refuses_newer(tmp_path: Path) -> None:
    p = tmp_path / "floor.json"
    p.write_text(_floor(_MAX_FLOOR_SCHEMA + 1).model_dump_json())
    with pytest.raises(SchemaTooNew):
        load_floor(p)


def test_floor_accepts_current(tmp_path: Path) -> None:
    p = tmp_path / "floor.json"
    p.write_text(_floor(_MAX_FLOOR_SCHEMA).model_dump_json())
    fl = load_floor(p)
    assert fl is not None and fl.schema_version == _MAX_FLOOR_SCHEMA


# --------------------------------------------------------------------------------------------------
# snapshot state — the sharpest case (a dropped fold row silently resets an anti-replay high-water)
# --------------------------------------------------------------------------------------------------
def test_snapshot_refuses_newer() -> None:
    with pytest.raises(SchemaTooNew):
        SnapshotState.from_folded({"schema_version": _MAX_SNAPSHOT_SCHEMA + 1})


def test_snapshot_accepts_current_and_empty() -> None:
    assert SnapshotState.from_folded({"schema_version": _MAX_SNAPSHOT_SCHEMA}).schema_version == _MAX_SNAPSHOT_SCHEMA
    # a full round-trip of the empty identity is accepted (the universal Slice-C load path)
    assert SnapshotState.from_folded(SnapshotState.empty().model_dump()).base_seq == 0


def test_snapshot_load_routes_through_the_gate() -> None:
    # SnapshotState.load must refuse a future folded_state, not just from_folded — pin the wiring by
    # driving a fake store whose named snapshot record carries a too-new folded_state.
    from sigil.spine import snapshot as snap_mod

    class _Rec:
        kind = "snapshot"
        payload = {"folded_state": {"schema_version": _MAX_SNAPSHOT_SCHEMA + 1,
                                    "base_seq": 7, "snapshot_seq": 3}}

    class _Store:
        def get(self, seq):  # noqa: ANN001
            return _Rec()

    # bypass the on-disk head verification (separately gated) — pin ONLY that load() refuses a newer snapshot
    import sigil.spine.snapshot as sm
    orig = sm._verified_prune_boundary
    sm._verified_prune_boundary = lambda store: (7, 3)  # noqa: ARG005
    try:
        with pytest.raises(SchemaTooNew):
            SnapshotState.load(_Store())
    finally:
        sm._verified_prune_boundary = orig
    assert snap_mod  # keep the import used


# --------------------------------------------------------------------------------------------------
# encrypted backup (signed manifest carries a "schema" field)
# --------------------------------------------------------------------------------------------------
def _write_backup(dest: Path, passphrase: str, owner, schema: int) -> None:
    manifest = {"schema": schema, "scope": owner.public_key_b64, "file_sha256": {},
                "has_owner_priv": False, "has_dek": False, "warden": []}
    sig = sign(owner.private_key_b64, canonical_json(manifest))
    body = {"manifest": manifest, "manifest_sig": sig, "manifest_pubkey": owner.public_key_b64,
            "files": {}, "owner_priv_b64": None, "spine_dek_b64": None}
    salt = os.urandom(backup._SALT_LEN)
    sealed = seal(backup._derive_key(passphrase, salt), canonical_json(body), context=backup._BODY_CONTEXT)
    dest.write_bytes(backup._MAGIC + salt + sealed)


class _NoVault:
    """restore refuses a too-new backup BEFORE it touches the vault, so a stub suffices."""


def test_backup_refuses_newer(tmp_path: Path) -> None:
    owner = generate_keypair()
    dest = tmp_path / "future.sglbk"
    _write_backup(dest, "pw-correct-horse", owner, _MAX_BACKUP_SCHEMA + 1)
    with pytest.raises(BackupError, match="newer than this build understands"):
        restore_backup(dest, tmp_path / "new", "pw-correct-horse", vault=_NoVault())


def test_backup_accepts_current_schema_at_the_gate(tmp_path: Path) -> None:
    # a current-schema backup PASSES the refuse-newer gate: restore proceeds past it (here to a clean
    # restore of the empty capture) and NEVER raises the schema-too-new message. This proves the gate is
    # not refusing every backup. Any later BackupError must not be the schema one.
    owner = generate_keypair()
    dest = tmp_path / "current.sglbk"
    _write_backup(dest, "pw-correct-horse", owner, _MAX_BACKUP_SCHEMA)
    try:
        restore_backup(dest, tmp_path / "new", "pw-correct-horse", vault=_NoVault())
    except BackupError as e:
        assert "newer than this build understands" not in str(e)


# --------------------------------------------------------------------------------------------------
# STRUCTURAL: a new versioned spine model without a registered refuse-newer gate turns CI red
# --------------------------------------------------------------------------------------------------
def _discover_versioned_spine_models() -> dict[str, type[BaseModel]]:
    import sigil.spine as spine_pkg
    found: dict[str, type[BaseModel]] = {}
    for mod in pkgutil.iter_modules(spine_pkg.__path__):
        if mod.name.startswith("_"):
            continue
        m = importlib.import_module(f"sigil.spine.{mod.name}")
        for _name, obj in inspect.getmembers(m, inspect.isclass):
            if (issubclass(obj, BaseModel) and obj.__module__ == m.__name__
                    and "schema_version" in obj.model_fields):
                found[obj.__name__] = obj
    return found


def test_every_versioned_spine_model_has_a_registered_gate() -> None:
    discovered = _discover_versioned_spine_models()
    registered = set(schema_guard.SPINE_VERSIONED_MODELS)
    missing = set(discovered) - registered
    assert not missing, (
        f"versioned spine model(s) with no registered refuse-newer gate: {sorted(missing)} — add each to "
        f"schema_guard.SPINE_VERSIONED_MODELS, wire refuse_newer() at its load site, and cover it above")
    # the registry may not name a phantom class that no longer exists
    stale = registered - set(discovered)
    assert not stale, f"schema_guard.SPINE_VERSIONED_MODELS names non-existent model(s): {sorted(stale)}"


def test_registered_gates_have_module_constants() -> None:
    # each versioned artifact defines a `_MAX_*_SCHEMA` constant this build understands (the gate ceiling).
    from sigil.spine.checkpoint import _MAX_HEAD_SCHEMA
    for const in (_MAX_HEAD_SCHEMA, _MAX_MANIFEST_SCHEMA, _MAX_SNAPSHOT_SCHEMA, _MAX_FLOOR_SCHEMA,
                  _MAX_BACKUP_SCHEMA):
        assert isinstance(const, int) and const >= 1


if __name__ == "__main__":  # pragma: no cover
    os.environ.setdefault("SIGIL_HOME", tempfile.mkdtemp())
    raise SystemExit(pytest.main([__file__, "-q"]))
