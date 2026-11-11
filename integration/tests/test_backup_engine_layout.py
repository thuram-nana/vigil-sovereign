"""#70c — the offense backup captures (and restores) every CRUCIBLE unit WHERE THE ENGINE ACTUALLY KEEPS IT.

THE DEFECT THIS PINS. The engine has two roots (``framework.v2.common.paths``): the crucible root (holds
``targets/``) and the v2 root ``<crucible_root>/framework/v2`` (holds ``.blackboard``, ``.console/runs``,
``.memory``, ``.entitlement``, ``.authority``, ``.authority-root``). The backup addressed some units relative to one
root and some relative to the other through ONE ``croot``, so:

  * the DEFAULT ``vigil backup`` (``_resolve_crucible_root()`` → ``…/framework/v2``) looked for
    ``framework/v2/targets`` and ``framework/v2/framework/v2/.entitlement`` — every client engagement, its evidence
    archive, the entitlement trust root, the DestructionAuthority (kill-switches) and the authority root were
    SILENTLY not backed up;
  * with ``$CRUCIBLE_ROOT`` (the engine's own override = the crucible root) the proof db and the runs were missed;
  * neither captured the MLS learning ``.memory`` nor any per-tenant ``tenants/<t>/store.sqlite`` shard.

Every expectation below is computed by the ENGINE's own path functions (not restated here), for both root
spellings, through create → restore → read back where the engine reads.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from test_backup_roundtrip import PW, SLUG, _seed_offense_home  # type: ignore  # noqa: E402

from vigil_integration import backup as ob
from vigil_integration.backup import (
    OffenseBackupError,
    _BODY_CONTEXT,
    _derive_key,
    _read_header,
    create_offense_backup,
    restore_offense_backup,
)

paths = pytest.importorskip("framework.v2.common.paths")

TENANT = "acme"


def _engine(monkeypatch, crucible_root: Path, tenant: "str | None" = None) -> dict:
    """The engine's OWN answer for where each unit lives under ``crucible_root``. ``crucible_root()`` is
    lru-cached, so the cache is cleared around every lookup — else a later call silently answers for the FIRST
    root (and a restore assertion would read the SOURCE tree, proving nothing)."""
    paths._reset_cache()
    monkeypatch.setenv("CRUCIBLE_ROOT", str(crucible_root))
    if tenant:
        monkeypatch.setenv("CRUCIBLE_TENANT", tenant)
    else:
        monkeypatch.delenv("CRUCIBLE_TENANT", raising=False)
    v2 = paths.v2_root()
    out = {"targets": paths.targets_root(), "runs": v2 / ".console" / "runs",
           "blackboard_db": paths.blackboard_dir() / "store.sqlite", "memory_db": paths.memory_db(),
           "entitlement": paths.entitlement_dir(), "authority": paths.authority_dir(),
           "authority_root": paths.authority_root_dir(), "evidence_keys": paths.evidence_keys_dir()}
    assert paths.crucible_root() == crucible_root.resolve(), "the engine resolved a different root"
    monkeypatch.delenv("CRUCIBLE_ROOT")
    monkeypatch.delenv("CRUCIBLE_TENANT", raising=False)
    paths._reset_cache()
    return out


def _db(path: Path, marker: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as c:
        c.execute("CREATE TABLE t (v TEXT)")
        c.execute("INSERT INTO t VALUES (?)", (marker,))


def _db_value(path: Path) -> str:
    with sqlite3.connect(path) as c:
        return c.execute("SELECT v FROM t").fetchone()[0]


def _real_engine_tree(tmp: Path, monkeypatch) -> tuple[Path, dict, dict]:
    croot = tmp / "crucible"
    (croot / "framework" / "v2").mkdir(parents=True)
    (croot / "CLAUDE.md").write_text("sentinel\n")                    # the engine's crucible-root sentinel
    monkeypatch.delenv("CRUCIBLE_EVIDENCE_KEYS_DIR", raising=False)     # the DEFAULT in-tree keystore
    monkeypatch.delenv("CRUCIBLE_ENTITLEMENT_DIR", raising=False)
    monkeypatch.delenv("VIGIL_AUTHORITY_ROOT_DIR", raising=False)
    e, s = _engine(monkeypatch, croot), _engine(monkeypatch, croot, TENANT)
    _db(e["blackboard_db"], "proof"); _db(s["blackboard_db"], "proof-acme")
    _db(e["memory_db"], "learned"); _db(s["memory_db"], "learned-acme")
    (e["targets"] / SLUG / "evidence").mkdir(parents=True)
    (e["targets"] / SLUG / "charter.md").write_text("# charter\n")
    (e["targets"] / SLUG / "evidence" / "a-0001.bin").write_bytes(b"\x00evidence")
    (e["runs"] / "r1").mkdir(parents=True)
    (e["runs"] / "r1" / "report.json").write_text('{"run": "r1"}')
    for k, name in (("entitlement", "entitlement.json"), ("authority", f"{SLUG}.halt"),
                    ("authority_root", "trust-root.json")):
        e[k].mkdir(parents=True)
        (e[k] / name).write_text(json.dumps({"unit": k}))
    e["evidence_keys"].mkdir(parents=True)
    (e["evidence_keys"] / f"{SLUG}.dek").write_bytes(b"NEVER-PACKAGED-DEK")
    return croot, e, s


def _packaged(dest: Path) -> dict:
    salt, sealed = _read_header(dest)
    from vigil_core.sealing import unseal
    return json.loads(unseal(_derive_key(PW, salt), sealed, context=_BODY_CONTEXT))["files"]


_EXPECTED_RELS = {
    "crucible/.blackboard/store.sqlite", f"crucible/.blackboard/tenants/{TENANT}/store.sqlite",
    "crucible/.memory/store.sqlite", f"crucible/.memory/tenants/{TENANT}/store.sqlite",
    f"crucible/targets/{SLUG}/charter.md", f"crucible/targets/{SLUG}/evidence/a-0001.bin",
    "crucible/.console/runs/r1/report.json", "crucible/framework/v2/.entitlement/entitlement.json",
    f"crucible/framework/v2/.authority/{SLUG}.halt", "crucible/framework/v2/.authority-root/trust-root.json",
}


@pytest.mark.parametrize("spelling", ["crucible_root", "v2_root"])
def test_every_engine_unit_is_captured_whichever_root_is_given(tmp_path, monkeypatch, spelling):
    base = tmp_path / "base"
    _seed_offense_home(base)
    croot, _e, _s = _real_engine_tree(tmp_path, monkeypatch)
    root = croot if spelling == "crucible_root" else croot / "framework" / "v2"
    dest = tmp_path / "off.vglbk"
    create_offense_backup(dest, PW, base_dir=base, crucible_root=root)
    rels = set(_packaged(dest))
    assert _EXPECTED_RELS <= rels, sorted(_EXPECTED_RELS - rels)
    assert not any("evidence-keys" in r or r.endswith(".dek") for r in rels)     # W16-8: never a DEK


@pytest.mark.parametrize("dest_spelling", ["crucible_root", "v2_root"])
def test_restore_puts_every_unit_where_the_engine_reads_it(tmp_path, monkeypatch, dest_spelling):
    base = tmp_path / "base"
    _seed_offense_home(base)
    croot, _e, _s = _real_engine_tree(tmp_path, monkeypatch)
    dest = tmp_path / "off.vglbk"
    create_offense_backup(dest, PW, base_dir=base, crucible_root=croot)

    new_croot = tmp_path / "restored"                                   # a FRESH host
    target = new_croot if dest_spelling == "crucible_root" else new_croot / "framework" / "v2"
    out = restore_offense_backup(dest, tmp_path / "nb", PW, crucible_root=target)
    assert out["verified"] is True
    (new_croot / "CLAUDE.md").write_text("sentinel\n")
    e, s = _engine(monkeypatch, new_croot), _engine(monkeypatch, new_croot, TENANT)
    assert _db_value(e["blackboard_db"]) == "proof" and _db_value(s["blackboard_db"]) == "proof-acme"
    assert _db_value(e["memory_db"]) == "learned" and _db_value(s["memory_db"]) == "learned-acme"
    assert (e["targets"] / SLUG / "charter.md").read_text() == "# charter\n"
    assert (e["targets"] / SLUG / "evidence" / "a-0001.bin").read_bytes() == b"\x00evidence"
    assert (e["runs"] / "r1" / "report.json").read_text() == '{"run": "r1"}'
    assert json.loads((e["authority"] / f"{SLUG}.halt").read_text()) == {"unit": "authority"}   # kill-switch back
    assert (e["entitlement"] / "entitlement.json").is_file() and (e["authority_root"] / "trust-root.json").is_file()
    assert not e["evidence_keys"].exists()                               # the DEK did not travel
    assert not (new_croot / "framework" / "v2" / "framework").exists()   # nothing written to the phantom path
    assert not (new_croot / "framework" / "v2" / "targets").exists()


def test_force_gate_sees_units_where_the_engine_keeps_them(tmp_path, monkeypatch):
    base = tmp_path / "base"
    _seed_offense_home(base)
    croot, _e, _s = _real_engine_tree(tmp_path, monkeypatch)
    dest = tmp_path / "off.vglbk"
    create_offense_backup(dest, PW, base_dir=base, crucible_root=croot)
    for root in (croot, croot / "framework" / "v2"):
        with pytest.raises(OffenseBackupError, match="refusing to overwrite live CRUCIBLE proof state") as ei:
            restore_offense_backup(dest, tmp_path / f"nb-{root.name}", PW, crucible_root=root)
        for unit in ("targets", f".memory/tenants/{TENANT}/store.sqlite", "framework/v2/.authority"):
            assert unit in str(ei.value)


def test_the_default_cli_root_maps_onto_the_engines_real_tree(monkeypatch):
    """The exact regression: with no flag and no $CRUCIBLE_ROOT, ``vigil backup`` resolves ``…/framework/v2``;
    every unit must still land on the repo's REAL engine paths (before #70c, targets + trust state did not)."""
    from vigil_integration import cli
    paths._reset_cache()
    monkeypatch.delenv("CRUCIBLE_ROOT", raising=False)
    monkeypatch.delenv("CRUCIBLE_TENANT", raising=False)
    monkeypatch.delenv("CRUCIBLE_ENTITLEMENT_DIR", raising=False)
    monkeypatch.delenv("VIGIL_AUTHORITY_ROOT_DIR", raising=False)
    monkeypatch.delenv("CRUCIBLE_EVIDENCE_KEYS_DIR", raising=False)
    layout = ob._CrucibleLayout(cli._resolve_crucible_root())
    assert layout.disk("targets") == paths.targets_root()
    assert layout.disk(".blackboard/store.sqlite") == paths.blackboard_dir() / "store.sqlite"
    assert layout.disk(".memory/store.sqlite") == paths.memory_db()
    assert layout.disk(".console/runs") == paths.v2_root() / ".console" / "runs"
    assert layout.disk("framework/v2/.entitlement") == paths.entitlement_dir()
    assert layout.disk("framework/v2/.authority") == paths.authority_dir()
    assert layout.disk("framework/v2/.authority-root") == paths.authority_root_dir()
    assert ob._evidence_keys_dir(cli._resolve_crucible_root()) == paths.evidence_keys_dir()


@pytest.mark.parametrize("bad", ["../escape", "a/b", "", ".hidden", "x" * 200])
def test_an_unsafe_shard_name_is_never_a_db_unit(bad):
    assert not ob._is_sqlite_db_rel(f"crucible/.memory/tenants/{bad}/store.sqlite")
    assert not ob._is_sqlite_db_rel(f"crucible/.blackboard/tenants/{bad}/store.sqlite")


@pytest.mark.parametrize("bad", [".hidden", "x" * 200, "-dash"])
def test_an_unsafe_shard_dir_on_disk_is_not_captured(tmp_path, bad):
    v2 = tmp_path / "c" / "framework" / "v2"
    _db(v2 / ".memory" / "tenants" / bad / "store.sqlite", "x")
    _db(v2 / ".memory" / "tenants" / "ok" / "store.sqlite", "y")
    assert ob._sqlite_db_unit_rels(v2) == [".memory/tenants/ok/store.sqlite"]


def test_a_symlinked_shard_db_is_not_captured(tmp_path):
    v2 = tmp_path / "c" / "framework" / "v2"
    _db(tmp_path / "elsewhere.sqlite", "outside")
    (v2 / ".blackboard" / "tenants" / "evil").mkdir(parents=True)
    (v2 / ".blackboard" / "tenants" / "evil" / "store.sqlite").symlink_to(tmp_path / "elsewhere.sqlite")
    assert ob._sqlite_db_unit_rels(v2) == []


@pytest.mark.parametrize("rel", ["crucible/.blackboard/store.sqlite", "crucible/.memory/store.sqlite",
                                 f"crucible/.blackboard/tenants/{TENANT}/store.sqlite",
                                 f"crucible/.memory/tenants/{TENANT}/store.sqlite"])
def test_every_db_unit_is_snapshotted_consistently_not_raw_copied(rel):
    assert ob._is_sqlite_db_rel(rel)                    # routed through the sqlite ONLINE BACKUP API
    assert not ob._is_sqlite_db_rel(rel.replace("store.sqlite", "other.sqlite"))


def test_a_forced_restore_drops_the_replaced_shard_dbs_stale_sidecars(tmp_path, monkeypatch):
    base = tmp_path / "base"
    _seed_offense_home(base)
    croot, _e, s = _real_engine_tree(tmp_path, monkeypatch)
    dest = tmp_path / "off.vglbk"
    create_offense_backup(dest, PW, base_dir=base, crucible_root=croot)
    wal = s["memory_db"].parent / "store.sqlite-wal"
    wal.write_bytes(b"stale wal of the db being replaced")   # would corrupt the NEW db on its next open
    restore_offense_backup(dest, tmp_path / "nb", PW, crucible_root=croot, force=True)
    assert not wal.exists()
    assert _db_value(s["memory_db"]) == "learned-acme"


def test_a_shard_db_commit_still_in_the_wal_survives_backup_and_restore(tmp_path, monkeypatch):
    """A live engine keeps the MLS memory db in WAL mode: a COMMITTED row can sit in ``store.sqlite-wal`` until a
    checkpoint. A raw byte copy of ``store.sqlite`` alone would silently drop it; the sqlite ONLINE BACKUP API
    (``_read_sqlite_consistent``) carries it — so every db unit, shards included, must go through it."""
    base = tmp_path / "base"
    _seed_offense_home(base)
    croot, _e, s = _real_engine_tree(tmp_path, monkeypatch)
    live = sqlite3.connect(s["memory_db"])
    try:
        live.execute("PRAGMA journal_mode=WAL")
        live.execute("PRAGMA wal_autocheckpoint=0")
        live.execute("INSERT INTO t VALUES ('committed-in-wal')")
        live.commit()                                          # committed, NOT checkpointed into store.sqlite
        assert (s["memory_db"].parent / "store.sqlite-wal").stat().st_size > 0
        dest = tmp_path / "off.vglbk"
        create_offense_backup(dest, PW, base_dir=base, crucible_root=croot)
    finally:
        live.close()
    new_croot = tmp_path / "restored"
    restore_offense_backup(dest, tmp_path / "nb", PW, crucible_root=new_croot)
    (new_croot / "CLAUDE.md").write_text("sentinel\n")
    restored = _engine(monkeypatch, new_croot, TENANT)["memory_db"]
    with sqlite3.connect(restored) as c:
        rows = {r[0] for r in c.execute("SELECT v FROM t")}
    assert rows == {"learned-acme", "committed-in-wal"}
