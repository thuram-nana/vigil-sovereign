"""
memory.migrate — schema versioning.

Today there is one schema (version 1) sourced from schema.sql. Future
schema bumps add a numbered migration function below; `apply()` runs
every migration whose number is greater than the stored version.

Each migration must be idempotent at the SQL level — operators may
restore from a backup mid-migration and re-run.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Callable

from ..common.errors import SchemaMismatch


_SCHEMA_SQL = Path(__file__).parent / "schema.sql"
_INTEL_SCHEMA_SQL = Path(__file__).parent / "intel_schema.sql"

_CURRENT_VERSION = 2


def _read_version(conn: sqlite3.Connection) -> int:
    cur = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_meta'"
    )
    if cur.fetchone() is None:
        return 0
    cur = conn.execute("SELECT value FROM schema_meta WHERE key='version'")
    row = cur.fetchone()
    return int(row[0]) if row else 0


def _write_version(conn: sqlite3.Connection, version: int) -> None:
    conn.execute(
        "INSERT INTO schema_meta(key, value) VALUES('version', ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (str(version),),
    )


def _migration_1(conn: sqlite3.Connection) -> None:
    """Initial schema."""
    conn.executescript(_SCHEMA_SQL.read_text(encoding="utf-8"))


def _migration_2(conn: sqlite3.Connection) -> None:
    """Intelligence & Reconnaissance durable store: the observation log, resolved
    entities + members, the merge audit trail, and cross-engagement source-yield
    learning. All ``CREATE TABLE IF NOT EXISTS`` — idempotent at the SQL level."""
    conn.executescript(_INTEL_SCHEMA_SQL.read_text(encoding="utf-8"))


_MIGRATIONS: dict[int, Callable[[sqlite3.Connection], None]] = {
    1: _migration_1,
    2: _migration_2,
}


def apply(conn: sqlite3.Connection) -> int:
    """Apply pending migrations. Returns final version."""
    current = _read_version(conn)
    if current > _CURRENT_VERSION:
        raise SchemaMismatch(
            f"DB schema version {current} is newer than this code's "
            f"{_CURRENT_VERSION}; refusing to downgrade."
        )
    for version, fn in sorted(_MIGRATIONS.items()):
        if version > current:
            fn(conn)
            _write_version(conn, version)
            current = version
    conn.commit()
    return current


def set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO schema_meta(key,value) VALUES(?,?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


def get_meta(conn: sqlite3.Connection, key: str, default: str = "") -> str:
    cur = conn.execute("SELECT value FROM schema_meta WHERE key=?", (key,))
    row = cur.fetchone()
    return row[0] if row else default
