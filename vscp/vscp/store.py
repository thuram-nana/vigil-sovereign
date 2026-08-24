"""VSCP's OWN sqlite store + migration runner (W13-7 / #500).

VSCP keeps a SEPARATE database from the product — its path comes from :mod:`vscp.config`,
which validates it is disjoint from every product data root. The schema is applied from
VSCP's OWN migrations (``vscp/migrations/*.sql``), tracked in a ``schema_migrations``
table, so VSCP owns its data lifecycle end to end and shares no storage with the product.

Stdlib only (``sqlite3``).
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from .config import VscpConfig

__all__ = ["MIGRATIONS_DIR", "VscpStore", "open_store"]

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"


def _migration_files() -> list[Path]:
    return sorted(MIGRATIONS_DIR.glob("*.sql"))


class VscpStore:
    """A thin connection wrapper that applies VSCP migrations on open. Not thread-shared;
    open one per unit of work (or reuse within a single thread)."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self._migrate()

    def _migrate(self) -> None:
        cur = self.conn.cursor()
        cur.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations "
            "(name TEXT PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT (datetime('now')))"
        )
        applied = {r["name"] for r in cur.execute("SELECT name FROM schema_migrations")}
        for mig in _migration_files():
            if mig.name in applied:
                continue
            self.conn.executescript(mig.read_text(encoding="utf-8"))
            cur.execute("INSERT INTO schema_migrations(name) VALUES (?)", (mig.name,))
        self.conn.commit()

    def applied_migrations(self) -> list[str]:
        return [r["name"] for r in self.conn.execute("SELECT name FROM schema_migrations ORDER BY name")]

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "VscpStore":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def open_store(config: VscpConfig) -> VscpStore:
    """Open (and migrate) VSCP's store at the config's validated db path."""
    return VscpStore(config.db_path)
