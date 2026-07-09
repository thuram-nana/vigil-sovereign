"""
memory.store — SQLite connection management for MLS.

Single-process use. Connections are per-instance; the operator
typically constructs one Store at the start of an engagement and lets
it live for the duration. The store is responsible for migrations
and for setting the embedder dimension into schema_meta on first use.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Iterable, Iterator

from ..common import logging as v2log
from ..common import paths
from ..common.errors import MemoryStoreError
from . import embed, migrate


_log = v2log.get_logger(__name__)


class Store:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or paths.memory_db()
        paths.secure_dir(self.path.parent)            # owner-only state dir (X2)
        self._conn = sqlite3.connect(
            self.path, detect_types=sqlite3.PARSE_DECLTYPES,
        )
        paths.secure_existing(self.path)              # 0600 the DB (dir 0700 guards WAL sidecars)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        version = migrate.apply(self._conn)
        _log.info("memory.store.opened", path=str(self.path), schema_version=version)

        # Record the current embedder dim so future readers can detect
        # incompatibilities.
        emb = embed.get_embedder()
        existing_dim = migrate.get_meta(self._conn, "embedder_dim")
        existing_name = migrate.get_meta(self._conn, "embedder_name")
        if not existing_dim:
            migrate.set_meta(self._conn, "embedder_dim", str(emb.dim))
            migrate.set_meta(self._conn, "embedder_name", emb.name)
            self._conn.commit()
        elif int(existing_dim) != emb.dim:
            _log.warning(
                "memory.store.embedder_mismatch",
                stored_name=existing_name,
                stored_dim=existing_dim,
                active_name=emb.name,
                active_dim=emb.dim,
                note="similarity queries against old embeddings may be incorrect",
            )

    # context-manager interface
    def __enter__(self) -> Store:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._conn.close()

    @property
    def conn(self) -> sqlite3.Connection:
        return self._conn

    # ---- low-level helpers ----

    def execute(self, sql: str, params: Iterable[object] = ()) -> sqlite3.Cursor:
        return self._conn.execute(sql, tuple(params))

    def executemany(self, sql: str, rows: Iterable[Iterable[object]]) -> sqlite3.Cursor:
        return self._conn.executemany(sql, [tuple(r) for r in rows])

    def fetchone(self, sql: str, params: Iterable[object] = ()) -> sqlite3.Row | None:
        return self.execute(sql, params).fetchone()

    def fetchall(self, sql: str, params: Iterable[object] = ()) -> list[sqlite3.Row]:
        return self.execute(sql, params).fetchall()

    def fetchiter(self, sql: str, params: Iterable[object] = ()) -> Iterator[sqlite3.Row]:
        cur = self.execute(sql, params)
        while True:
            row = cur.fetchone()
            if row is None:
                return
            yield row

    def commit(self) -> None:
        self._conn.commit()

    # ---- engagement convenience ----

    def engagement_id(self, slug: str) -> int:
        row = self.fetchone("SELECT id FROM engagements WHERE slug=?", (slug,))
        if row is None:
            raise MemoryStoreError(f"no engagement with slug {slug!r}")
        return int(row["id"])

    def engagement_summary(self) -> dict[str, int]:
        """Stats for status output."""
        c = self._conn
        return {
            "engagements": c.execute("SELECT COUNT(*) FROM engagements").fetchone()[0],
            "findings":    c.execute("SELECT COUNT(*) FROM findings").fetchone()[0],
            "hypotheses":  c.execute("SELECT COUNT(*) FROM hypotheses").fetchone()[0],
            "payloads":    c.execute("SELECT COUNT(*) FROM payloads").fetchone()[0],
            "dead_ends":   c.execute("SELECT COUNT(*) FROM dead_ends").fetchone()[0],
            "priors":      c.execute("SELECT COUNT(*) FROM archetype_priors").fetchone()[0],
        }


def open_store(path: Path | None = None) -> Store:
    """Convenience constructor."""
    return Store(path)
