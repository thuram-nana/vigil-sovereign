"""The MERIDIAN database — a real SQLite store of SYNTHETIC data.

The store is genuine SQLite so the planted SQLi is a real, oracle-confirmable weakness (a string-concatenated
query surfaces a real `sqlite3.OperationalError` and a real boolean differential). It holds only fabricated
rows — no real people, no real permits. A connection is opened per request (SQLite serialises writers itself).
"""

from __future__ import annotations

import os
import sqlite3
from typing import TYPE_CHECKING

from .config import Config
from .seed import SCHEMA, seed_rows

if TYPE_CHECKING:
    from .router import Ctx


def connect(config: Config) -> sqlite3.Connection:
    con = sqlite3.connect(config.db_path)
    con.row_factory = sqlite3.Row
    return con


def from_ctx(ctx: Ctx) -> sqlite3.Connection:
    """Open a connection for a request context (uses only its base_dir)."""
    return connect(Config(base_dir=ctx.base_dir))


def ensure(config: Config) -> None:
    """Create + seed the DB if it does not exist yet (called on `target up`)."""
    config.ensure_dirs()
    if os.path.exists(config.db_path):
        return
    reseed(config)


def reseed(config: Config) -> None:
    """Drop and rebuild the synthetic DB from scratch (called by `target seed`)."""
    config.ensure_dirs()
    try:
        os.unlink(config.db_path)
    except OSError:
        pass
    con = connect(config)
    try:
        con.executescript(SCHEMA)
        seed_rows(con)
        con.commit()
    finally:
        con.close()
