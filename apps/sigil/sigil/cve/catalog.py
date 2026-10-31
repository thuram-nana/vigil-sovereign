"""The public CVE catalog store — a standing, browsable SQLite mirror keyed by CVE id.

Offense-free + plane-neutral (pure stdlib ``sqlite3`` + ``json``). One row per CVE, holding a SUPERSET of
the four public feeds (NVD base/CVSS, OSV ranges/aliases, CISA-KEV exploited-in-the-wild, FIRST EPSS
probability) plus a VIGIL-only ``vigil_exploit`` field (set only when a VIGIL oracle has proven a pinned
version exploitable). Nested data is stored as JSON text columns; the scalar, filterable fields
(severity / cvss_base / year / kev / epss) are real indexed columns.

Thread-safety: every call opens its OWN short-lived connection (the public read API is served by a threading
server), so no connection is shared across threads. Writes are small and transactional.
"""
from __future__ import annotations

import json
import re
import sqlite3
import time
from pathlib import Path
from typing import Optional

from ..reuse import assert_no_offense

assert_no_offense()

_CVE_RE = re.compile(r"^CVE-(\d{4})-(\d{4,})$", re.IGNORECASE)
_SEVERITIES = ("none", "low", "medium", "high", "critical")
# the nested fields persisted as JSON text columns
_JSON_COLS = ("cvss_metrics", "cwes", "affected", "refs", "feeds", "aliases", "vigil_exploit")
# list-valued JSON fields that MERGE as a de-duped union across feeds (order-preserving)
_LIST_MERGE = ("cwes", "affected", "refs", "feeds", "aliases")
# scalar fields a later, non-null feed value fills in (first non-empty wins unless overwrite)
_SCALARS = ("published", "last_modified", "title", "description", "severity", "status",
            "cvss_base", "cvss_vector", "cvss_version", "epss_score", "epss_pct",
            "kev", "kev_date", "ransomware")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cve (
  id            TEXT PRIMARY KEY,
  year          INTEGER,
  published     TEXT,
  last_modified TEXT,
  title         TEXT,
  description   TEXT,
  severity      TEXT,
  cvss_base     REAL,
  cvss_vector   TEXT,
  cvss_version  TEXT,
  cvss_metrics  TEXT,
  epss_score    REAL,
  epss_pct      REAL,
  kev           INTEGER DEFAULT 0,
  kev_date      TEXT,
  ransomware    INTEGER DEFAULT 0,
  status        TEXT DEFAULT 'published',
  cwes          TEXT,
  affected      TEXT,
  refs          TEXT,
  feeds         TEXT,
  aliases       TEXT,
  vigil_exploit TEXT,
  ingested_at   REAL
);
CREATE INDEX IF NOT EXISTS ix_cve_year      ON cve(year);
CREATE INDEX IF NOT EXISTS ix_cve_severity  ON cve(severity);
CREATE INDEX IF NOT EXISTS ix_cve_base      ON cve(cvss_base);
CREATE INDEX IF NOT EXISTS ix_cve_kev       ON cve(kev);
CREATE INDEX IF NOT EXISTS ix_cve_published ON cve(published);
"""


def normalize_cve_id(cve_id: str) -> "Optional[str]":
    """Canonical upper-case ``CVE-YYYY-NNNN`` or None (fail-closed on anything that isn't a CVE id — the id
    is a primary key and, on the public API, a path component, so it must be strictly validated)."""
    m = _CVE_RE.match(str(cve_id or "").strip())
    return f"CVE-{m.group(1)}-{m.group(2)}" if m else None


def severity_for(base: "Optional[float]") -> "Optional[str]":
    """The CVSS 3.1 qualitative band for a base score, or None if no score."""
    if base is None:
        return None
    b = float(base)
    if b <= 0:
        return "none"
    if b < 4:
        return "low"
    if b < 7:
        return "medium"
    if b < 9:
        return "high"
    return "critical"


class CveCatalogStore:
    def __init__(self, path: "str | Path") -> None:
        self.path = str(path)
        p = Path(self.path)
        if p.parent and str(p.parent) not in ("", "."):
            p.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.executescript(_SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.path, timeout=30)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        return c

    # -- normalization ------------------------------------------------------------------------------
    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> dict:
        d = dict(row)
        for col in _JSON_COLS:
            raw = d.get(col)
            try:
                d[col] = json.loads(raw) if raw else ([] if col in _LIST_MERGE else None)
            except (TypeError, ValueError):
                d[col] = [] if col in _LIST_MERGE else None
        d["kev"] = bool(d.get("kev"))
        d["ransomware"] = bool(d.get("ransomware"))
        return d

    def _clean(self, rec: dict) -> "Optional[dict]":
        """Validate + shape an inbound record into the column set. Returns None if the id is not a CVE id.
        `severity` is derived from `cvss_base` when absent; `year` from the id."""
        cid = normalize_cve_id(rec.get("id", ""))
        if cid is None:
            return None
        out: dict = {"id": cid, "year": int(cid.split("-")[1])}
        for k in _SCALARS:
            if k in rec and rec[k] is not None:
                out[k] = rec[k]
        if out.get("severity") is None and out.get("cvss_base") is not None:
            out["severity"] = severity_for(out.get("cvss_base"))
        if out.get("severity") is not None and str(out["severity"]).lower() in _SEVERITIES:
            out["severity"] = str(out["severity"]).lower()
        for k in ("kev", "ransomware"):
            if k in out:
                out[k] = 1 if out[k] else 0
        for k in _JSON_COLS:
            if k in rec and rec[k] is not None:
                out[k] = rec[k]
        return out

    # -- writes -------------------------------------------------------------------------------------
    def upsert(self, rec: dict) -> bool:
        """Insert or fully replace one record (feed values overwrite). Returns True if written."""
        clean = self._clean(rec)
        if clean is None:
            return False
        self._write(clean, merge=False)
        return True

    def merge(self, rec: dict) -> bool:
        """Merge one feed's data into any existing row: scalars fill-if-empty (a non-null incoming value wins
        only where the stored one is empty), list JSON fields union de-duped, `feeds` accumulates. This is how
        NVD + OSV + KEV + EPSS for the same CVE combine into one record without clobbering each other."""
        clean = self._clean(rec)
        if clean is None:
            return False
        self._write(clean, merge=True)
        return True

    def _write(self, clean: dict, *, merge: bool) -> None:
        with self._conn() as c:
            existing = None
            if merge:
                r = c.execute("SELECT * FROM cve WHERE id=?", (clean["id"],)).fetchone()
                existing = self._row_to_record(r) if r is not None else None
            final = self._combine(existing, clean) if merge else clean
            final.setdefault("year", int(final["id"].split("-")[1]))
            final["ingested_at"] = time.time()
            cols = ["id", "year", *_SCALARS, *_JSON_COLS, "ingested_at"]
            vals = []
            for col in cols:
                v = final.get(col)
                vals.append(json.dumps(v) if col in _JSON_COLS and v is not None else v)
            placeholders = ",".join("?" for _ in cols)
            c.execute(f"INSERT OR REPLACE INTO cve ({','.join(cols)}) VALUES ({placeholders})", vals)

    @staticmethod
    def _combine(existing: "Optional[dict]", incoming: dict) -> dict:
        if not existing:
            return dict(incoming)
        out = dict(existing)
        for k in _SCALARS:
            if k in incoming and incoming[k] is not None:
                # fill-if-empty for descriptive scalars; always take a present kev/score/severity signal
                cur = out.get(k)
                empty = cur is None or cur == "" or (k in ("cvss_base", "epss_score", "epss_pct") and not cur)
                if empty or k in ("kev", "ransomware", "severity", "cvss_base", "cvss_vector",
                                  "cvss_version", "epss_score", "epss_pct", "last_modified"):
                    out[k] = incoming[k]
        for k in _LIST_MERGE:
            if incoming.get(k):
                merged = list(out.get(k) or [])
                seen = {json.dumps(x, sort_keys=True) for x in merged}
                for x in incoming[k]:
                    key = json.dumps(x, sort_keys=True)
                    if key not in seen:
                        merged.append(x); seen.add(key)
                out[k] = merged
        if incoming.get("cvss_metrics") is not None:
            out["cvss_metrics"] = incoming["cvss_metrics"]
        if incoming.get("vigil_exploit") is not None:
            out["vigil_exploit"] = incoming["vigil_exploit"]
        if out.get("cvss_base") is not None and not out.get("severity"):
            out["severity"] = severity_for(out["cvss_base"])
        return out

    def merge_many(self, recs: "list[dict]") -> int:
        n = 0
        for r in recs:
            if self.merge(r):
                n += 1
        return n

    # -- reads --------------------------------------------------------------------------------------
    def get(self, cve_id: str) -> "Optional[dict]":
        cid = normalize_cve_id(cve_id)
        if cid is None:
            return None
        with self._conn() as c:
            r = c.execute("SELECT * FROM cve WHERE id=?", (cid,)).fetchone()
        return self._row_to_record(r) if r is not None else None

    def query(self, *, page: int = 1, per_page: int = 50, severity: "Optional[str]" = None,
              year: "Optional[int]" = None, kev: "Optional[bool]" = None, q: "Optional[str]" = None,
              order: str = "published_desc") -> dict:
        """A paginated, filtered listing. Returns {items, total, page, per_page, pages}. Fail-closed:
        per_page is clamped to [1,100], page to >=1, severity to the known set, and `q` is matched with a
        parameterized LIKE over id/title/description (never string-interpolated)."""
        per_page = max(1, min(int(per_page or 50), 100))
        page = max(1, int(page or 1))
        where: "list[str]" = []
        args: list = []
        if severity and str(severity).lower() in _SEVERITIES:
            where.append("severity=?"); args.append(str(severity).lower())
        if year is not None:
            try:
                where.append("year=?"); args.append(int(year))
            except (TypeError, ValueError):
                pass
        if kev is not None:
            where.append("kev=?"); args.append(1 if kev else 0)
        if q:
            like = f"%{str(q).strip()}%"
            where.append("(id LIKE ? OR title LIKE ? OR description LIKE ?)"); args += [like, like, like]
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        orders = {
            "published_desc": "published DESC, id DESC", "published_asc": "published ASC, id ASC",
            "cvss_desc": "cvss_base DESC, id DESC", "cvss_asc": "cvss_base ASC, id ASC",
            "epss_desc": "epss_score DESC, id DESC", "id_desc": "id DESC",
        }
        order_sql = orders.get(order, orders["published_desc"])
        with self._conn() as c:
            total = c.execute(f"SELECT COUNT(*) FROM cve{clause}", args).fetchone()[0]
            rows = c.execute(
                f"SELECT * FROM cve{clause} ORDER BY {order_sql} LIMIT ? OFFSET ?",
                [*args, per_page, (page - 1) * per_page]).fetchall()
        return {"items": [self._row_to_record(r) for r in rows], "total": int(total),
                "page": page, "per_page": per_page,
                "pages": max(1, (int(total) + per_page - 1) // per_page)}

    def years(self) -> "list[dict]":
        with self._conn() as c:
            rows = c.execute(
                "SELECT year, COUNT(*) n FROM cve WHERE year IS NOT NULL GROUP BY year ORDER BY year DESC"
            ).fetchall()
        return [{"year": int(r["year"]), "count": int(r["n"])} for r in rows]

    def stats(self) -> dict:
        with self._conn() as c:
            total = c.execute("SELECT COUNT(*) FROM cve").fetchone()[0]
            kev = c.execute("SELECT COUNT(*) FROM cve WHERE kev=1").fetchone()[0]
            by_sev = {r["severity"] or "unknown": int(r["n"]) for r in
                      c.execute("SELECT severity, COUNT(*) n FROM cve GROUP BY severity").fetchall()}
            proven = c.execute("SELECT COUNT(*) FROM cve WHERE vigil_exploit IS NOT NULL").fetchone()[0]
        return {"total": int(total), "kev": int(kev), "by_severity": by_sev, "vigil_proven": int(proven)}

    def count(self) -> int:
        with self._conn() as c:
            return int(c.execute("SELECT COUNT(*) FROM cve").fetchone()[0])
