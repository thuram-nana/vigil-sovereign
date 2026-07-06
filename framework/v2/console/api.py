"""
console.api — read-only data providers for the Ops Console.

Every function here is PURE and RESILIENT: it reads an artifact/store on demand and
returns a plain JSON-serializable dict, and it never raises on a missing/fresh tree
(a brand-new checkout has no `.memory/`, `.authority/`, or `targets/*` yet). It
reuses the framework's own read helpers (`common.paths`, `authority.killswitch`,
`memory.store`, `kernel.backends`) — it does not re-implement them, and it imports
nothing from the scan/engage hot path.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..common import paths


def _safe(fn, default=None):
    """Call a zero-arg read and swallow any error into ``default`` — the console
    must render a partial view of a half-initialised tree, never 500 on it."""
    try:
        return fn()
    except Exception:
        return default


# ---------------------------------------------------------------------------
# status / health
# ---------------------------------------------------------------------------


def status_data() -> dict[str, Any]:
    """Environment + backend health — the data behind the `status` CLI, as JSON."""
    from ..kernel import backends as backends_pkg

    def _paths() -> dict[str, str | None]:
        out: dict[str, str | None] = {}
        for label, fn in (
            ("crucible_root", paths.crucible_root),
            ("v2_root", paths.v2_root),
            ("memory_db", paths.memory_db),
            ("dryrun_dir", paths.dryrun_dir),
            ("targets_root", paths.targets_root),
        ):
            p = _safe(fn)
            out[label] = str(p) if p is not None else None
        return out

    backends = _safe(
        lambda: [
            {"name": name, "available": bool(avail), "note": note}
            for name, avail, note in backends_pkg.probe_all()
        ],
        default=[],
    )
    return {"paths": _paths(), "backends": backends}


# ---------------------------------------------------------------------------
# engagements
# ---------------------------------------------------------------------------


def _killswitch_state(slug: str) -> dict[str, Any]:
    from ..authority.killswitch import KillSwitch

    def _read() -> dict[str, Any]:
        ks = KillSwitch(slug)
        tripped = ks.is_tripped()
        return {"tripped": bool(tripped), "reason": ks.reason() if tripped else None}

    # is_tripped fails CLOSED (ambiguous stat -> tripped); mirror that honestly.
    return _safe(_read, default={"tripped": True, "reason": "state unreadable (fail-closed)"})


def _authority_state(slug: str) -> dict[str, Any] | None:
    def _read() -> dict[str, Any] | None:
        p = paths.authority_path(slug)
        if not Path(p).is_file():
            return None
        doc = json.loads(Path(p).read_text(encoding="utf-8"))
        # SignedAuthority wraps an authority payload; surface the operator-relevant bits.
        auth = doc.get("authority", doc)
        return {
            "environment": auth.get("environment"),
            "scope": auth.get("scope", []),
            "not_before": auth.get("not_before"),
            "not_after": auth.get("not_after"),
            "allow_destructive": auth.get("allow_destructive"),
            "max_actions": auth.get("max_actions"),
            "issued_by": auth.get("issued_by"),
        }

    return _safe(_read, default=None)


def _engagement_row(slug: str) -> dict[str, Any]:
    td = _safe(lambda: Path(paths.target_dir(slug)))
    has_charter = _safe(lambda: Path(paths.charter_path(slug)).is_file(), default=False)
    log = _safe(lambda: Path(paths.crucible_v2_log(slug)))
    return {
        "slug": slug,
        "has_charter": bool(has_charter),
        "killswitch": _killswitch_state(slug),
        "authority": _authority_state(slug),
        "log_exists": bool(log and log.is_file()),
        "log_size": _safe(lambda: log.stat().st_size, default=0) if log else 0,
        "evidence_count": _safe(
            lambda: sum(1 for _ in (td / "evidence").iterdir()) if (td / "evidence").is_dir() else 0,
            default=0,
        ),
    }


def list_engagements() -> dict[str, Any]:
    """Every engagement (a slug = a directory under ``targets/``), with its
    safety/charter state. Skips the `_template` scaffold and hidden dirs."""
    def _list() -> list[str]:
        root = Path(paths.targets_root())
        if not root.is_dir():
            return []
        return sorted(
            p.name for p in root.iterdir()
            if p.is_dir() and not p.name.startswith((".", "_"))
        )

    slugs = _safe(_list, default=[])
    return {"engagements": [_engagement_row(s) for s in slugs]}


def engagement_detail(slug: str) -> dict[str, Any]:
    """One engagement's full at-a-glance state (charter presence, safety, logs)."""
    row = _engagement_row(slug)
    row["charter_present"] = row["has_charter"]
    row["memory"] = _safe(_memory_summary, default={})
    return row


def _memory_summary() -> dict[str, int]:
    from ..memory.store import Store

    return Store().engagement_summary()


# ---------------------------------------------------------------------------
# console runs + reports (populated by the launch action)
# ---------------------------------------------------------------------------


def list_runs() -> dict[str, Any]:
    """Console-launched scan runs, newest first, with their meta + finding count."""
    from . import actions

    def _list() -> list[dict[str, Any]]:
        runs_root = actions.console_dir() / "runs"
        if not runs_root.is_dir():
            return []
        out: list[dict[str, Any]] = []
        for d in sorted(runs_root.iterdir(), reverse=True):
            if not d.is_dir():
                continue
            meta = _safe(lambda p=d: json.loads((p / "meta.json").read_text(encoding="utf-8")), default={})
            report = _safe(lambda p=d: json.loads((p / "report.json").read_text(encoding="utf-8")), default=None)
            out.append({
                "run_id": d.name,
                "target": meta.get("target"),
                "status": meta.get("status", "unknown"),
                "started": meta.get("started"),
                "findings": len((report or {}).get("findings", [])) if report else None,
                "has_report": report is not None,
            })
        return out

    return {"runs": _safe(_list, default=[])}


def run_report(run_id: str) -> dict[str, Any]:
    """The saved `build_report` document for a console run (findings + attack_paths +
    summary), or an error marker if it has not finished yet."""
    from . import actions

    rep = actions.run_dir(run_id) / "report.json"
    doc = _safe(lambda: json.loads(rep.read_text(encoding="utf-8")), default=None)
    if doc is None:
        meta = _safe(lambda: json.loads((actions.run_dir(run_id) / "meta.json").read_text(encoding="utf-8")), default={})
        return {"run_id": run_id, "pending": True, "status": meta.get("status", "unknown")}
    doc["run_id"] = run_id
    return doc
