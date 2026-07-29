"""telemetry — a live assurance/metrics collector over the signed event spine (VIGIL G2).

Materializes a continuously-updated metrics snapshot from the append-only blackboard (the signed spine): per
engagement, how many oracle-confirmed FACTs vs LEADs, refusals, tool calls, agent messages, and a by-kind
histogram — plus a running total. It is a PURE, ONE-WAY projection of the spine (nothing is read back into
it; no tier/grant is ever derived from it), so it can only reflect what the oracle+gate already recorded — it
never mints a fact and never widens anything.

Two entry points:
  * :func:`collect_snapshot` — the pure projection (blackboard rows → metrics dict). Deterministic + total.
  * :func:`run_collector` / :func:`main` — the ``vigil up --with-telemetry`` sidecar: open the blackboard,
    write a snapshot to ``--out`` every ``--interval`` seconds (or ``--once``), fail-soft (an unreadable
    spine writes an honest empty snapshot, never crashes the sidecar).

Import-clean: stdlib only; the blackboard (framework) is lazy-imported inside the functions that need it, so
importing this module in the sovereign env stays clean (the two-env boundary holds).
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Optional

_SCHEMA = 1
# Which blackboard kinds roll up into the headline counters (the rest still land in the by-kind histogram).
_TOOL_KINDS = ("action", "tool_call")


def _blank_metrics() -> dict:
    return {"events": 0, "facts": 0, "leads": 0, "refusals": 0, "tool_calls": 0, "messages": 0,
            "findings": 0, "by_kind": {}, "last_event_id": 0}


def _fold_event(m: dict, kind: str, payload: dict) -> None:
    """Fold ONE spine event into the running metrics ``m`` (a headline counter + the by-kind histogram).
    A finding with a truthy ``verified_by_oracle`` is an oracle-confirmed FACT; else a LEAD."""
    m["events"] += 1
    m["by_kind"][kind] = m["by_kind"].get(kind, 0) + 1
    if kind == "finding":
        m["findings"] += 1
        if bool(payload.get("verified_by_oracle")):
            m["facts"] += 1
        else:
            m["leads"] += 1
    elif kind == "refusal":
        m["refusals"] += 1
    elif kind in _TOOL_KINDS:
        m["tool_calls"] += 1
    elif kind == "agent_message":
        m["messages"] += 1


def collect_snapshot(bb: Any, *, engagements: Optional[list] = None, generated_at: Optional[Any] = None) -> dict:
    """PURE projection of the signed spine into a live metrics snapshot. ``bb`` is any object exposing
    ``replay(engagement=, since_id=)`` (the blackboard). ``engagements`` is the slug list to summarise (else
    every slug on the spine, via ``_all_engagement_slugs``). Deterministic — no wallclock/RNG (an OPTIONAL
    ``generated_at`` is the only injected stamp, defaulting to None). Total: an unreadable engagement
    contributes an empty section, never a traceback."""
    slugs = engagements if engagements is not None else _all_engagement_slugs(bb)
    per: list = []
    totals = _blank_metrics()
    for slug in slugs:
        m = _blank_metrics()
        try:
            rows = bb.replay(engagement=slug, since_id=0)
        except Exception:  # noqa: BLE001 — an unregistered/unreadable slug contributes nothing
            rows = []
        for row in rows:
            kind = str(getattr(getattr(row, "kind", None), "value", getattr(row, "kind", "")) or "")
            payload = getattr(row, "payload", None) or {}
            if not isinstance(payload, dict):
                payload = {}
            _fold_event(m, kind, payload)
            rid = int(getattr(row, "id", 0) or 0)
            if rid > m["last_event_id"]:
                m["last_event_id"] = rid
        per.append({"slug": str(slug), **m})
        # roll the per-engagement counters into the totals (by_kind merges; last_event_id is a max)
        for k in ("events", "facts", "leads", "refusals", "tool_calls", "messages", "findings"):
            totals[k] += m[k]
        for kk, vv in m["by_kind"].items():
            totals["by_kind"][kk] = totals["by_kind"].get(kk, 0) + vv
        totals["last_event_id"] = max(totals["last_event_id"], m["last_event_id"])
    snap = {"schema": _SCHEMA, "engagements": per, "totals": totals}
    if generated_at is not None:
        snap["generated_at"] = generated_at
    return snap


def _all_engagement_slugs(bb: Any) -> list:
    """Every engagement slug on the spine, in id order (read-only over ``bb_engagements``). Total: [] on any
    error or a blackboard that does not expose the table."""
    try:
        conn = getattr(bb, "_conn", None)
        if conn is None:
            return []
        rows = conn.execute("SELECT slug FROM bb_engagements ORDER BY id").fetchall()
        return [str(r["slug"] if hasattr(r, "keys") else r[0]) for r in rows]
    except Exception:  # noqa: BLE001
        return []


def _open_blackboard() -> Any:
    """Lazy-open the signed spine (framework). Returns None on any error (the collector then writes an honest
    empty snapshot rather than crashing)."""
    try:
        from framework.v2.agents.blackboard import open_blackboard
        return open_blackboard()
    except Exception:  # noqa: BLE001 — framework absent / store unopenable ⇒ fail-soft
        return None


def _write_snapshot(out_path: Path, snap: dict) -> None:
    """Atomically write the snapshot JSON (tmp + rename), so a reader never sees a half-written file."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = out_path.with_suffix(out_path.suffix + ".tmp")
    tmp.write_text(json.dumps(snap, sort_keys=True), encoding="utf-8")
    os.replace(tmp, out_path)


def run_collector(*, out: str, interval: float, once: bool = False,
                  now_fn: Any = None, sleep_fn: Any = None, open_fn: Any = None) -> int:
    """The sidecar loop: every ``interval`` seconds write a fresh snapshot to ``out`` (or ``--once``). Fail-
    soft — a closed/absent spine writes an honest empty snapshot; a write error is logged and retried next
    tick. ``now_fn``/``sleep_fn``/``open_fn`` are injectable for tests (defaults: wallclock + real
    blackboard)."""
    now_fn = now_fn or (lambda: int(time.time()))
    sleep_fn = sleep_fn or time.sleep
    open_fn = open_fn or _open_blackboard
    out_path = Path(out)
    while True:
        bb = open_fn()
        try:
            snap = collect_snapshot(bb, generated_at=now_fn()) if bb is not None else {
                "schema": _SCHEMA, "engagements": [], "totals": _blank_metrics(),
                "generated_at": now_fn(), "note": "spine not open (framework absent or store unopenable)"}
        except Exception as e:  # noqa: BLE001 — a projection error is a logged, honest empty snapshot
            snap = {"schema": _SCHEMA, "engagements": [], "totals": _blank_metrics(),
                    "generated_at": now_fn(), "note": f"collect error: {type(e).__name__}"}
        try:
            _write_snapshot(out_path, snap)
        except OSError as e:
            print(f"telemetry: could not write {out_path} ({type(e).__name__}) — retry next tick", file=sys.stderr)
        finally:
            if bb is not None:
                try:
                    bb.close()
                except Exception:  # noqa: BLE001
                    pass
        if once:
            return 0
        sleep_fn(max(1.0, float(interval)))


def main(argv: Optional[list] = None) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="vigil telemetry",
                                description="live assurance/metrics collector over the signed spine (G2)")
    p.add_argument("--out", required=True, help="snapshot JSON path (atomically rewritten each tick)")
    p.add_argument("--interval", type=float, default=15.0, help="seconds between snapshots (default 15)")
    p.add_argument("--once", action="store_true", help="write one snapshot and exit")
    args = p.parse_args(argv)
    return run_collector(out=args.out, interval=args.interval, once=args.once)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
