"""G2 — the live assurance/metrics collector over the signed spine (vigil_integration.telemetry).

collect_snapshot is a PURE, one-way projection: spine events → per-engagement fact/lead/refusal/tool/message
counts + totals. It never reads back into the spine and never mints a fact. The collector loop is fail-soft
(no spine → an honest empty snapshot). Framework-free (a fake blackboard is injected).
"""

from __future__ import annotations

import json
import sqlite3
from types import SimpleNamespace

from vigil_integration.telemetry import _all_engagement_slugs, collect_snapshot, run_collector


class FakeBB:
    """A blackboard stand-in: replay(engagement, since_id) yields fake rows, and a real in-memory ``_conn``
    with a bb_engagements table so the default slug enumeration (``_all_engagement_slugs``) works exactly as
    against the real spine. Never touches a real store."""

    def __init__(self, by_slug):
        self._by = by_slug            # {slug: [(id, kind, payload), ...]}
        self._conn = sqlite3.connect(":memory:")
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("CREATE TABLE bb_engagements(id INTEGER PRIMARY KEY, slug TEXT)")
        self._conn.executemany("INSERT INTO bb_engagements(slug) VALUES(?)", [(s,) for s in by_slug])

    def replay(self, *, engagement, since_id=0):
        return [SimpleNamespace(id=i, kind=k, payload=p)
                for (i, k, p) in self._by.get(engagement, []) if i > since_id]

    def close(self):
        pass


def test_collect_snapshot_counts_facts_leads_refusals_tools_messages():
    bb = FakeBB({"loopback": [
        (1, "finding", {"verified_by_oracle": True, "bug_class": "sqli"}),   # oracle-confirmed FACT
        (2, "finding", {"verified_by_oracle": False}),                       # LEAD
        (3, "finding", {}),                                                  # LEAD (no flag)
        (4, "refusal", {"gate": "warden"}),
        (5, "action", {"tool": "nmap"}),                                     # tool call
        (6, "tool_call", {"tool": "httpx"}),                                 # tool call
        (7, "agent_message", {"sender": "a", "recipient": "b"}),
        (8, "hypothesis", {}),
    ]})
    e = collect_snapshot(bb, engagements=["loopback"])["engagements"][0]
    assert e["slug"] == "loopback"
    assert e["facts"] == 1 and e["leads"] == 2 and e["findings"] == 3
    assert e["refusals"] == 1 and e["tool_calls"] == 2 and e["messages"] == 1
    assert e["events"] == 8 and e["last_event_id"] == 8
    assert e["by_kind"]["finding"] == 3 and e["by_kind"]["hypothesis"] == 1


def test_collect_snapshot_totals_across_engagements():
    bb = FakeBB({"a": [(1, "finding", {"verified_by_oracle": True})],
                 "b": [(1, "finding", {}), (2, "refusal", {})]})
    t = collect_snapshot(bb, engagements=["a", "b"])["totals"]
    assert t["facts"] == 1 and t["leads"] == 1 and t["refusals"] == 1 and t["events"] == 3


def test_collect_snapshot_total_on_unreadable_engagement():
    class Boom:
        def replay(self, **k):
            raise RuntimeError("nope")
    snap = collect_snapshot(Boom(), engagements=["x"])
    assert snap["engagements"][0]["events"] == 0 and snap["totals"]["events"] == 0   # empty, no crash


def test_collect_snapshot_is_deterministic():
    bb = FakeBB({"a": [(1, "finding", {"verified_by_oracle": True})]})
    assert collect_snapshot(bb, engagements=["a"]) == collect_snapshot(bb, engagements=["a"])   # no wallclock/RNG


def test_run_collector_once_writes_snapshot(tmp_path):
    bb = FakeBB({"loopback": [(1, "finding", {"verified_by_oracle": True})]})
    out = tmp_path / "telemetry.json"
    rc = run_collector(out=str(out), interval=1, once=True, now_fn=lambda: 42, open_fn=lambda: bb)
    assert rc == 0
    snap = json.loads(out.read_text(encoding="utf-8"))
    assert snap["generated_at"] == 42 and snap["totals"]["facts"] == 1


def test_run_collector_fail_soft_without_spine(tmp_path):
    out = tmp_path / "t.json"
    run_collector(out=str(out), interval=1, once=True, now_fn=lambda: 7, open_fn=lambda: None)
    snap = json.loads(out.read_text(encoding="utf-8"))
    assert snap["engagements"] == [] and "note" in snap        # honest empty snapshot, never a crash


def test_all_engagement_slugs_from_conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE bb_engagements(id INTEGER PRIMARY KEY, slug TEXT)")
    conn.executemany("INSERT INTO bb_engagements(slug) VALUES(?)", [("alpha",), ("beta",)])
    bb = SimpleNamespace(_conn=conn)
    assert _all_engagement_slugs(bb) == ["alpha", "beta"]
    assert _all_engagement_slugs(SimpleNamespace()) == []      # no _conn ⇒ [] (fail-soft)
