"""
Tests for the blackboard.

Covers the load-bearing invariants:
  - schema migrates cleanly
  - post validates payload by kind
  - append-only enforcement (UPDATE/DELETE refused at the SQL layer)
  - supersession preserves history
  - read defaults to excluding superseded
  - read filters and pagination
  - validation rejects unknown kinds and ill-shaped payloads
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from framework.v2.agents import models
from framework.v2.agents.blackboard import (
    Blackboard, BlackboardError, open_blackboard,
)


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def bb(tmp_path: Path) -> Blackboard:
    db = tmp_path / "bb.sqlite"
    b = open_blackboard(db_path=db)
    yield b
    b.close()


# ---------------------------------------------------------------------------
# schema + migration
# ---------------------------------------------------------------------------


def test_schema_creates_tables(bb: Blackboard) -> None:
    rows = bb._conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    ).fetchall()
    names = {r["name"] for r in rows}
    assert {"events", "bb_engagements", "bb_schema_meta"} <= names


def test_engagement_idempotent(bb: Blackboard) -> None:
    eid = bb.engagement_id("alpha")
    eid2 = bb.engagement_id("alpha")
    assert eid == eid2


def test_engagement_create_false_raises_when_missing(bb: Blackboard) -> None:
    with pytest.raises(BlackboardError):
        bb.engagement_id("does-not-exist", create=False)


def test_wal_and_synchronous_normal(bb: Blackboard) -> None:
    # X3: WAL (persisted, from schema.sql) + synchronous=NORMAL (per-connection) — the standard
    # safe fast setting that drops the per-commit fsync without risking corruption.
    assert bb._conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    assert int(bb._conn.execute("PRAGMA synchronous").fetchone()[0]) == 1   # 1 == NORMAL


def test_read_parent_id_filter(bb: Blackboard) -> None:
    # X3: read(parent_id=...) restricts to the direct children of one event (served by
    # idx_events_parent), and is additive — parent_id=None yields the full set as before.
    bb.engagement_id("e")
    root = bb.post(engagement="e", kind="observation", agent_name="a",
                   payload={"source": "recon", "surface": "/x", "summary": "root"})
    c1 = bb.post(engagement="e", kind="observation", agent_name="a", parent_id=root,
                 payload={"source": "recon", "surface": "/x", "summary": "c1"})
    c2 = bb.post(engagement="e", kind="observation", agent_name="a", parent_id=root,
                 payload={"source": "recon", "surface": "/x", "summary": "c2"})
    bb.post(engagement="e", kind="observation", agent_name="a",
            payload={"source": "recon", "surface": "/x", "summary": "unrelated"})
    kids = bb.read(engagement="e", parent_id=root)
    assert {r.id for r in kids} == {c1, c2}                       # only root's children
    assert bb.read(engagement="e", parent_id=999_999) == []       # no children -> empty
    assert len(bb.read(engagement="e")) == 4                       # parent_id=None -> unchanged


# ---------------------------------------------------------------------------
# post + validation
# ---------------------------------------------------------------------------


def test_post_observation(bb: Blackboard) -> None:
    eid = bb.engagement_id("alpha")
    new_id = bb.post(
        engagement=eid, kind="observation", agent_name="recon",
        payload={
            "source": "recon", "surface": "/api/orders/123",
            "summary": "200 with another user's order body",
            "confidence": 0.7,
        },
    )
    assert new_id > 0
    row = bb.get(new_id)
    assert row is not None
    assert row.kind == "observation"
    assert row.payload["surface"] == "/api/orders/123"


def test_post_validates_payload_shape(bb: Blackboard) -> None:
    bb.engagement_id("alpha")
    # ObservationPayload requires source/surface/summary
    with pytest.raises(BlackboardError):
        bb.post(
            engagement="alpha", kind="observation",
            agent_name="recon", payload={"surface": "/x"},
        )


def test_post_rejects_unknown_kind(bb: Blackboard) -> None:
    bb.engagement_id("alpha")
    with pytest.raises(BlackboardError):
        bb.post(
            engagement="alpha", kind="invalid",  # type: ignore[arg-type]
            agent_name="recon", payload={},
        )


def test_post_validates_finding_severity(bb: Blackboard) -> None:
    bb.engagement_id("alpha")
    with pytest.raises(BlackboardError):
        bb.post(
            engagement="alpha", kind="finding", agent_name="exploit",
            payload={
                "finding_slug": "001-x", "title": "x",
                "severity": "Bogus",  # invalid
                "bug_class": "x", "surface": "/x", "summary": "x",
            },
        )


# ---------------------------------------------------------------------------
# append-only enforcement
# ---------------------------------------------------------------------------


def test_sql_update_refused(bb: Blackboard) -> None:
    bb.engagement_id("alpha")
    eid = bb.post(
        engagement="alpha", kind="observation", agent_name="x",
        payload={"source": "x", "surface": "/", "summary": "y"},
    )
    with pytest.raises(sqlite3.IntegrityError):
        bb._conn.execute("UPDATE events SET agent_name='hacked' WHERE id=?", (eid,))


def test_sql_delete_refused(bb: Blackboard) -> None:
    bb.engagement_id("alpha")
    eid = bb.post(
        engagement="alpha", kind="observation", agent_name="x",
        payload={"source": "x", "surface": "/", "summary": "y"},
    )
    with pytest.raises(sqlite3.IntegrityError):
        bb._conn.execute("DELETE FROM events WHERE id=?", (eid,))


def test_python_api_has_no_update(bb: Blackboard) -> None:
    """Api shape: confirm no `update`, `delete`, or `edit` method exists."""
    forbidden = {"update", "delete", "edit", "remove", "clear", "drop"}
    public = {n for n in dir(bb) if not n.startswith("_")}
    assert not (forbidden & public), f"forbidden methods: {forbidden & public}"


# ---------------------------------------------------------------------------
# supersession
# ---------------------------------------------------------------------------


def test_supersede_preserves_history(bb: Blackboard) -> None:
    bb.engagement_id("alpha")
    old = bb.post(
        engagement="alpha", kind="hypothesis", agent_name="hyp",
        payload={
            "handle": "H-001", "surface": "/api", "bug_class": "IDOR",
            "given": "g", "if_action": "i", "then_observation": "t",
            "because_model": "b", "refute_on": "r", "cheap_test": "c",
            "status": "open",
        },
    )
    new = bb.supersede(
        old_id=old, agent_name="hyp",
        new_payload={
            "handle": "H-001", "surface": "/api", "bug_class": "IDOR",
            "given": "g", "if_action": "i", "then_observation": "t",
            "because_model": "b", "refute_on": "r", "cheap_test": "c",
            "status": "confirmed",  # status changed
        },
    )
    # Old still exists
    assert bb.get(old) is not None
    # By default, read excludes superseded
    visible = bb.read(engagement="alpha", kinds=["hypothesis"])
    visible_ids = [v.id for v in visible]
    assert new in visible_ids
    assert old not in visible_ids
    # include_superseded brings it back
    all_h = bb.read(engagement="alpha", kinds=["hypothesis"], include_superseded=True)
    assert {old, new} <= {v.id for v in all_h}


def test_supersede_refuses_kind_mismatch(bb: Blackboard) -> None:
    bb.engagement_id("alpha")
    obs = bb.post(
        engagement="alpha", kind="observation", agent_name="x",
        payload={"source": "x", "surface": "/", "summary": "y"},
    )
    # post a finding with supersedes_id pointing at the observation -> refused
    with pytest.raises(BlackboardError):
        bb.post(
            engagement="alpha", kind="finding", agent_name="x",
            payload={
                "finding_slug": "001-x", "title": "x", "severity": "Low",
                "bug_class": "x", "surface": "/", "summary": "x",
            },
            supersedes_id=obs,
        )


def test_supersede_refuses_cross_engagement(bb: Blackboard) -> None:
    bb.engagement_id("alpha")
    bb.engagement_id("beta")
    eid = bb.post(
        engagement="alpha", kind="observation", agent_name="x",
        payload={"source": "x", "surface": "/", "summary": "y"},
    )
    with pytest.raises(BlackboardError):
        bb.post(
            engagement="beta", kind="observation", agent_name="x",
            payload={"source": "x", "surface": "/", "summary": "y2"},
            supersedes_id=eid,
        )


# ---------------------------------------------------------------------------
# read filters
# ---------------------------------------------------------------------------


def test_read_filters_by_kind_and_agent(bb: Blackboard) -> None:
    bb.engagement_id("alpha")
    bb.post(
        engagement="alpha", kind="observation", agent_name="recon",
        payload={"source": "r", "surface": "/", "summary": "x"},
    )
    bb.post(
        engagement="alpha", kind="observation", agent_name="exploit",
        payload={"source": "e", "surface": "/", "summary": "y"},
    )
    bb.post(
        engagement="alpha", kind="hypothesis", agent_name="hyp",
        payload={
            "handle": "H-001", "surface": "/", "bug_class": "x",
            "given": "g", "if_action": "i", "then_observation": "t",
            "because_model": "b", "refute_on": "r", "cheap_test": "c",
        },
    )
    obs = bb.read(engagement="alpha", kinds=["observation"])
    assert len(obs) == 2
    just_recon = bb.read(engagement="alpha", agent="recon")
    assert len(just_recon) == 1


def test_read_since_id(bb: Blackboard) -> None:
    bb.engagement_id("alpha")
    e1 = bb.post(
        engagement="alpha", kind="observation", agent_name="x",
        payload={"source": "x", "surface": "/", "summary": "1"},
    )
    e2 = bb.post(
        engagement="alpha", kind="observation", agent_name="x",
        payload={"source": "x", "surface": "/", "summary": "2"},
    )
    later = bb.read(engagement="alpha", since_id=e1)
    assert [r.id for r in later] == [e2]


def test_count(bb: Blackboard) -> None:
    bb.engagement_id("alpha")
    for _ in range(3):
        bb.post(
            engagement="alpha", kind="observation", agent_name="x",
            payload={"source": "x", "surface": "/", "summary": "y"},
        )
    assert bb.count(engagement="alpha", kind="observation") == 3
    assert bb.count(engagement="alpha") == 3
    assert bb.count(engagement="alpha", kind="finding") == 0


def test_latest_event_id(bb: Blackboard) -> None:
    bb.engagement_id("alpha")
    assert bb.latest_event_id(engagement="alpha") == 0
    e1 = bb.post(
        engagement="alpha", kind="observation", agent_name="x",
        payload={"source": "x", "surface": "/", "summary": "y"},
    )
    assert bb.latest_event_id(engagement="alpha") == e1


# ---------------------------------------------------------------------------
# parent_id provenance
# ---------------------------------------------------------------------------


def test_parent_id_links(bb: Blackboard) -> None:
    bb.engagement_id("alpha")
    obs = bb.post(
        engagement="alpha", kind="observation", agent_name="recon",
        payload={"source": "r", "surface": "/api", "summary": "200 leak"},
    )
    hyp = bb.post(
        engagement="alpha", kind="hypothesis", agent_name="hyp",
        parent_id=obs,
        payload={
            "handle": "H-001", "surface": "/api", "bug_class": "IDOR",
            "given": "g", "if_action": "i", "then_observation": "t",
            "because_model": "b", "refute_on": "r", "cheap_test": "c",
        },
    )
    row = bb.get(hyp)
    assert row is not None and row.parent_id == obs
