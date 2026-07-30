"""Red-pen MED regression: distinct session ids differing only by a trailing dot ("abc" vs "abc.") must map
to DISTINCT graph partitions — otherwise one session's projection clobbers/leaks the other's, and a hard
delete of one collaterally wipes the other. The partition key must be injective over valid ids."""
from __future__ import annotations

from framework.v2.graph.store import EmbeddedGraphStore


def _ev(i, eng, kind):
    return {"id": i, "engagement_id": eng, "kind": kind, "agent_name": "a",
            "payload": {}, "parent_id": None, "supersedes_id": None}


def test_trailing_dot_sessions_do_not_collide(tmp_path):
    s = EmbeddedGraphStore(tmp_path)
    s.project_from_spine([_ev(1, 7, "A")], partition="abc")
    s.project_from_spine([_ev(2, 9, "B")], partition="abc.")

    files = sorted(p.name for p in tmp_path.glob("*.json"))
    assert len(files) == 2, f"distinct sessions must not share one partition file: {files}"

    # dropping 'abc' must NOT wipe 'abc.' (no collateral wipe), and 'abc' is genuinely gone.
    s.drop_partition("abc")
    assert s.nodes("abc."), "dropping 'abc' collaterally wiped 'abc.'"
    assert not s.nodes("abc"), "'abc' should be dropped"
