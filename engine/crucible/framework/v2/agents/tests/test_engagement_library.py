"""
The ENGAGEMENT LIBRARY roster — ``Blackboard.list_engagements``.

The operator's requirement: "a list of past jobs you can go back to, months later", with dates and
timestamps. That needs three things the old console listing (an alphabetical ``ls targets/``) could
not give: WHEN each job was worked on, a stable identity to come back to, and counts worth showing.

These tests pin exactly that, plus the property that makes renaming safe: a human LABEL is INJECTED
by the caller and is never stored on, read from, or written into the append-only signed spine.
"""

from __future__ import annotations

import json

from framework.v2.agents.blackboard import Blackboard


def _obs(bb: Blackboard, slug: str, summary: str = "probe") -> int:
    return bb.post(engagement=slug, kind="observation", agent_name="recon",
                   payload={"source": "recon", "surface": "/", "summary": summary})


def _finding(bb: Blackboard, slug: str, *, slug_id: str, oracle: bool) -> int:
    return bb.post(
        engagement=slug, kind="finding", agent_name="reporter",
        payload={"finding_slug": slug_id, "title": "t", "severity": "High", "bug_class": "sqli",
                 "surface": "/q", "summary": "s", "verified_by_oracle": oracle},
    )


def _bb(tmp_path) -> Blackboard:
    return Blackboard(db_path=tmp_path / "spine.sqlite")


# ---------------------------------------------------------------------------
# identity + timestamps + ordering — the library's whole reason to exist
# ---------------------------------------------------------------------------


def test_lists_every_engagement_with_a_stable_id_and_real_timestamps(tmp_path) -> None:
    with _bb(tmp_path) as bb:
        first = bb.engagement_id("acme-prod")
        _obs(bb, "acme-prod")
        rows = bb.list_engagements()

    assert [r["slug"] for r in rows] == ["acme-prod"]
    row = rows[0]
    assert row["id"] == first                       # the stable identity to come back to
    # every stamp is REAL (derived from the registry / the events), never fabricated
    assert row["started_at"] and row["first_seen"] and row["last_activity"]
    assert row["first_seen"] <= row["last_activity"]
    assert row["closed_at"] is None


def test_an_engagement_with_no_events_reports_its_registration_time_not_a_blank(tmp_path) -> None:
    with _bb(tmp_path) as bb:
        bb.engagement_id("registered-never-run")
        row = bb.list_engagements()[0]
    assert row["events"] == 0 and row["findings"] == 0 and row["facts"] == 0
    # falls back to when it was registered — an honest stamp, not None and not "now"
    assert row["first_seen"] == row["started_at"] == row["last_activity"]


def test_newest_activity_first(tmp_path) -> None:
    """Ordering is by LAST ACTIVITY, so the job you touched most recently is at the top — the
    alphabetical directory listing this replaces put 'acme' above a job worked on yesterday.

    The three jobs are worked in the order zeta -> alpha -> mid, so the expected roster
    ``[mid, alpha, zeta]`` differs from BOTH the alphabetical order ``[alpha, mid, zeta]`` and its
    reverse ``[zeta, mid, alpha]``. That is deliberate: an earlier version of this test used a
    recency order that HAPPENED to equal the alphabetical one, so re-sorting the roster
    alphabetically still passed it — the control was silent for the exact regression it exists to
    catch."""
    with _bb(tmp_path) as bb:
        for slug in ("alpha", "mid", "zeta"):
            bb.engagement_id(slug)
        for slug in ("zeta", "alpha", "mid"):      # worked in this order; `mid` is the most recent
            _obs(bb, slug)
        rows = bb.list_engagements()

    assert [r["slug"] for r in rows] == ["mid", "alpha", "zeta"]
    stamps = [r["last_activity"] for r in rows]
    assert stamps == sorted(stamps, reverse=True)


def test_ordering_tie_break_within_one_second_is_the_spines_logical_clock(tmp_path, monkeypatch) -> None:
    """``posted_at`` is second-precision, so three jobs touched inside the SAME second all carry the
    same ``last_activity``. The tie-break must then be the spine's own logical clock (the highest
    event id is genuinely the later one) — never the slug, which would quietly reintroduce the
    alphabetical listing this method exists to replace."""
    from framework.v2.agents import blackboard as bb_mod
    monkeypatch.setattr(bb_mod, "now_iso", lambda: "2026-08-13T12:00:00+00:00")

    with _bb(tmp_path) as bb:
        for slug in ("alpha", "mid", "zeta"):
            bb.engagement_id(slug)
        for slug in ("zeta", "alpha", "mid"):
            _obs(bb, slug)
        rows = bb.list_engagements()

    assert len({r["last_activity"] for r in rows}) == 1, "the fixture must actually produce a tie"
    assert [r["slug"] for r in rows] == ["mid", "alpha", "zeta"]


def test_limit_is_respected(tmp_path) -> None:
    with _bb(tmp_path) as bb:
        for i in range(5):
            bb.engagement_id(f"e{i}")
        assert len(bb.list_engagements(limit=2)) == 2
        assert bb.list_engagements(limit=0) == []


# ---------------------------------------------------------------------------
# counts — findings vs oracle-confirmed FACTs, and the current view
# ---------------------------------------------------------------------------


def test_counts_separate_oracle_confirmed_facts_from_findings(tmp_path) -> None:
    with _bb(tmp_path) as bb:
        _finding(bb, "acme", slug_id="001-a", oracle=True)
        _finding(bb, "acme", slug_id="002-b", oracle=False)
        _obs(bb, "acme")
        row = bb.list_engagements()[0]

    assert row["events"] == 3
    assert row["findings"] == 2
    assert row["facts"] == 1, "only a finding a deterministic oracle confirmed is a FACT"


def test_superseded_rows_are_excluded_so_counts_match_the_current_view(tmp_path) -> None:
    with _bb(tmp_path) as bb:
        old = _finding(bb, "acme", slug_id="001-a", oracle=False)
        bb.supersede(old_id=old, agent_name="reporter",
                     new_payload={"finding_slug": "001-a", "title": "t", "severity": "High",
                                  "bug_class": "sqli", "surface": "/q", "summary": "revised",
                                  "verified_by_oracle": True})
        row = bb.list_engagements()[0]
        # the same view `read()` gives by default
        assert len(bb.read(engagement="acme", kinds=["finding"])) == 1

    assert row["findings"] == 1, "a superseded finding must not be double-counted"
    assert row["facts"] == 1
    assert row["events"] == 1


def test_an_unparseable_finding_payload_is_never_counted_as_a_fact(tmp_path) -> None:
    """Fail-closed: if a payload cannot be read, it is a finding but NOT a fact — the count can
    never over-claim proof."""
    db = tmp_path / "spine.sqlite"
    with _bb(tmp_path) as bb:
        _finding(bb, "acme", slug_id="001-a", oracle=True)
    # corrupt the stored payload out-of-band (a torn write / a hand-edited row)
    import sqlite3
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA foreign_keys = OFF")
    conn.execute("DROP TRIGGER IF EXISTS bb_events_no_update")
    conn.execute("UPDATE events SET payload_json = ? WHERE kind = 'finding'", ("{not json",))
    conn.commit()
    conn.close()

    with Blackboard(db_path=db) as bb:
        row = bb.list_engagements()[0]
    assert row["findings"] == 1 and row["facts"] == 0


# ---------------------------------------------------------------------------
# the RENAME property: a label is presentation metadata, never spine content
# ---------------------------------------------------------------------------


def test_label_is_injected_by_the_caller_and_defaults_to_empty(tmp_path) -> None:
    with _bb(tmp_path) as bb:
        bb.engagement_id("acme")
        assert bb.list_engagements()[0]["label"] == ""
        assert bb.list_engagements(labels={"acme": "Acme — Q3 external review"})[0]["label"] \
            == "Acme — Q3 external review"
        # an unrelated slug in the map never leaks onto another row
        assert bb.list_engagements(labels={"other": "Nope"})[0]["label"] == ""


def test_listing_with_a_label_writes_NOTHING_to_the_spine(tmp_path) -> None:
    """THE load-bearing invariant. Renaming is presentation only: listing under two different
    labels must leave the append-only spine byte-identical, and the label text must appear in NO
    stored row. If a label could reach an event payload it would change signed content."""
    db = tmp_path / "spine.sqlite"

    def _spine_rows() -> list[tuple]:
        import sqlite3
        conn = sqlite3.connect(db)
        try:
            return conn.execute(
                "SELECT id, engagement_id, kind, agent_name, posted_at, payload_json, "
                "       parent_id, supersedes_id FROM events ORDER BY id").fetchall()
        finally:
            conn.close()

    with Blackboard(db_path=db) as bb:
        _finding(bb, "acme", slug_id="001-a", oracle=True)
        _obs(bb, "acme")
        before = _spine_rows()

        bb.list_engagements(labels={"acme": "LABEL-ONE-9f3a"})
        bb.list_engagements(labels={"acme": "LABEL-TWO-4c81"})

        after = _spine_rows()

    assert after == before, "listing under a label must not mutate the append-only spine"
    blob = json.dumps(after, default=str)
    assert "LABEL-ONE-9f3a" not in blob and "LABEL-TWO-4c81" not in blob


def test_the_spine_has_no_label_column_at_all(tmp_path) -> None:
    """MUTATION CONTROL for the property above: the reason a label cannot reach signed content is
    STRUCTURAL — there is no label column on either spine table, so there is nothing to write it
    into. If someone ever adds one, this test fails and the invariant gets re-argued on purpose."""
    with _bb(tmp_path) as bb:
        bb.engagement_id("acme")
        cols = {t: {r["name"] for r in bb._conn.execute(f"PRAGMA table_info({t})")}   # noqa: SLF001
                for t in ("bb_engagements", "events")}
    assert "label" not in cols["bb_engagements"], cols["bb_engagements"]
    assert "label" not in cols["events"], cols["events"]
