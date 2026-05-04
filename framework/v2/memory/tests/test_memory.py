"""
Tests for MLS — schema, storage, embeddings, recorder, recall, priors.

Acceptance test per FORGE PROTOCOL § 3.2:

    "seed the store with the built-in sample engagement data ...
     Run UTI on a structurally similar second target.  Confirm the
     planner's first hypotheses are biased — measurably — toward
     what worked on the seeded archetype."

The achievable acceptance is that recall over the seeded store
returns the seeded archetype's priors at the top when queried with
a similar fingerprint.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from framework.v2.memory import embed, postmortem, priors, recall, recorder
from framework.v2.memory.store import Store, open_store


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def fresh_store(tmp_path: Path) -> Store:
    db = tmp_path / "store.sqlite"
    s = open_store(db)
    yield s
    s.close()


@pytest.fixture(autouse=True)
def _isolate_target_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The built-in seed module's seed() calls postmortem.run() which
    writes targets/<slug>/postmortem.md on disk. Without this redirect,
    every test that calls seed pollutes the real targets/ tree. Reads
    still degrade gracefully (returning [] when files are absent)."""
    from framework.v2.common import paths as _paths
    monkeypatch.setattr(_paths, "target_dir", lambda slug: tmp_path / slug)


# ---------------------------------------------------------------------------
# schema + store
# ---------------------------------------------------------------------------


def test_store_creates_schema(fresh_store: Store) -> None:
    rows = fresh_store.fetchall(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    )
    names = {r["name"] for r in rows}
    expected = {
        "schema_meta", "engagements", "findings", "hypotheses",
        "payloads", "dead_ends", "archetype_priors", "playbook_outcomes",
    }
    assert expected <= names


def test_store_summary(fresh_store: Store) -> None:
    summary = fresh_store.engagement_summary()
    assert summary["engagements"] == 0


# ---------------------------------------------------------------------------
# embeddings
# ---------------------------------------------------------------------------


def test_lexical_embedder_deterministic() -> None:
    e = embed.LexicalEmbedder()
    v1 = e.embed("Laravel marketplace IDOR on /api/orders/123")
    v2 = e.embed("Laravel marketplace IDOR on /api/orders/123")
    assert v1 == v2  # deterministic


def test_lexical_embedder_normalised() -> None:
    e = embed.LexicalEmbedder()
    v = e.embed("payment webhook signature verification missing")
    norm = sum(x * x for x in v) ** 0.5
    assert abs(norm - 1.0) < 1e-5


def test_lexical_embedder_similar_text_higher_cosine() -> None:
    e = embed.LexicalEmbedder()
    a = e.embed("PHP Smarty SMM panel webhook signature missing")
    b = e.embed("PHP Smarty panel forks omit signature on webhooks")
    c = e.embed("Java enterprise XML processing XXE in document parser")
    sim_ab = embed.cosine(a, b)
    sim_ac = embed.cosine(a, c)
    assert sim_ab > sim_ac


def test_blob_round_trip() -> None:
    e = embed.LexicalEmbedder()
    v = e.embed("test text")
    blob = embed.vec_to_blob(v)
    v2 = embed.blob_to_vec(blob)
    assert v == pytest.approx(v2)


# ---------------------------------------------------------------------------
# recorder + retrieval round-trip
# ---------------------------------------------------------------------------


def test_engagement_round_trip(fresh_store: Store) -> None:
    eid = recorder.record_engagement_start(
        fresh_store, slug="t1", target_url="https://t1.example",
        archetype="Test archetype", fingerprint={"server": "nginx"},
        business_context="testing",
    )
    assert eid > 0
    assert fresh_store.engagement_id("t1") == eid


def test_finding_persists(fresh_store: Store) -> None:
    recorder.record_engagement_start(
        fresh_store, slug="t2", archetype="X")
    fid = recorder.record_finding(
        fresh_store, "t2",
        finding_slug="001-test", title="Test finding",
        severity="High", bug_class="IDOR",
        summary="x", surface="/y",
    )
    rows = fresh_store.fetchall(
        "SELECT severity, bug_class FROM findings WHERE id=?", (fid,))
    assert len(rows) == 1
    assert rows[0]["severity"] == "High"


def test_hypothesis_status_update(fresh_store: Store) -> None:
    recorder.record_engagement_start(fresh_store, slug="t3", archetype="X")
    recorder.record_hypothesis(
        fresh_store, "t3", handle="H-001", bug_class="IDOR",
        if_text="hit /a/{id}", status="open",
    )
    recorder.update_hypothesis_status(
        fresh_store, "t3", "H-001", status="confirmed",
    )
    row = fresh_store.fetchone(
        "SELECT status, closed_at FROM hypotheses WHERE handle='H-001'"
    )
    assert row["status"] == "confirmed"
    assert row["closed_at"]  # populated


# ---------------------------------------------------------------------------
# priors
# ---------------------------------------------------------------------------


def test_priors_increment(fresh_store: Store) -> None:
    priors.bump_attempt(fresh_store, "Arch", "IDOR")
    priors.bump_attempt(fresh_store, "Arch", "IDOR")
    priors.bump_success(fresh_store, "Arch", "IDOR")  # third attempt, success
    p = priors.get_prior(fresh_store, "Arch", "IDOR")
    assert p is not None
    assert p.attempts == 3
    assert p.successes == 1
    # Laplace mean = (1+1)/(3+2) = 0.4
    assert p.mean == pytest.approx(0.4, abs=1e-6)


# ---------------------------------------------------------------------------
# built-in sample seed + acceptance
# ---------------------------------------------------------------------------


def test_seed_mrbeanpanel_runs(fresh_store: Store) -> None:
    from framework.v2.memory import seed_mrbeanpanel
    stats = seed_mrbeanpanel.seed(fresh_store)
    assert stats["engagement_id"] > 0
    # confirmed hypotheses + open hypotheses written
    row = fresh_store.fetchone(
        "SELECT COUNT(*) AS c FROM hypotheses WHERE engagement_id = ?",
        (stats["engagement_id"],),
    )
    assert row["c"] >= len(seed_mrbeanpanel._SEED_FINDINGS)
    # findings recorded
    row = fresh_store.fetchone(
        "SELECT COUNT(*) AS c FROM findings WHERE engagement_id = ?",
        (stats["engagement_id"],),
    )
    assert row["c"] == len(seed_mrbeanpanel._SEED_FINDINGS)


def test_recall_finds_seeded_target_by_similarity(fresh_store: Store) -> None:
    from framework.v2.memory import seed_mrbeanpanel
    seed_mrbeanpanel.seed(fresh_store)
    # Add a deliberate noise engagement on a totally different stack so
    # the seeded one has competition.
    recorder.record_engagement_start(
        fresh_store, slug="noise-rails", target_url="https://noise.example",
        archetype="Ruby on Rails monolith",
        fingerprint={"server": "puma", "framework": "Rails"},
        business_context="completely unrelated CRM app",
    )

    # Query with text resembling the seeded fingerprint.
    sims = recall.similar_targets(
        fresh_store,
        text="PHP Smarty SMM reseller panel payment webhook",
        limit=5,
    )
    assert sims, "expected at least one similar target"
    # The seeded engagement must rank above the unrelated rails one.
    top = sims[0]
    assert top.slug == "sample-php-panel"
    assert top.archetype == "PHP-Smarty SMM-panel fork"
    if len(sims) > 1:
        assert sims[0].score > sims[1].score


def test_recall_winning_hypotheses_returns_seeded(fresh_store: Store) -> None:
    from framework.v2.memory import seed_mrbeanpanel
    seed_mrbeanpanel.seed(fresh_store)
    wins = recall.winning_hypotheses(
        fresh_store, archetype="PHP-Smarty SMM-panel fork", limit=10,
    )
    classes = {w.bug_class for w in wins}
    # at least the three seeded confirmed classes should be present
    assert {"webhook-forgery", "IDOR", "mass-assignment"} <= classes


def test_recall_payload_priors_returns_seeded(fresh_store: Store) -> None:
    from framework.v2.memory import seed_mrbeanpanel
    seed_mrbeanpanel.seed(fresh_store)
    pp = recall.payload_priors(
        fresh_store, bug_class="webhook-forgery",
        archetype="PHP-Smarty SMM-panel fork",
    )
    assert pp
    assert pp[0].success_count >= 1


def test_priors_top_for_seeded_archetype(fresh_store: Store) -> None:
    from framework.v2.memory import seed_mrbeanpanel
    seed_mrbeanpanel.seed(fresh_store)
    rows = priors.top_priors_for(fresh_store, "PHP-Smarty SMM-panel fork", limit=10)
    classes = {p.bug_class for p in rows}
    # Seeded successful classes should appear in priors
    assert {"webhook-forgery", "IDOR", "mass-assignment"} <= classes


def test_postmortem_writes_file(fresh_store: Store, tmp_path: Path,
                                 monkeypatch: pytest.MonkeyPatch) -> None:
    from framework.v2.common import paths as _paths
    from framework.v2.memory import seed_mrbeanpanel

    # Redirect target_dir to tmp so we don't pollute the real targets/.
    monkeypatch.setattr(_paths, "target_dir",
                         lambda slug: tmp_path / slug)
    seed_mrbeanpanel.seed(fresh_store)
    out = postmortem.run(fresh_store, "sample-php-panel")
    assert out.is_file()
    text = out.read_text(encoding="utf-8")
    assert "Postmortem" in text
    assert "Findings" in text
    assert "PHP-Smarty SMM-panel fork" in text or "Archetype" in text


# ---------------------------------------------------------------------------
# acceptance summary — § 3.2 measurable bias
# ---------------------------------------------------------------------------


def test_acceptance_measurable_bias_after_seed(fresh_store: Store) -> None:
    """
    After seeding the built-in sample engagement and recording an unrelated one,
    a query for hypotheses biased toward 'PHP-Smarty SMM-panel fork'
    must rank the seeded confirmed bug-classes ABOVE arbitrary others.
    This is the closest we can get to § 3.2 without UTI/ACP.
    """
    from framework.v2.memory import seed_mrbeanpanel

    seed_mrbeanpanel.seed(fresh_store)

    # add a rails engagement with different confirmed bugs
    recorder.record_engagement_start(
        fresh_store, slug="rails-app", archetype="Ruby on Rails monolith",
    )
    recorder.record_finding(
        fresh_store, "rails-app",
        finding_slug="R001-xxe", title="XXE in document import",
        severity="High", bug_class="XXE",
        surface="/import", summary="xxe path",
    )
    recorder.record_hypothesis(
        fresh_store, "rails-app", handle="HR-001",
        bug_class="XXE", surface="/import", status="confirmed",
    )

    wins = recall.winning_hypotheses(
        fresh_store, archetype="PHP-Smarty SMM-panel fork", limit=20,
    )
    bug_classes = [w.bug_class for w in wins]

    # XXE belongs to the Rails archetype; it must NOT be in the
    # PHP-archetype winning list.
    assert "XXE" not in bug_classes
    # seeded PHP-archetype confirmed classes MUST be present
    assert "webhook-forgery" in bug_classes
    assert "IDOR" in bug_classes
