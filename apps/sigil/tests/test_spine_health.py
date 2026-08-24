"""Spine health — the read-time integrity guards (W16-STD-4 / issue #530), covering three defects seen on
the reference host: a records-bearing host with NO signed head; a PROJECTION that drifted from the signed
chain (13,667 vector points over a 16-record chain); and individual CITATIONS that resolve to no signed
record yet were rendered.

Each behaviour is proven WITH its negative control (proving the gate is not a no-op):
  * signed_head_health FAILS on records-without-a-valid-head; PASSES once signed; empty box is advisory-OK.
  * resolve_citation REFUSES a seq beyond the tip AND a real seq carrying the WRONG entry_hash.
  * projection_drift TRIPS on an over-range / over-count projection but LEAVES a merely-trailing one alone.

Run: SIGIL_HOME=$(mktemp -d) ~/.sigil/venv/bin/python -m pytest tests/test_spine_health.py -q
"""
import pytest

import sigil.spine.checkpoint as _cp
import sigil.spine.floor as _fl
from sigil.spine import health
from sigil.spine.store import SpineStore


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    """Per-test owner head + keys + floor (the config globals are process-shared)."""
    import sigil.config as cfg
    keys = tmp_path / "keys"
    head = tmp_path / "head.json"
    monkeypatch.setattr(_cp, "HEAD_PATH", head)
    monkeypatch.setattr(cfg, "HEAD_PATH", head, raising=False)
    monkeypatch.setattr(_cp, "KEYS_DIR", keys)
    monkeypatch.setattr(_cp, "_PRIV", keys / "owner.priv")
    monkeypatch.setattr(_cp, "_PUB", keys / "owner.pub")
    monkeypatch.setattr(_fl, "FLOOR_PATH", tmp_path / "floor.json")
    return head


def _store_with_records(tmp_path, n=16):
    s = SpineStore(tmp_path / "spine.jsonl")
    s.migrate()
    for i in range(n):
        s.append(kind="message", source="t", actor="u", payload={"text": f"m{i}"})
    return s


# ── (1) signed-head health ────────────────────────────────────────────────────────────────────────────
def test_records_without_signed_head_is_unhealthy(tmp_path, isolated):
    """THE reference-host defect: a spine that holds records but has NO signed head must FAIL the health
    check (it is serving un-anchored memory with no tamper-evidence)."""
    s = _store_with_records(tmp_path, 16)
    assert not isolated.exists()                       # no head signed yet
    ok, detail = health.signed_head_health(s)
    assert not ok, "records-without-a-signed-head must be UNHEALTHY"
    assert "no valid signed head" in detail


def test_signed_head_is_healthy(tmp_path, isolated):
    """Negative control (the gate is not stuck-failing): once the owner signs the head, health passes."""
    s = _store_with_records(tmp_path, 16)
    _cp.checkpoint(s)                                  # owner-sign the head
    ok, detail = health.signed_head_health(s)
    assert ok, detail


def test_empty_pristine_spine_is_advisory_ok(tmp_path, isolated):
    """A genuinely EMPTY box with no head is a pristine install, not the defect — advisory OK so a fresh
    checkout's doctor stays green. (Distinguishes 'never signed, nothing to anchor' from 'records served
    unanchored'.)"""
    s = SpineStore(tmp_path / "spine.jsonl")
    s.migrate()
    assert s.next_seq == 0
    ok, _ = health.signed_head_health(s)
    assert ok


# ── (3) unresolvable-citation refusal (the READ-TIME negative control) ──────────────────────────────────
def test_resolve_citation_true_for_real_record(tmp_path):
    s = _store_with_records(tmp_path, 16)
    r = s.get(3)
    assert health.resolve_citation(s, 3, r.entry_hash)


def test_resolve_citation_refuses_seq_beyond_tip(tmp_path):
    """The 13,667-vs-16 case at the citation level: a projection point citing a seq the chain does not hold
    is refused (returns False -> the caller drops it, never renders it)."""
    s = _store_with_records(tmp_path, 16)              # seqs 0..15
    assert not health.resolve_citation(s, 13666, "deadbeef" * 8)


def test_resolve_citation_refuses_wrong_entry_hash(tmp_path):
    """Negative control that the gate is not a no-op: a citation with a VALID seq but a MISMATCHED
    entry_hash (a stale/rebuilt projection point at a live seq) is refused, not rendered."""
    s = _store_with_records(tmp_path, 16)
    assert not health.resolve_citation(s, 3, "ff" * 32)


def test_filter_resolved_hits_partitions(tmp_path):
    s = _store_with_records(tmp_path, 16)
    good = {"seq": 5, "entry_hash": s.get(5).entry_hash, "text": "real"}
    stale_seq = {"seq": 99999, "entry_hash": "ab" * 32, "text": "stale seq"}
    stale_hash = {"seq": 6, "entry_hash": "cd" * 32, "text": "wrong hash"}
    resolved, refused = health.filter_resolved_hits(s, [good, stale_seq, stale_hash])
    assert [h["seq"] for h in resolved] == [5]
    assert {h["seq"] for h in refused} == {99999, 6}


# ── (2) projection-drift detection ──────────────────────────────────────────────────────────────────────
def test_projection_drift_trips_on_reference_host_shape():
    """13,667 vector points over a signed 16-record chain (tip seq 15): drift on BOTH signals — the
    projection references a seq beyond the tip AND holds more points than the chain has records."""
    d = health.projection_drift("vector", signed_records=16, projected=13667,
                                projected_max_seq=13666, spine_tip_seq=15)
    assert d.drift and len(d.reasons) == 2


def test_projection_trailing_is_not_drift():
    """Negative control: a projection that merely TRAILS the chain (fewer/older points, nothing beyond the
    tip) is stale-but-honest, NOT drift — re-projection catches it up and it never serves an unresolvable
    citation. If this tripped, the detector would be a no-op alarm."""
    d = health.projection_drift("vector", signed_records=16, projected=10,
                                projected_max_seq=9, spine_tip_seq=15)
    assert not d.drift and d.reasons == []


def test_projection_drift_in_sync_is_clean():
    d = health.projection_drift("vector", signed_records=16, projected=16,
                                projected_max_seq=15, spine_tip_seq=15)
    assert not d.drift


def test_embeddable_record_count_matches_policy(tmp_path):
    """`embeddable_record_count` is the apples-to-apples denominator for the vector projection: it counts
    exactly the EMBEDDABLE_KINDS records the index would hold."""
    s = SpineStore(tmp_path / "spine.jsonl")
    s.migrate()
    for i in range(10):
        s.append(kind="message", source="t", actor="u", payload={"text": f"m{i}"})
    s.append(kind="tool_call", source="t", actor="u", payload={"cmd": "ls"})   # NOT embeddable
    n, tip = health.embeddable_record_count(s)
    assert n == 10 and tip == 10                       # 11 records (seq 0..10); 10 embeddable messages
