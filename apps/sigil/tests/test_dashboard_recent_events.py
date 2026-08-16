"""Home-screen payload contract for dashboard.snapshot().

The Home screen's "Recent activity" feed calls `snap.recent_events.slice(0, 8)` — an ARRAY operation.
`recent_decisions` and `recent_by_agent` are Counter → dict (decision-outcome → count) and are NOT arrays;
the UI must never call `.slice()` on them. Before this contract existed the feed sliced `recent_decisions`
(a dict) and threw `TypeError: .slice is not a function` on every healthy-backend load, breaking the panel.

These tests lock the shape the UI depends on: `recent_events` is a list of {ts, actor, kind, choice, text}
dicts (newest-first, capped), while the two counters stay dicts. If a future change flips either shape, the
Home feed breaks again — and this test goes red first.

Run: SIGIL_HOME=$(mktemp -d) python -m pytest tests/test_dashboard_recent_events.py -q
"""

import tempfile

import pytest

from sigil.dashboard import snapshot
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


@pytest.fixture(autouse=True)
def owner(monkeypatch):
    # Point identity readers at a test key so snapshot()'s pending()/PromotionPolicy path resolves without a
    # persisted keyring/vault (same pattern as test_knowledge_proposals).
    import sigil.governor.identity as idmod
    monkeypatch.setattr(idmod, "ensure_owner_keypair", lambda: OWNER)
    monkeypatch.setattr(idmod, "owner_keypair", lambda: OWNER)
    monkeypatch.setattr(idmod, "owner_pubkey", lambda: OWNER.public_key_b64)
    return OWNER


def _decide(store, actor, decision):
    return store.append(kind="event", source="agent", actor=actor, payload={"decision": decision})


def test_recent_events_is_a_list_the_ui_can_slice():
    s = _store()
    _decide(s, "SENTINEL", "auto")
    _decide(s, "ARCHIVIST", "queued")
    snap = snapshot(s)
    ev = snap["recent_events"]
    assert isinstance(ev, list), "the UI calls recent_events.slice() — it MUST be a list, not a dict"
    # every item carries the fields the feed reads: feedRow('decision', d.text || d.choice, d.ts)
    for item in ev:
        assert isinstance(item, dict)
        assert set(item) >= {"ts", "actor", "kind", "choice", "text"}
        assert isinstance(item["text"], str) and item["text"]
    # the emulated UI access path does not raise (the exact call the Home feed makes)
    sliced = ev[:8]
    assert [row["text"] or row["choice"] or "decision" for row in sliced]


def test_recent_events_is_newest_first_and_capped_at_8():
    s = _store()
    for i in range(12):
        _decide(s, f"A{i}", "auto")
    ev = snapshot(s)["recent_events"]
    assert len(ev) == 8, "the feed shows the 8 most recent events"
    assert ev[0]["actor"] == "A11" and ev[-1]["actor"] == "A4", "newest-first ordering"


def test_counter_fields_stay_dicts_never_arrays():
    """The regression guard: recent_decisions / recent_by_agent are decision→count / agent→count maps. If
    either became a list the OLD (removed) UI code would have worked and the array one would break — so lock
    them as dicts, the shape the UI must NOT .slice()."""
    s = _store()
    _decide(s, "SENTINEL", "auto")
    _decide(s, "SENTINEL", "denied")
    snap = snapshot(s)
    assert isinstance(snap["recent_decisions"], dict)
    assert isinstance(snap["recent_by_agent"], dict)
    assert snap["recent_decisions"].get("auto") == 1 and snap["recent_decisions"].get("denied") == 1
    # a dict has no .slice — asserting the type is asserting "the UI must not treat this as an array"
    assert not hasattr(snap["recent_decisions"], "slice")


def test_empty_store_yields_empty_list_not_missing_key():
    """A cold engagement must still hand the UI an (empty) ARRAY, so the feed renders its empty state rather
    than tripping on a missing key or a non-array default."""
    snap = snapshot(_store())
    assert snap["recent_events"] == []
    assert isinstance(snap["recent_events"], list)
