"""SIGIL agent mesh (Phase 3) — autonomy-ceiling gating, ENVOY drafts-only (structural),
STEWARD brief composition, SENTINEL salience + budget. Run: ~/.sigil/venv/bin/python tests/test_agents.py"""
import tempfile

from sigil.agents.base import Agent, Proposal, Tier
from sigil.agents.envoy import Envoy, triage
from sigil.agents.sentinel import Sentinel
from sigil.agents.steward import Steward
from sigil.spine.store import SpineStore


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _grounded(store, kind, subject, text, **extra):
    store.append(kind=kind, source="archivist", actor="archivist",
                 payload={"subject": subject, "statement": text, "quote": text,
                          "source_seqs": [0], "verified_seqs": [0], "grounding": "ingest:seq=0",
                          "alpha": 2, "beta": 1, "promotion_key": kind + subject, **extra})


class _Dummy(Agent):
    name = "DUMMY"
    ceiling = Tier.A2


def test_ceiling_gate_auto_vs_queued():
    a = _Dummy(_store())
    res = a._dispatch([
        Proposal("finding", {"x": 1}, Tier.A1),                 # ≤ auto bar → applied
        Proposal("draft", {"to": "x", "subject": "s"}, Tier.A2),  # above auto bar → queued
        Proposal("event", {"y": 2}, Tier.A3),                    # above ceiling → queued (never auto)
    ])
    assert len(res.applied) == 1, "only the A1 proposal auto-applies"
    assert len(res.queued) == 2, "A2 and A3 both queue for approval"


class _A0Agent(Agent):
    name = "OBSERVER"
    ceiling = Tier.A0   # may only observe


def test_ceiling_blocks_above_ceiling_not_just_auto_bar():
    # an A1 proposal is at/below the AUTO_BAR, yet must QUEUE because it exceeds an A0 ceiling —
    # proving the ceiling gate independently of the auto bar.
    a = _A0Agent(_store())
    res = a._dispatch([Proposal("event", {"x": 1}, Tier.A1)])
    assert len(res.applied) == 0 and len(res.queued) == 1, "A1 exceeds an A0 ceiling → queued"


class _Inbox:
    def __init__(self, msgs):
        self._m = msgs

    def messages(self):
        return self._m


def test_envoy_drafts_only_and_triage():
    msgs = [
        {"from": "boss@co.com", "subject": "URGENT: deadline today", "body": "need this asap"},
        {"from": "alice@co.com", "subject": "lunch?", "body": "want to grab lunch"},
        {"from": "no-reply@newsletter.com", "subject": "Weekly digest", "body": "news"},
        {"from": "x@spam.com", "subject": "You have won a lottery", "body": "click here to claim"},
    ]
    assert triage(msgs[0]) == "urgent" and triage(msgs[1]) == "normal"
    assert triage(msgs[2]) == "fyi" and triage(msgs[3]) == "spam"
    e = Envoy(_store())
    res = e.run(_Inbox(msgs))
    # 4 triage interactions (A1 auto) + 2 drafts (urgent+normal, A2 queued); spam/fyi get no draft
    assert len(res.applied) == 4, "every message is triaged (interaction, auto)"
    assert len(res.queued) == 2, "only urgent+normal are drafted, and drafts QUEUE (never auto)"
    assert all(q["tier"] == "A2" for q in res.queued)
    # the DURABLE contract: the draft records on the spine carry the queued/awaiting-approval status
    drafts = [r for r in e.store.iter_records() if r.kind == "draft"]
    assert len(drafts) == 2
    for d in drafts:
        assert d.payload.get("decision") == "queued" and d.payload.get("status") == "awaiting-approval", \
            "a draft must be persisted as QUEUED, never auto-applied"
    # no transmit-intent method exists on ENVOY (not just a two-name spot-check)
    transmit = ("send", "transmit", "deliver", "smtp", "post", "publish", "outbound", "email_out", "mail")
    public = [n for n in dir(e) if not n.startswith("_")]
    assert not any(t in n.lower() for n in public for t in transmit), f"ENVOY exposes no send path: {public}"


def test_steward_brief_is_grounded_and_sectioned():
    s = _store()
    _grounded(s, "commitment", "ship it", "ship the release", owner="owner", due_iso="2026-08-01")
    _grounded(s, "decision", "database", "use Postgres for the store")
    # ungrounded decision — must NOT reach the brief (grounded-only guarantee, negative control)
    s.append(kind="decision", source="archivist", actor="archivist",
             payload={"subject": "phantom", "statement": "UNGROUNDED must not appear", "quote": "x",
                      "grounding": "llm:ungrounded", "promotion_key": "pk_ung"})
    text = Steward(s).brief_text(date_label="2026-07-18")
    assert "morning brief — 2026-07-18" in text
    assert "2026-08-01" in text and "ship the release" in text, "the due commitment appears"
    assert "use Postgres" in text, "the open decision appears"
    assert "UNGROUNDED must not appear" not in text, "an ungrounded record must NOT reach the brief"
    assert "Open threads" in text and "Commitments" in text


class _Watcher:
    def __init__(self, cands):
        self._c = cands

    def poll(self):
        return self._c


def test_sentinel_salience_floor_and_budget():
    cands = [{"kind": "a", "summary": "low", "salience": 0.3},      # below floor → dropped
             {"kind": "b", "summary": "mid", "salience": 0.6},
             {"kind": "c", "summary": "high", "salience": 0.95},
             {"kind": "d", "summary": "hi2", "salience": 0.8}]
    sen = Sentinel(_store(), salience_floor=0.5, alert_budget=2)
    res = sen.run([_Watcher(cands)])
    assert len(res.applied) == 2, "below-floor dropped, budget caps to 2"
    # prove WHICH survived: the two HIGHEST-salience (0.95, 0.8), not the 0.6 or below-floor 0.3
    sals = sorted(r.payload["salience"] for r in sen.store.iter_records() if r.kind == "event")
    assert sals == [0.8, 0.95], f"the two highest-salience alerts survived (sort direction), got {sals}"
    # and a malformed candidate (missing summary/kind) must not crash the run
    Sentinel(_store()).run([_Watcher([{"salience": 0.9}, {"kind": "k", "summary": "ok", "salience": 0.95}])])


def test_agent_records_carry_provenance():
    s = _store()
    Sentinel(s).run([_Watcher([{"kind": "x", "summary": "y", "salience": 0.9}])])
    rec = [r for r in s.iter_records() if r.kind == "event"][0]
    assert rec.source == "agent" and rec.actor == "SENTINEL" and rec.payload.get("tier") == "A1"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        try:
            fn(); print(f"  PASS  {fn.__name__}"); passed += 1
        except AssertionError as e:
            print(f"  FAIL  {fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            print(f"  ERROR {fn.__name__}: {e}")
    print(f"{passed}/{len(fns)} agent-mesh guarantees hold")
