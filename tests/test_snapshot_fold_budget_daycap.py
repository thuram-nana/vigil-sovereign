"""Hard-prune equivalence proof for the BUDGET day-cap consumer (`BudgetLedger.spent`).

budget is the NO-FOLD bearer: it carries NO SnapshotState sub-state. `spent()` counts an agent's records
for ONE UTC day (`day_iso`), and the prune's RETENTION INVARIANT keeps the current UTC day LIVE, so every
pruned record (seq < base_seq) bears a `ts` BEFORE today and cannot match a current-day query. The rewrite
therefore seeds the ZERO (identity) Spend and windows to the LIVE records `[base_seq..T]` via
`iter_records(since_seq=st.base_seq - 1)` — byte-identical to the old genesis scan under the empty snapshot.

Two proofs:
  (A) IDENTITY  — real (empty) load; `spent()` returns the KNOWN-CORRECT value (today's behavior).
  (B) SPLIT     — the same full store, but load() is monkeypatched to a SYNTHETIC prefix snapshot
                  (`build([0..K))`, base_seq=K). `split = spent()` then seeds that prefix (ZERO for budget)
                  and folds only the LIVE [K..T] window. For the CURRENT day: split == full — i.e.
                  fold([0..K)) + fold([K..T]) == scan([0..T]). To prove it is NOT green-washed, the prefix
                  is NON-EMPTY and genuinely carries agent spend, shown by the documented PAST-day divergence
                  (full sees the pruned past-day records; the windowed split does not).

Run: SIGIL_HOME=$(mktemp -d) ~/.sigil/venv/bin/python -m pytest tests/test_snapshot_fold_budget_daycap.py -q
"""
import tempfile

from sigil.governor.budget import BudgetLedger, Spend
from sigil.spine.snapshot import SnapshotState, build
from sigil.spine.store import SpineStore

# Fixed, wall-clock-independent day buckets. DAY_A models a PRUNED past day; DAY_B the LIVE current day.
# `spent()` buckets purely by the `day_iso` we pass, so nothing here depends on the real date.
DAY_A = "2020-01-01"
DAY_B = "2026-07-19"
TS_A = DAY_A + "T00:00:00+00:00"
TS_B = DAY_B + "T12:00:00+00:00"


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _append(store, *, actor, kind, decision, ts, usage=None, source="agent"):
    payload = {"decision": decision, "subject": "x"}
    if usage is not None:
        payload["usage"] = usage
    return store.append(kind=kind, source=source, actor=actor, payload=payload, ts=ts)


def _populate(store):
    """A store whose FIRST 4 records are past-day (DAY_A) and whose rest are current-day (DAY_B). Returns
    the split seq K = the first LIVE (current-day) seq — a realistic prune point (prune == start of today).
    Exercises every fold branch: two agents, auto/queued/denied, an `event` interrupt, usage tokens+cost,
    a no-usage action, and a non-agent record that must be ignored."""
    # --- pruned PAST day (DAY_A): the prefix [0..K) ---
    _append(store, actor="SCHOLAR", kind="tool_call", decision="auto", ts=TS_A,
            usage={"input_tokens": 100, "output_tokens": 50, "cost_usd": 0.5})   # seq 0
    _append(store, actor="SCHOLAR", kind="event", decision="auto", ts=TS_A,
            usage={"input_tokens": 10, "output_tokens": 0, "cost_usd": 0.1})     # seq 1 (interrupt)
    _append(store, actor="ARTIFICER", kind="tool_call", decision="auto", ts=TS_A,
            usage={"input_tokens": 999, "output_tokens": 1, "cost_usd": 9.0})    # seq 2 (other agent)
    _append(store, actor="SCHOLAR", kind="tool_call", decision="denied", ts=TS_A,
            usage={"input_tokens": 777, "output_tokens": 0, "cost_usd": 7.0})    # seq 3 (denied -> skip)
    k = store.next_seq                                                            # K == 4 (first live seq)
    # --- live CURRENT day (DAY_B): the window [K..T] ---
    _append(store, actor="SCHOLAR", kind="tool_call", decision="auto", ts=TS_B,
            usage={"input_tokens": 200, "output_tokens": 100, "cost_usd": 0.3})  # seq 4
    _append(store, actor="SCHOLAR", kind="event", decision="auto", ts=TS_B,
            usage={"input_tokens": 50, "output_tokens": 0, "cost_usd": 0.2})     # seq 5 (interrupt)
    _append(store, actor="SCHOLAR", kind="tool_call", decision="denied", ts=TS_B,
            usage={"input_tokens": 888, "output_tokens": 0, "cost_usd": 8.0})    # seq 6 (denied -> skip)
    _append(store, actor="ARTIFICER", kind="tool_call", decision="auto", ts=TS_B,
            usage={"input_tokens": 30, "output_tokens": 0, "cost_usd": 0.05})    # seq 7 (other agent)
    _append(store, actor="SCHOLAR", kind="tool_call", decision="queued", ts=TS_B,
            usage={"input_tokens": 5, "output_tokens": 5, "cost_usd": 0.01})     # seq 8 (queued counts)
    _append(store, actor="SCHOLAR", kind="tool_call", decision="auto", ts=TS_B)  # seq 9 (no usage: action only)
    # a non-agent record with an agent-looking actor must be ignored by the source gate
    _append(store, actor="SCHOLAR", kind="tool_call", decision="auto", ts=TS_B, source="claude-code",
            usage={"input_tokens": 111, "output_tokens": 0, "cost_usd": 1.0})    # seq 10 (source!=agent)
    return k


# ---- (A) IDENTITY: real (empty) load -> the KNOWN-CORRECT current behavior -------------------------
def test_identity_empty_load_matches_known_values():
    store = _store()
    _populate(store)
    led = BudgetLedger(store)

    # SCHOLAR, current day (DAY_B): seq4 (300t/0.3), seq5 (50t/0.2, interrupt), seq8 (10t/0.01, queued),
    # seq9 (action, no usage). seq6 denied, seq10 non-agent -> excluded.
    sp = led.spent("SCHOLAR", DAY_B)
    assert sp == Spend(actions=4, interrupts=1, tokens=360, cost_usd=0.51)
    assert isinstance(sp, Spend)

    # SCHOLAR, past day (DAY_A): seq0 (150t/0.5), seq1 (10t/0.1, interrupt). seq3 denied -> excluded.
    sp_a = led.spent("SCHOLAR", DAY_A)
    assert sp_a == Spend(actions=2, interrupts=1, tokens=160, cost_usd=0.6)

    # ARTIFICER, current day: only seq7 (30t/0.05).
    assert led.spent("ARTIFICER", DAY_B) == Spend(actions=1, interrupts=0, tokens=30, cost_usd=0.05)


# ---- (B) SPLIT: fold([0..K)) [build] + fold([K..T]) [consumer] == scan([0..T]) ----------------------
def test_split_prefix_plus_live_equals_full_scan(monkeypatch):
    store = _store()
    k = _populate(store)
    led = BudgetLedger(store)

    # full = the real (empty) load -> scans ALL [0..T]. Enforcement is always the CURRENT-day query.
    full = led.spent("SCHOLAR", DAY_B)
    full_past = led.spent("SCHOLAR", DAY_A)           # the past-day (report-style) query, for non-triviality

    # Build a SYNTHETIC prefix snapshot from [0..K) and make load() return it. base_seq=K windows the
    # consumer to the LIVE [K..T]. trusted_pubkey is irrelevant to budget (it verifies no signatures).
    prefix = [r for r in store.iter_records() if r.seq < k]
    synthetic = build(prefix, trusted_pubkey="", base_seq=k, snapshot_seq=k - 1)
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: synthetic))

    split = led.spent("SCHOLAR", DAY_B)               # seeds prefix (ZERO for budget) + folds live [K..T]
    split_past = led.spent("SCHOLAR", DAY_A)

    # THE PROOF: the current-day enforcement query is EXACT under the prune.
    assert split == full == Spend(actions=4, interrupts=1, tokens=360, cost_usd=0.51)

    # Non-trivial split guards: K is mid-stream, the prefix is NON-EMPTY and carries real SCHOLAR spend
    # (so the equality above is NOT because the prefix is empty/irrelevant). budget is a NO-FOLD bearer, so
    # `build()` records NO budget sub-state — the equivalence rides entirely on the day filter + ZERO seed
    # + retention invariant, which the PAST-day divergence below makes concrete.
    assert 0 < k < store.next_seq
    assert synthetic.base_seq == k and synthetic.snapshot_seq == k - 1
    assert [r for r in prefix if r.source == "agent" and r.actor == "SCHOLAR"], "prefix carries SCHOLAR spend"

    # PAST-day divergence: full (whole scan) sees the pruned DAY_A SCHOLAR records; the windowed split does
    # NOT -> documented live-meter under-count. This proves the prefix genuinely mattered (green-wash guard).
    assert full_past == Spend(actions=2, interrupts=1, tokens=160, cost_usd=0.6)
    assert split_past == Spend(actions=0, interrupts=0, tokens=0, cost_usd=0.0)
    assert full_past.actions > split_past.actions
