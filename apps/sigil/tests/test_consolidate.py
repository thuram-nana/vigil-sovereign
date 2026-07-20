"""SIGIL consolidation — the bounded proof (zero Max spend, isolated temp store).

Proves the whole extract→gate→promote→brief loop plus the review-hardened guarantees: the gate
grounds only the VERBATIM QUOTE (never the model's paraphrase, so a dropped negation or reorder
cannot misrepresent), demotes fabricated citations/quotes, is Unicode-aware, is idempotent,
contradictions are extractor-judged + gate-verified, and the tools serve only grounded, cited
facts. Run: ~/.sigil/venv/bin/python tests/test_consolidate.py
"""
import tempfile

from sigil.consolidate.gate import admit
from sigil.consolidate.models import CandidateFact
from sigil.consolidate.pipeline import run_consolidation
from sigil.consolidate.queries import due_commitments, open_threads, pending_contradictions
from sigil.spine.store import SpineStore

_PROJ = "-home-kali-Pictures-PENTEST-main"


def _store(*texts):
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    for t in texts:
        s.append(kind="message", source="claude-code", actor="user",
                 payload={"session_id": "s1", "project": _PROJ, "text": t})
    return s


def _spine():
    return _store(
        "We decided to use Qdrant server mode for concurrent access.",       # seq0 decision
        "I'll ship the consolidation engine by 2026-07-20.",                 # seq1 commitment (due)
        "Let's go with Kuzu for the graph database.",                        # seq2 decision
        "Actually, we should switch the graph database to SQLite instead.",  # seq3 decision (reversal)
        "The weather is nice today and I had a coffee.")                     # seq4 chit-chat


class _Fixture:
    """Crafted candidates (positive + negative controls) once — a deterministic double."""
    def __init__(self):
        self._done = False

    def extract(self, records):
        if self._done:
            return []
        self._done = True
        return [
            CandidateFact("decision", "vector store", "use Qdrant server mode",
                          "We decided to use Qdrant server mode for concurrent access.", [0], 0.9, extractor="fx"),
            CandidateFact("commitment", "ship consolidation", "ship the consolidation engine",
                          "I'll ship the consolidation engine by 2026-07-20.", [1], 0.8,
                          owner="owner", due_iso="2026-07-20", extractor="fx"),
            CandidateFact("decision", "graph database", "Kuzu",
                          "Let's go with Kuzu for the graph database.", [2], 0.7, extractor="fx"),
            CandidateFact("decision", "graph database", "SQLite",
                          "Actually, we should switch the graph database to SQLite instead.", [3], 0.7, extractor="fx"),
            # extractor-judged reversal: cites BOTH conflicting records with a verbatim quote from EACH
            CandidateFact("contradiction", "graph database", "reversed Kuzu to SQLite", "", [2, 3], 0.7,
                          extractor="fx",
                          quotes=("Let's go with Kuzu for the graph database.",
                                  "Actually, we should switch the graph database to SQLite instead.")),
            # negative control A: cites a seq OUTSIDE the fed window → fabricated citation
            CandidateFact("decision", "phantom", "made up", "irrelevant", [999], 0.99, extractor="fx"),
            # negative control B: quote NOT verbatim in the cited record → fabricated quote
            CandidateFact("decision", "ghost", "invented", "THIS EXACT QUOTE IS IN NO RECORD", [0], 0.99, extractor="fx"),
        ]


def _run(store):
    return run_consolidation(_Fixture(), store=store, since_seq=-1, batch_size=100,
                             dry_run=False, sign=False, save_cursor=False)


def test_grounds_positives_demotes_fabrications():
    s = _spine()
    rep = _run(s)
    assert rep.grounded == 5, f"4 decisions/commitment + 1 contradiction must ground, got {rep.grounded}"
    assert rep.ungrounded == 2, f"fabricated citation + fabricated quote must demote, got {rep.ungrounded}"


def test_served_fact_is_the_verbatim_quote_not_the_model_statement():
    """The core guarantee: the fact served to the owner is the VERBATIM record quote, never the
    model's free-text statement — so a dropped negation or reorder cannot misrepresent."""
    s = _store("we have decided we should NOT deploy to prod on friday")
    # extractor drops the negation (a token-subset compression the old gate blessed) — attack
    inverted = CandidateFact("decision", "friday deploy", "deploy to prod on friday",
                             "we should NOT deploy to prod on friday", [0], 0.99, extractor="agent")
    v = admit(inverted, {0}, s)
    assert v.grounded, "the verbatim quote itself grounds"
    run_consolidation(_OneShot(inverted), store=s, since_seq=-1, batch_size=100,
                      dry_run=False, sign=False, save_cursor=False)
    threads = open_threads(s)
    assert threads and "not deploy" in threads[0]["text"].lower(), \
        f"served fact must be the real quote (negation intact), got {threads[0]['text']!r}"
    assert threads[0]["summary"] == "deploy to prod on friday", "the model statement is advisory-only, not the fact"


def test_grounded_facts_are_cited_spine_records():
    s = _spine()
    _run(s)
    decisions = [r for r in s.iter_records() if r.kind == "decision" and r.source == "archivist"]
    assert len(decisions) == 3, f"3 grounded decisions promoted, got {len(decisions)}"
    for d in decisions:
        assert d.payload["grounding"].startswith("ingest:"), "grounded facts carry an ingest: grounding"
        assert d.payload["verified_seqs"], "each cites the seqs that re-verified"


def test_fabrications_excluded_from_threads():
    s = _spine()
    _run(s)
    subjects = {t["subject"] for t in open_threads(s)}
    assert "phantom" not in subjects and "ghost" not in subjects, "demoted candidates must not surface as facts"
    assert "vector store" in subjects, "a grounded decision is an open thread"


def test_commitment_due_ledger():
    s = _spine()
    _run(s)
    due = due_commitments(s)
    assert len(due) == 1 and due[0]["due"] == "2026-07-20" and due[0]["owner"] == "owner"


def test_commitment_reschedule_serves_chronologically_latest_due():
    """The CHRONOLOGICALLY-later promise wins — even when its due date is EARLIER and even when
    the extractor emits it FIRST (so 'max spine-seq' and 'max due' would both pick wrong). This
    proves recency is source-record chronology, not promoted seq or due value (finding 1)."""
    s = _store("I'll ship it by 2026-07-20 for sure.",
               "Update: pulling it in — I'll ship it by 2026-06-15 instead.")  # later message, EARLIER due
    resc = CandidateFact("commitment", "ship it", "ship it",
                         "Update: pulling it in — I'll ship it by 2026-06-15 instead.",
                         [1], 0.8, owner="owner", due_iso="2026-06-15", extractor="fx")
    orig = CandidateFact("commitment", "ship it", "ship it", "I'll ship it by 2026-07-20 for sure.",
                         [0], 0.8, owner="owner", due_iso="2026-07-20", extractor="fx")
    run_consolidation(_Many([resc, orig]), store=s, since_seq=-1, batch_size=100,  # reschedule emitted FIRST
                      dry_run=False, sign=False, save_cursor=False)
    due = due_commitments(s)
    assert len(due) == 1 and due[0]["due"] == "2026-06-15", \
        f"the chronologically-later promise (seq1, earlier due) must win, got {due}"


def test_contradiction_extractor_driven():
    s = _spine()
    _run(s)
    pend = pending_contradictions(s)
    assert len(pend) == 1, f"one extractor-judged contradiction, got {len(pend)}"
    assert set(pend[0]["conflicting_seqs"]) == {2, 3}, \
        f"must name the exact VERIFIED conflicting record seqs, got {pend[0]['conflicting_seqs']}"


def test_contradiction_requires_two_verified_records():
    """A 'contradiction' that verifies only ONE record cannot serve an unverified second seq as
    a conflicting record — it must DEMOTE (findings 2/3)."""
    s = _store("Let's go with Kuzu for the graph database.",
               "The weather is nice today and I had a coffee.")
    c = CandidateFact("contradiction", "graph database", "reversed to weather", "", [0, 1], 0.9,
                      extractor="agent", quotes=("Let's go with Kuzu for the graph database.",))
    assert not admit(c, {0, 1}, s).grounded, "a contradiction with < 2 verbatim-verified records must demote"


def test_gate_rejects_out_of_window_existing_seq():
    """A seq that EXISTS but was not fed to the extractor is a fabricated citation (finding 8)."""
    s = _spine()
    c = CandidateFact("decision", "weather", "weather nice",
                      "The weather is nice today and I had a coffee.", [4], 0.9, extractor="agent")
    assert admit(c, {0, 1, 2, 3, 4}, s).grounded, "control: in-window, specific verbatim quote grounds"
    assert not admit(c, {0, 1, 2, 3}, s).grounded, "seq4 exists but is OUT of the fed window → demote"


def test_gate_rejects_trivial_quote_isolated():
    """Isolate MIN_QUOTE_SALIENT: quote verbatim + in-window, failing ONLY the specificity floor."""
    s = _spine()
    c = CandidateFact("decision", "x", "coffee", "coffee", [4], 0.99, extractor="agent")  # seq4 has 'coffee'
    v = admit(c, {0, 1, 2, 3, 4}, s)
    assert not v.grounded and "trivial" in v.reason, f"a 1-salient-token quote must demote via specificity: {v.reason}"


def test_gate_is_unicode_aware():
    """A FULLY non-ASCII quote (no embedded ASCII words) must still produce salient tokens and
    ground — an ASCII-only tokenizer would drop below MIN_QUOTE_SALIENT and wrongly demote it
    (finding 4/8). Uses Cyrillic so the test fails under an ASCII-only regression."""
    s = _store("Мы решили использовать Постгрес для базы данных проекта.")
    c = CandidateFact("decision", "база", "использовать Постгрес",
                      "Мы решили использовать Постгрес для базы данных проекта.", [0], 0.8, extractor="agent")
    assert admit(c, {0}, s).grounded, "a specific fully-Cyrillic verbatim quote must ground"


def test_idempotent_rerun():
    s = _spine()
    _run(s)
    n1 = s.count()
    rep2 = run_consolidation(_Fixture(), store=s, since_seq=-1, batch_size=100,
                             dry_run=False, sign=False, save_cursor=False)
    assert rep2.grounded == 0 and rep2.skipped == 7, f"re-run must promote nothing new, got {rep2.as_dict()}"
    assert s.count() == n1 + 1, "only the second brief record is added (all promotions deduped)"


def test_integrity_holds_after_promotion():
    s = _spine()
    _run(s)
    ok, msg = s.verify()
    assert ok, f"chain must still verify after promotion: {msg}"


def test_agent_json_parse_and_gate():
    from sigil.consolidate.extract import parse_candidates
    s = _spine()
    raw = (
        "Here are the durable facts:\n\n```json\n"
        '[{"kind":"decision","subject":"vector store","statement":"Qdrant server mode",'
        '"quote":"We decided to use Qdrant server mode for concurrent access.","source_seqs":[0],"confidence":0.9},'
        '{"kind":"decision","subject":"fabricated","statement":"nope",'
        '"quote":"a quote that appears in no record at all","source_seqs":[0],"confidence":0.95}]\n```\n'
    )
    cands = parse_candidates(raw, extractor="agent")
    assert len(cands) == 2, f"both candidates must parse from the fenced+prose response, got {len(cands)}"
    vs = [admit(c, {0, 1, 2, 3, 4}, s) for c in cands]
    assert vs[0].grounded and vs[0].grounding.startswith("ingest:"), "verbatim quote → grounded"
    assert not vs[1].grounded, "fabricated quote → demoted"


class _OneShot:
    def __init__(self, cand):
        self._c, self._done = cand, False

    def extract(self, records):
        if self._done:
            return []
        self._done = True
        return [self._c]


class _Many:
    def __init__(self, cands):
        self._c, self._done = cands, False

    def extract(self, records):
        if self._done:
            return []
        self._done = True
        return list(self._c)


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
    print(f"{passed}/{len(fns)} consolidation guarantees hold")
