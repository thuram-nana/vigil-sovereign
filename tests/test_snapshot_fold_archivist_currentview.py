"""Equivalence proof for the hard-prune fold of the ARCHIVIST current-view + promotion ledgers
(revise.py: consolidation_records / iter_current / promotion_ledgers).

Proves fold == scan, not green-wash:
  (A) IDENTITY — under the Slice-C empty snapshot the rewired consumers return the KNOWN-CORRECT
      current-view + ledgers (this is the current genesis-scan behavior: load -> empty identity).
  (B) SPLIT — with the SAME store, fold([0..K) via SnapshotState.build) + fold([K..T] via the
      consumer) reproduces the full genesis scan, byte-for-byte. K is chosen so the prefix carries
      state that MATTERS: a decision (B1) that a LIVE record (B2) supersedes across the boundary,
      a grounded key and a refused key that must survive only via the folded ledgers, AND a
      NON-fact-kind refusal (R1) + brief (BR) that live ONLY in the pruned prefix.

Why the refusal/brief live in the prefix: consolidation_records(kinds=None) serves EVERY
source==archivist record (refusals + nightly briefs too), not just fact-kinds. build() used to fold
only fact-kinds into archivist_view, so a pruned refusal/brief would VANISH from a kinds=None /
kinds={"refusal"} / kinds={"brief"} query (they're in [0..K), never in the live window [K..T]).
The split test therefore asserts kinds=None AND kinds={"refusal"} AND kinds={"brief"} — not only
kinds={"decision"} — so the fold that drops refusal/brief cannot pass this gate.

Run:
  SIGIL_HOME=$(mktemp -d) ~/.sigil/venv/bin/python -m pytest tests/test_snapshot_fold_archivist_currentview.py -q
"""
import tempfile

from sigil.consolidate.revise import consolidation_records, iter_current, promotion_ledgers
from sigil.spine import snapshot
from sigil.spine.snapshot import SnapshotState
from sigil.spine.store import SpineStore


def _arch(store, kind, payload, supersedes_id=None):
    return store.append(kind=kind, source="archivist", actor="archivist",
                        payload=payload, supersedes_id=supersedes_id)


def _build_store():
    """A crafted archivist stream with fact records, refusals, a nightly brief, a cross-boundary
    supersession, and non-archivist noise. The refusal R1 and the brief BR sit in the pruned prefix
    [0..K) and appear NOWHERE in the live window — they survive a prune ONLY via the folded
    archivist_view. Returns (store, {label: seq})."""
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    seqs = {}
    seqs["noise0"] = s.append(kind="message", source="claude-code", actor="user", payload={"text": "hi"})
    seqs["A"] = _arch(s, "decision", {"subject": "A", "promotion_key": "kA", "grounding": "ingest:seq=0"})
    # refusal (source=archivist, non-fact-kind) with a promotion_key — lands in the PREFIX [0..K).
    seqs["R1"] = _arch(s, "refusal", {"subject": "R1", "promotion_key": "kR1", "grounding": "llm:ungrounded"})
    # nightly brief (source=archivist, non-fact-kind, NO promotion_key) — also in the PREFIX.
    seqs["BR"] = _arch(s, "brief", {"subject": "nightly", "text": "# ARCHIVIST brief", "open_threads": 1})
    seqs["B1"] = _arch(s, "decision", {"subject": "B", "promotion_key": "kB1", "grounding": "ingest:seq=4"})
    seqs["noise5"] = s.append(kind="commit", source="git", actor="dev", payload={"text": "c"})
    # ---- split boundary K = seq(B2): B1 + R1 refusal + BR brief land in the prefix, B2 in the live window
    seqs["B2"] = _arch(s, "decision", {"subject": "B", "promotion_key": "kB2", "grounding": "ingest:seq=6"},
                       supersedes_id=seqs["B1"])
    seqs["C"] = _arch(s, "commitment", {"subject": "C", "promotion_key": "kC", "owner": "o",
                                        "due_iso": "2026-08-01", "grounding": "ingest:seq=7"})
    seqs["R2"] = _arch(s, "refusal", {"subject": "R2", "promotion_key": "kR2", "grounding": "llm:ungrounded"})
    seqs["noise9"] = s.append(kind="message", source="claude-code", actor="user", payload={"text": "bye"})
    return s, seqs


def test_identity_fold_matches_known_correct(monkeypatch, tmp_path):
    # Force the production load path to the no-prune identity regardless of ambient SIGIL_HOME.
    monkeypatch.setattr(snapshot, "HEAD_PATH", tmp_path / "no-head.json")
    store, seqs = _build_store()

    # precondition: the real load IS the Slice-C empty identity (so this exercises the production path).
    st = SnapshotState.load(store)
    assert st.base_seq == 0 and not st.archivist_view and not st.grounded_keys and not st.refused_keys

    # current-view per kind: A survives, B1 is superseded OUT by B2; refusals + brief are current.
    assert {r.seq for r in iter_current(store, {"decision"})} == {seqs["A"], seqs["B2"]}
    assert {r.seq for r in iter_current(store, {"commitment"})} == {seqs["C"]}
    assert {r.seq for r in iter_current(store, {"refusal"})} == {seqs["R1"], seqs["R2"]}
    assert {r.seq for r in iter_current(store, {"brief"})} == {seqs["BR"]}

    # consolidation_records with NO kinds filter yields EVERY archivist record (incl. refusals AND the
    # brief), ascending seq, noise excluded — proving the empty-load path is the full genesis scan.
    assert [r.seq for r in consolidation_records(store)] == \
        [seqs["A"], seqs["R1"], seqs["BR"], seqs["B1"], seqs["B2"], seqs["C"], seqs["R2"]]

    grounded, refused = promotion_ledgers(store)
    assert grounded == {"kA", "kB1", "kB2", "kC"}
    assert refused == {"kR1", "kR2"}


def test_split_fold_equals_full_scan(monkeypatch, tmp_path):
    monkeypatch.setattr(snapshot, "HEAD_PATH", tmp_path / "no-head.json")
    store, seqs = _build_store()
    K = seqs["B2"]  # prefix [0..K) holds B1 (superseded by a LIVE record), a grounded key, a refused key,
    #                 the refusal R1, and the brief BR — none of which appear in the live window [K..T].

    # full = the REAL empty load -> scans the whole store. Capture EVERY query surface the consumer serves:
    # not just kinds={"decision"} (the gap the checker flagged) but kinds=None / {"refusal"} / {"brief"} too.
    full_dec = iter_current(store, {"decision"})
    full_ref = iter_current(store, {"refusal"})
    full_brief = iter_current(store, {"brief"})
    full_dec_records = list(consolidation_records(store, {"decision"}))
    full_all_records = list(consolidation_records(store))              # kinds=None: ALL archivist records
    full_g, full_r = promotion_ledgers(store)

    # synthesize the prefix snapshot the same way Slice D/E will at prune time.
    prefix = [r for r in store.iter_records() if r.seq < K]
    assert prefix, "prefix must be non-empty"
    synthetic = snapshot.build(prefix, trusted_pubkey="", base_seq=K, snapshot_seq=K - 1)

    # the prefix carries state that MATTERS (not a trivially-passing split): the soon-superseded decision
    # B1, a grounded + a refused ledger key, AND the two non-fact-kind records (refusal R1, brief BR) that
    # build() used to DROP. archivist_records_of(None) must retain all of them.
    assert synthetic.base_seq == K
    view_seqs = {r.seq for r in synthetic.archivist_records_of(None)}
    assert view_seqs == {seqs["A"], seqs["R1"], seqs["BR"], seqs["B1"]}, view_seqs
    assert set(synthetic.grounded_keys) == {"kA", "kB1"}                    # ledger keys only in the prefix
    assert set(synthetic.refused_keys) == {"kR1"}

    # now the consumer seeds the synthetic prefix and folds ONLY the live window [K..T] from the SAME store.
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: synthetic))
    split_dec = iter_current(store, {"decision"})
    split_ref = iter_current(store, {"refusal"})
    split_brief = iter_current(store, {"brief"})
    split_dec_records = list(consolidation_records(store, {"decision"}))
    split_all_records = list(consolidation_records(store))             # kinds=None under the synthetic snapshot
    split_g, split_r = promotion_ledgers(store)

    # fold([0..K)) + fold([K..T]) == scan([0..T]), byte-for-byte (SpineRecord is a frozen dataclass) — across
    # EVERY query surface, so a fold that drops the pruned refusal/brief cannot pass.
    assert split_dec_records == full_dec_records
    assert split_all_records == full_all_records
    assert split_dec == full_dec
    assert split_ref == full_ref
    assert split_brief == full_brief
    assert (split_g, split_r) == (full_g, full_r)

    # and it reconstructed the CORRECT cross-boundary view/ledgers, not merely "equal to itself":
    assert {r.seq for r in split_dec} == {seqs["A"], seqs["B2"]}
    assert split_g == {"kA", "kB1", "kB2", "kC"} and split_r == {"kR1", "kR2"}

    # THE regression the checker flagged: the PRUNED refusal + brief (in [0..K), absent from the live window)
    # MUST still appear via the folded archivist_view — a kinds=None / {"refusal"} / {"brief"} query would
    # silently under-return if build() folded only fact-kinds.
    all_seqs = {r.seq for r in split_all_records}
    assert seqs["R1"] in all_seqs and seqs["BR"] in all_seqs, all_seqs
    assert {r.seq for r in split_ref} == {seqs["R1"], seqs["R2"]}       # pruned R1 + live R2
    assert {r.seq for r in split_brief} == {seqs["BR"]}                 # pruned brief survives
