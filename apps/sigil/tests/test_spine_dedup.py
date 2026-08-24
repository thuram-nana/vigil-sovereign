"""Content de-duplication on append (issue #530, W16-STD-4) — MUST NOT break the hash chain.

`append(..., dedup=True)` looks back a bounded window for a record with byte-identical PLAINTEXT content and,
on a hit, returns that record's seq WITHOUT writing a new one. It is OPT-IN: the default path is byte-
identical to before. Because a dedup hit writes NOTHING, the chain is never altered — verify() and every
signed head are exactly what they'd be if the caller had simply chosen not to re-append.

Proven WITH negative controls:
  * dedup=True on identical content ⇒ one record, chain intact  (and keyed on PLAINTEXT, so SEALED content
    dedups even though its stored cert_digest differs per seq);
  * dedup=False (default) ⇒ the duplicate IS appended (opt-in, semantics unchanged);
  * dedup=True on DISTINCT content ⇒ both appended (not a no-op that swallows everything);
  * a duplicate OUTSIDE the window is appended (the window is a real bound, not "dedup against all history").

FAIL WITHOUT THE FIX: the pre-#530 `append` has no `dedup` parameter, so `dedup=True` raises TypeError.

Run: SIGIL_HOME=$(mktemp -d) ~/.sigil/venv/bin/python -m pytest tests/test_spine_dedup.py -q
"""
from sigil.spine.store import SpineStore


def _store(tmp_path):
    s = SpineStore(tmp_path / "spine.jsonl")
    s.migrate()
    return s


def _seqs(s):
    return [r.seq for r in s.iter_records()]


def test_dedup_returns_existing_seq_and_writes_nothing(tmp_path):
    s = _store(tmp_path)
    a = s.append(kind="event", source="x", actor="u", payload={"n": 1})
    b = s.append(kind="event", source="x", actor="u", payload={"n": 1}, dedup=True)
    assert b == a                                       # returned the existing seq
    assert _seqs(s) == [0]                              # NO new record written
    ok, why = s.verify()
    assert ok, why                                      # chain intact + contiguous


def test_dedup_off_by_default_appends_the_duplicate(tmp_path):
    """Negative control (opt-in): with dedup unset, identical content is appended — semantics unchanged."""
    s = _store(tmp_path)
    s.append(kind="event", source="x", actor="u", payload={"n": 1})
    s.append(kind="event", source="x", actor="u", payload={"n": 1})   # no dedup ⇒ a real 2nd record
    assert _seqs(s) == [0, 1] and s.verify()[0]


def test_dedup_distinct_content_both_appended(tmp_path):
    """Negative control (not over-matching / not a swallow-all no-op): different content is NOT deduped."""
    s = _store(tmp_path)
    s.append(kind="event", source="x", actor="u", payload={"n": 1}, dedup=True)
    s.append(kind="event", source="x", actor="u", payload={"n": 2}, dedup=True)
    assert _seqs(s) == [0, 1] and s.verify()[0]


def test_dedup_keys_on_plaintext_for_sealed_content(tmp_path):
    """THE soundness pin: `message.text` is a SEALED content field, so two identical messages get DIFFERENT
    stored cert_digests (the AEAD binds seq). Dedup keyed on the stored digest would never fire; keyed on
    PLAINTEXT it correctly dedups to one record. Force a spine DEK so sealing actually happens (the vault is
    unprovisioned in CI, which would otherwise store plaintext)."""
    import os

    s = _store(tmp_path)
    s._dek_cache = os.urandom(32)                       # force at-rest sealing (bypass the unprovisioned vault)
    a = s.append(kind="message", source="claude", actor="user", payload={"text": "hello world"})
    # sanity: the field really is sealed at rest (stored payload is a ciphertext envelope, not the plaintext),
    # AND its stored cert_digest is seq-bound — a stored-digest dedup key could NOT match across seqs.
    stored = s.get(a)
    assert isinstance(stored.payload.get("text"), dict) and stored.payload["text"].get("_enc")
    b = s.append(kind="message", source="claude", actor="user", payload={"text": "hello world"}, dedup=True)
    assert b == a and _seqs(s) == [0] and s.verify()[0]


def test_dedup_only_within_the_window(tmp_path):
    """The window is a real bound: a duplicate of a record that has scrolled OUT of the look-back window is
    appended, not deduped (dedup is bounded O(window), never O(spine))."""
    s = _store(tmp_path)
    first = s.append(kind="event", source="x", actor="u", payload={"marker": "A"})
    for i in range(5):
        s.append(kind="event", source="x", actor="u", payload={"filler": i})
    # window=2 only looks at the two most-recent records, so the marker at seq 0 is out of range → appended.
    again = s.append(kind="event", source="x", actor="u", payload={"marker": "A"}, dedup=True, dedup_window=2)
    assert again != first and again == 6
    # but with a window covering it, the same content dedups to the record just written (seq 6).
    third = s.append(kind="event", source="x", actor="u", payload={"marker": "A"}, dedup=True, dedup_window=50)
    assert third == 6 and _seqs(s) == list(range(7)) and s.verify()[0]


def test_dedup_interleaved_keeps_chain_contiguous(tmp_path):
    s = _store(tmp_path)
    for i in range(4):
        s.append(kind="event", source="x", actor="u", payload={"n": i})
    # a burst of duplicates (all deduped) between real appends must not gap or fork the chain.
    for _ in range(3):
        s.append(kind="event", source="x", actor="u", payload={"n": 3}, dedup=True)
    s.append(kind="event", source="x", actor="u", payload={"n": 99})
    assert _seqs(s) == [0, 1, 2, 3, 4]                  # 4 originals + 1 new; the 3 dupes wrote nothing
    ok, why = s.verify()
    assert ok, why
