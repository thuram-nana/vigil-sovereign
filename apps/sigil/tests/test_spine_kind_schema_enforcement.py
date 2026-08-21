"""W5-1 (#445) — the spine ENFORCES its `kind` vocabulary and stamps a per-record `schema_version`.

Before this change `KINDS` was imported for re-export and one test only — "a comment, not a constraint":
`SpineStore.append` would happily write ANY string as a record kind, and no record carried a schema
version. These tests pin the enforced invariants and prove each gate is not a no-op:

  * an out-of-vocabulary `kind` is REFUSED on append (fail-closed, nothing written) — this test FAILS on
    a tree without the fix (the bogus append would succeed);
  * a valid kind still appends and the whole chain still verifies (negative control — the gate is not a
    blanket refusal);
  * every new record carries `schema_version == SCHEMA_VERSION`;
  * a MIGRATION-SAFE read: a pre-W5-1 spine (records with no `schema_version` on the line) defaults to
    `LEGACY_SCHEMA_VERSION` and still verifies END TO END — no chain break (schema_version is not digested);
  * an unknown `schema_version` is refused on append (fail-closed);
  * the read/integrity path (`verify()` + `verify_record`) mirrors the offense SQL `CHECK(kind IN (...))`:
    a hand-edited record with an out-of-vocabulary kind fails verification;
  * `"detection"` — a real kind written by the inbound finding receiver — is IN the vocabulary (the
    enforcement would otherwise break that production append path; this pins the vocabulary is in sync).

Run: PYTHONPATH=apps/sigil python -m pytest apps/sigil/tests/test_spine_kind_schema_enforcement.py -q
"""
import json
import tempfile
from pathlib import Path

import pytest

from sigil.spine.models import (
    KINDS,
    KNOWN_SCHEMA_VERSIONS,
    LEGACY_SCHEMA_VERSION,
    SCHEMA_VERSION,
    SpineRecord,
)
from sigil.spine.store import SpineError, SpineStore
from sigil.spine.verify import verify_record


def _store() -> SpineStore:
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _append(s: SpineStore, kind: str = "event", n: int = 1) -> list[int]:
    return [s.append(kind=kind, source="agent", actor="TESTER", payload={"summary": f"e{i}"})
            for i in range(n)]


# ---- kind enforcement (write path) ---------------------------------------------------------------

def test_append_refuses_unknown_kind_and_writes_nothing():
    """FAILS WITHOUT THE FIX: on an unenforced tree `append` returns a seq for a bogus kind. Here it
    raises AND leaves the chain untouched (fail-closed — no partial write)."""
    s = _store()
    _append(s, "event", 2)
    before = s.count()
    with pytest.raises(SpineError) as ei:
        s.append(kind="not_a_real_kind", source="agent", actor="TESTER", payload={"x": 1})
    assert "unknown kind" in str(ei.value)
    assert s.count() == before, "a refused append must write NOTHING (fail-closed, no partial record)"
    ok, msg = s.verify()
    assert ok, f"the chain must remain intact after a refused append: {msg}"


def test_append_accepts_every_declared_kind():
    """Negative control: the gate is not a blanket refusal — every kind in the enforced vocabulary
    appends and the whole chain verifies."""
    s = _store()
    for kind in sorted(KINDS):
        s.append(kind=kind, source="t", actor="u", payload={"summary": kind})
    ok, msg = s.verify()
    assert ok, msg
    assert s.count() == len(KINDS)


def test_detection_kind_is_in_the_enforced_vocabulary():
    """`"detection"` is written to the sovereign spine by the inbound finding receiver
    (finding_receiver.DETECTION_KIND). Enforcing `kind` would break that production path unless the
    vocabulary is in sync — pin it."""
    from sigil.inbound.finding_receiver import DETECTION_KIND, FINDING_KIND
    assert DETECTION_KIND in KINDS
    assert FINDING_KIND in KINDS
    s = _store()
    seq = s.append(kind=DETECTION_KIND, source="offense", actor="ORACLE", payload={"summary": "det"})
    assert s.get(seq).kind == DETECTION_KIND


# ---- schema_version -------------------------------------------------------------------------------

def test_new_records_carry_the_current_schema_version():
    s = _store()
    seq = s.append(kind="event", source="agent", actor="X", payload={"summary": "hi"})
    rec = s.get(seq)
    assert rec.schema_version == SCHEMA_VERSION
    # and it is present on the raw line (persisted, not only reconstructed)
    raw = json.loads(Path(s.path).read_text().splitlines()[-1])
    assert raw["schema_version"] == SCHEMA_VERSION


def test_append_refuses_unknown_schema_version():
    """Negative control on the version gate: an unknown schema_version is refused (fail-closed)."""
    s = _store()
    unknown = max(KNOWN_SCHEMA_VERSIONS) + 99
    before = s.count()
    with pytest.raises(SpineError) as ei:
        s.append(kind="event", source="agent", actor="X", payload={"x": 1}, schema_version=unknown)
    assert "unknown schema_version" in str(ei.value)
    assert s.count() == before, "a refused append must write NOTHING"


# ---- migration-safe read of a pre-W5-1 spine -----------------------------------------------------

def test_legacy_prewversioned_spine_defaults_and_verifies_end_to_end():
    """The linchpin: a spine written BEFORE W5-1 has no `schema_version` on any line. Strip the field to
    simulate exactly that, reopen, and assert (a) every record reads back as LEGACY_SCHEMA_VERSION and
    (b) the whole chain still verifies END TO END — schema_version is informational (not digested), so
    defaulting it must NOT break any record's cert_digest or the chain."""
    s = _store()
    _append(s, "event", 3)
    s.append(kind="finding", source="agent", actor="X", payload={"summary": "f"})

    p = Path(s.path)
    stripped = []
    for ln in p.read_text().splitlines():
        d = json.loads(ln)
        d.pop("schema_version", None)                 # simulate a pre-W5-1 record
        assert "schema_version" not in d
        stripped.append(json.dumps(d, ensure_ascii=False))
    p.write_text("\n".join(stripped) + "\n")

    s2 = SpineStore(p)
    ok, msg = s2.verify()
    assert ok, f"a pre-versioned spine must verify end to end (no chain break): {msg}"
    recs = list(s2.iter_records())
    assert len(recs) == 4
    assert all(r.schema_version == LEGACY_SCHEMA_VERSION for r in recs), \
        "a record with no schema_version on the line must default to LEGACY_SCHEMA_VERSION"
    # per-atom re-verify (the live-tail path) also passes for every legacy record
    for r in recs:
        rok, rwhy = verify_record(r)
        assert rok, rwhy


def test_from_dict_defaults_missing_schema_version():
    d = {"seq": 0, "scope": "s", "kind": "event", "source": "t", "actor": "u", "payload": {},
         "parent_id": None, "supersedes_id": None, "ts": "", "cert_digest": "x",
         "prev_hash": "y", "entry_hash": "z"}
    assert SpineRecord.from_dict(d).schema_version == LEGACY_SCHEMA_VERSION
    d2 = {**d, "schema_version": SCHEMA_VERSION}
    assert SpineRecord.from_dict(d2).schema_version == SCHEMA_VERSION


# ---- read/integrity mirror of the SQL CHECK ------------------------------------------------------

def test_verify_rejects_a_hand_edited_unknown_kind():
    """Layer 2 (the sovereign mirror of the offense SQL `CHECK(kind IN (...))`): a record whose kind is
    forced out of vocabulary on disk fails BOTH the whole-log verify() and the per-atom verify_record."""
    s = _store()
    _append(s, "event", 2)
    p = Path(s.path)
    lines = p.read_text().splitlines()
    d = json.loads(lines[-1])
    d["kind"] = "smuggled_kind"                        # a hand-editor forces a bad kind onto the line
    lines[-1] = json.dumps(d, ensure_ascii=False)
    p.write_text("\n".join(lines) + "\n")

    s2 = SpineStore(p)
    ok, msg = s2.verify()
    assert not ok and ("unknown kind" in msg or "binding" in msg), msg
    bad = next(r for r in s2.iter_records() if r.kind == "smuggled_kind")
    rok, rwhy = verify_record(bad)
    assert not rok and "unknown kind" in rwhy
