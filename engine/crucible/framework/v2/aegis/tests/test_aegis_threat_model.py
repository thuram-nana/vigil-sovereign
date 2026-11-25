"""AS-0 — the public AEGIS threat register is fixed-state only (plan §4.7).

These tests guard the publication invariant for the PUBLIC repository: the register in
``docs/aegis/aegis-threat-model.json`` may contain only mitigated (fixed-state) entries, each
with a record reference, and the Markdown companion must name every id. Open / un-mitigated
entries are not published here — they live in the private handoff register (plan §4.7).

The JSON is pure data; no framework import is needed to validate it, so these tests collect and
run even without the gateway stack.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

# docs/aegis lives two levels up from this tests/ dir: .../framework/v2/aegis/tests -> v2 -> docs/aegis
_V2 = Path(__file__).resolve().parents[2]
_DOCS = _V2 / "docs" / "aegis"
JSON_PATH = _DOCS / "aegis-threat-model.json"
MD_PATH = _DOCS / "aegis-threat-model.md"

_REQUIRED_FIELDS = ("id", "title", "zone", "attacker", "vector", "status", "mitigation", "record_ref")


@pytest.fixture(scope="module")
def model() -> dict:
    assert JSON_PATH.is_file(), f"public threat register missing: {JSON_PATH}"
    # it parses
    return json.loads(JSON_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def entries(model) -> list:
    assert isinstance(model.get("threats"), list), "'threats' must be a JSON array"
    assert model["threats"], "the public register must contain at least one entry"
    return model["threats"]


def test_json_parses_and_is_an_object(model):
    assert isinstance(model, dict)


def test_every_entry_has_the_required_fields(entries):
    for i, e in enumerate(entries):
        assert isinstance(e, dict), f"entry {i} is not an object"
        missing = [f for f in _REQUIRED_FIELDS if f not in e]
        assert not missing, f"entry {i} ({e.get('id', '?')}) missing fields: {missing}"


def test_every_public_entry_is_fixed_state(entries):
    """The §4.7 invariant: public == fixed state only. Every published entry must be 'mitigated'
    and must carry a non-empty record_ref (a shipped record, e.g. 'AS-27a / PR#1228', or
    'pending-AS-25' for a decided mitigation whose signed AS-25 record is scheduled)."""
    for e in entries:
        eid = e.get("id", "?")
        assert e.get("status") == "mitigated", (
            f"entry {eid} has status {e.get('status')!r}; the public register may hold only "
            f"'mitigated' (fixed-state) entries — open entries stay in the private register"
        )
        ref = e.get("record_ref")
        assert isinstance(ref, str) and ref.strip(), (
            f"entry {eid} has an empty record_ref; a mitigated public entry needs a record "
            f"reference per §4.7"
        )


def test_ids_are_unique(entries):
    ids = [e.get("id") for e in entries]
    assert all(isinstance(i, str) and i.strip() for i in ids), "every entry needs a non-empty id"
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    assert not dupes, f"duplicate threat ids: {dupes}"


def test_private_register_note_present(model):
    """§4.7: open entries are not published here; the file must say so."""
    note = model.get("private_register_note")
    assert isinstance(note, str) and note.strip(), "top-level 'private_register_note' is required"


def test_markdown_names_every_json_id(entries):
    assert MD_PATH.is_file(), f"Markdown companion missing: {MD_PATH}"
    md = MD_PATH.read_text(encoding="utf-8")
    for e in entries:
        eid = e["id"]
        assert eid in md, f"id {eid!r} from the JSON is not named in aegis-threat-model.md"
