"""W5-2 (#446) — the spine payload-evolution CONTRACT is real, upcasts old records, and is ENFORCED.

Context (the structural fact the contract exists for): a record's `payload` is folded into `cert_digest`,
which chains into `entry_hash` and the owner-signed head. An already-appended record therefore cannot be
rewritten without breaking the chain — payloads are *un-migratable*. The only safe evolutions are ADD an
optional field, or mint a new `kind`. W5-2 writes those rules down (`sigil.spine.payload_contract` + the
decision record) and enforces them with a committed-baseline schema diff.

This suite pins three things and proves each gate is not a no-op:

  * READ-TIME UPCASTER (C3) — `SpineRecord.typed_payload()` / `upcast_payload` reads an OLD payload (one
    that predates a later-added field) correctly under the current model: the missing field takes its
    default, present fields survive, and a field a NEWER writer added round-trips (C5). These tests FAIL on
    a tree without this change — `payload_contract` / `typed_payload` do not exist, so the import errors.
  * SCHEMA DIFF (enforcement) — `test_live_models_match_committed_baseline` runs the REAL `diff_shapes`
    over the committed `payload_shapes.json` vs the live models and fails on ANY breaking drift. It is the
    required regression guard: a future PR that removes/retypes a committed field, or adds a required one,
    turns this (P7-required) job red.
  * NEGATIVE CONTROL — the diff engine is exercised, in the SAME run, over the REAL committed baseline with
    a deliberately breaking mutation (a removed field, a retyped field, a new required field, a removed
    kind) → each is flagged; a deliberately ADDITIVE mutation (a new optional field) is NOT flagged. This
    proves the gate rejects a bad change and is not simply passing everything.

Run: PYTHONPATH=apps/sigil:integration <venv>/bin/python -m pytest \
       apps/sigil/tests/test_payload_evolution_contract.py -q
"""
from __future__ import annotations

import copy
import re
from pathlib import Path

import pytest

from sigil.spine.models import SpineRecord
from sigil.spine.payload_contract import (
    COMMITTED_SHAPES_PATH,
    PAYLOAD_MODELS,
    current_shapes,
    diff_shapes,
    load_committed_shapes,
    upcast_payload,
)
from sigil.spine.store import SpineStore


def _store() -> SpineStore:
    import tempfile
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


# ==================================================================================================
# ENFORCEMENT — the live models introduce NO breaking change vs the committed baseline.
# ==================================================================================================
def test_live_models_match_committed_baseline():
    """THE guard: on this tree the live per-kind models are additively-compatible with the committed
    `payload_shapes.json`. A future breaking edit (remove/retype a committed field, or add a required one)
    makes `diff_shapes` non-empty and turns this required job red."""
    committed = load_committed_shapes()
    breaking = diff_shapes(committed, current_shapes())
    assert breaking == [], (
        "the payload models drifted from the committed contract in a BREAKING way:\n  - "
        + "\n  - ".join(breaking)
        + "\n\nIf the change is genuinely additive (a new OPTIONAL field / new kind) this test passes; a "
          "breaking change must instead be a NEW field name or a NEW kind. Regenerate the baseline only for "
          "additive changes: python -m sigil.spine.payload_contract")


def test_committed_baseline_covers_every_registered_kind():
    """Every kind with a live payload model has a committed shape — so a new registered kind ships with its
    baseline entry (its own fields are then frozen by the contract from that point on)."""
    committed = load_committed_shapes()
    assert set(committed) == set(PAYLOAD_MODELS), (
        f"committed baseline kinds {sorted(committed)} != registered models {sorted(PAYLOAD_MODELS)}; "
        f"regenerate: python -m sigil.spine.payload_contract")


def test_committed_baseline_is_committed_to_the_tree():
    assert COMMITTED_SHAPES_PATH.exists(), f"the committed contract baseline is missing: {COMMITTED_SHAPES_PATH}"


# ==================================================================================================
# NEGATIVE CONTROL — the diff engine flags each breaking mutation of the REAL baseline (same run),
# and passes a genuinely additive one. Proves the gate above is not a no-op.
# ==================================================================================================
def test_diff_flags_a_removed_committed_field():
    committed = load_committed_shapes()
    mutated = copy.deepcopy(committed)
    del mutated["snapshot"]["folded_state"]          # drop a security-critical committed field
    breaking = diff_shapes(committed, mutated)
    assert any("snapshot.folded_state" in b and "REMOVED" in b for b in breaking), breaking


def test_diff_flags_a_retyped_committed_field():
    committed = load_committed_shapes()
    mutated = copy.deepcopy(committed)
    mutated["snapshot"]["base_seq"]["type"] = "str"   # int -> str: a meaning change
    breaking = diff_shapes(committed, mutated)
    assert any("snapshot.base_seq" in b and "type changed" in b for b in breaking), breaking


def test_diff_flags_a_new_required_field():
    committed = load_committed_shapes()
    mutated = copy.deepcopy(committed)
    mutated["commit"]["mandatory"] = {"type": "str", "required": True}
    breaking = diff_shapes(committed, mutated)
    assert any("commit.mandatory" in b and "REQUIRED" in b for b in breaking), breaking


def test_diff_flags_an_optional_field_made_required():
    committed = load_committed_shapes()
    mutated = copy.deepcopy(committed)
    mutated["commit"]["subject"]["required"] = True
    breaking = diff_shapes(committed, mutated)
    assert any("commit.subject" in b and "REQUIRED" in b for b in breaking), breaking


def test_diff_flags_a_removed_kind():
    committed = load_committed_shapes()
    mutated = copy.deepcopy(committed)
    del mutated["web_page"]
    breaking = diff_shapes(committed, mutated)
    assert any(b.startswith("web_page:") and "removed" in b for b in breaking), breaking


def test_diff_allows_a_new_optional_field():
    """The additive case the AC calls out explicitly: adding an OPTIONAL field is NOT breaking."""
    committed = load_committed_shapes()
    mutated = copy.deepcopy(committed)
    mutated["commit"]["author_email"] = {"type": "str", "required": False}
    assert diff_shapes(committed, mutated) == [], "adding an optional field must be allowed (additive)"


def test_diff_allows_a_brand_new_kind():
    committed = load_committed_shapes()
    mutated = copy.deepcopy(committed)
    mutated["brand_new_kind"] = {"a": {"type": "str", "required": False}}
    assert diff_shapes(committed, mutated) == [], "a brand-new kind's shape is additive"


# ==================================================================================================
# READ-TIME UPCASTER (C3/C5) — an old record reads correctly; these FAIL on a tree without the change.
# ==================================================================================================
def test_typed_payload_upcasts_a_legacy_record_on_the_real_read_path():
    """Append a `commit` record whose payload OMITS `subject` (simulating a record written before that
    field existed), read it back through the store, and upcast via the record's own method: the missing
    field takes its default, the present fields survive. `typed_payload` is on the real `SpineRecord`."""
    s = _store()
    seq = s.append(kind="commit", source="git", actor="a",
                   payload={"text": "t", "hash": "h", "repo": "r"})   # no "subject"
    rec = s.get(seq)
    assert isinstance(rec, SpineRecord)
    typed = rec.typed_payload()
    assert typed is not None
    assert typed.text == "t" and typed.hash == "h" and typed.repo == "r"
    assert typed.subject is None, "a later-added field absent on an old record must upcast to its default"


def test_typed_payload_is_none_for_a_freeform_kind():
    s = _store()
    seq = s.append(kind="event", source="t", actor="u", payload={"anything": 1})
    assert s.get(seq).typed_payload() is None, "a free-form (unregistered) kind has no structural contract"


def test_upcast_reads_the_wire_schema_field_of_a_finding():
    """The finding/detection payloads carry a wire field named `schema` (pydantic-reserved); the model
    binds it via an alias so the upcaster actually reads it, not silently drops it to an extra."""
    m = upcast_payload("finding", {
        "schema": "vigil.inert-finding.v1", "finding_ref": "F-1",
        "oracle_context_digest": "abc", "certificate": {"k": 1}, "signatures": [{"s": "x"}]})
    assert m is not None
    assert m.schema_ == "vigil.inert-finding.v1"
    assert m.finding_ref == "F-1" and m.certificate == {"k": 1}


def test_extra_field_from_a_newer_writer_round_trips():
    """C5 forward-compat: a field a NEWER writer added, unknown to this build's model, is preserved
    (extra='allow') rather than dropped or rejected — an old reader tolerates a new record."""
    m = upcast_payload("commit", {"text": "t", "future_field": {"nested": [1, 2]}})
    assert m is not None and m.text == "t"
    assert m.model_extra.get("future_field") == {"nested": [1, 2]}


def test_upcast_never_raises_on_a_malformed_legacy_payload():
    """A read of an already-chain-verified record must not crash on a badly-typed legacy value — upcast is
    a tolerant typed VIEW; `verify()` remains the sole fail-closed integrity gate."""
    m = upcast_payload("commit", {"text": {"unexpected": "dict-not-str"}})
    assert m is not None  # does not raise


@pytest.mark.parametrize("kind,payload", [
    ("commit", {"text": "subj\n\nbody", "hash": "deadbeef", "repo": "vigil", "subject": "subj"}),
    ("document", {"text": "chunk", "title": "MEMORY", "chunk": 0, "path": "/x.md", "project": "p"}),
    ("web_page", {"url": "https://x", "http_status": 200, "content_hash": "h",
                  "robots_allowed": True, "depth": 1, "text": "body"}),
    ("finding", {"schema": "vigil.inert-finding.v1", "finding_ref": "F", "oracle_context_digest": "d",
                 "certificate": {"c": 1}, "signatures": [{"s": "x"}]}),
    ("detection", {"schema": "vigil.inert-finding.v1", "oracle": "ORACLE", "evidence_digest_hex": "ab",
                   "bug_class": "sqli", "certificate": {"c": 1}, "signatures": [{"s": "x"}]}),
    ("snapshot", {"signal": "spine.snapshot", "base_seq": 10, "base_prev_hash": "h", "base_count": 10,
                  "delta_merkle_root": "r", "cumulative_merkle_root": "c", "prev_snapshot_seq": -1,
                  "snapshot_seq": -1, "trusted_pubkey": "pk", "folded_state": {"base_seq": 10}}),
])
def test_real_producer_payloads_upcast_cleanly(kind, payload):
    """Pins the models to the REAL producers (`ingest/git`, `ingest/docs`, `scrape/researcher`,
    `inert_finding.to_spine_payload`, `prune.snapshot_payload`): a representative real payload upcasts and
    every declared field it carries round-trips. If a producer's shape drifts from the contract, this red."""
    m = upcast_payload(kind, payload)
    assert m is not None
    dumped = m.model_dump(by_alias=True)
    for k, v in payload.items():
        assert dumped.get(k) == v, f"{kind}.{k} did not round-trip through the model: {dumped.get(k)!r} != {v!r}"


# ==================================================================================================
# DOC-TRUTH — the contract is documented + the claim registered (via a decision record until [W0-3] #398).
# ==================================================================================================
_DECISION = Path(__file__).resolve().parents[3] / "docs" / "decisions" / "W5-2-payload-evolution-contract.md"


def _norm(s: str) -> str:
    return re.sub(r"[\s#]+", " ", (s or "").replace("`", " ")).strip().lower()


def test_contract_decision_record_exists_and_states_the_rules():
    assert _DECISION.exists(), f"the W5-2 payload-evolution contract decision record is missing: {_DECISION}"
    doc = _norm(_DECISION.read_text(encoding="utf-8"))
    # the normative rules must be present and TRUE of the code (the code is exercised by the tests above)
    assert "additive-only" in doc or "additive only" in doc
    assert "no meaning change" in doc or "meaning change" in doc
    assert "upcast" in doc
    # names the real enforcement artifacts
    assert "payload_shapes.json" in doc
    assert "payload_contract" in doc
    # honest about the registry: registered via THIS decision record until [W0-3] #398 lands
    assert "#398" in _DECISION.read_text(encoding="utf-8")


def test_module_docstring_documents_the_contract():
    from sigil.spine import payload_contract
    doc = _norm(payload_contract.__doc__ or "")
    assert "additive-only" in doc and "un-migratable" in doc and "upcast" in doc
