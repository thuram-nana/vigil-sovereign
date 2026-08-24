"""W5-7 (#451) — the N-1 → N upgrade / rollback + schema-compat HARNESS is real and falsifiable.

The harness (``sigil.spine.upgrade_harness``) ties together W5-1/W5-2's per-record ``schema_version`` +
additive-only payload contract and W5-5's crash-safe migrate/rollback orchestrator into the property that
matters across a release: a spine of realistic OWNER-SIGNED build-(N-1) data upgrades to build N, its owner
signature still verifies over the migrated store, and a rollback restores it with the signature and every
record intact — and the schema changes that made that safe are provably additive-only in BOTH directions.

This suite pins each falsifiable property and proves each gate is not a no-op:

  * ROUNDTRIP — ``run_upgrade_rollback_roundtrip`` on realistic signed data: legacy(N-1) → segment(N) via
    the real ``upgrade()``, the owner signature survives the migration AND the rollback, a mixed {0,1}
    schema-version spine verifies under one head, and every record is preserved through the rollback.
  * COMPAT MATRIX — ``run_compat_matrix`` over the REAL primitives (``from_dict``, ``upcast_payload``,
    ``refuse_newer``, ``diff_shapes``): forward+backward × additive/non-additive, every cell green.
  * NEGATIVE CONTROLS (same run) — a deliberately NON-ADDITIVE schema change makes the harness verdict
    FAIL; the signed-verify gate rejects a corrupted store; ``refuse_newer`` accepts the same version (not
    "refuse always"); and the additive digest exclusion is proven LOAD-BEARING (folding ``schema_version``
    into the digest would break the owner signature).
  * FULL-STACK SOAK — a large multi-segment spine variant, wired to a SCHEDULED job (opt-in via env), so
    the required PR job stays fast + deterministic while the heavier path is honestly labelled, not faked.

Every test FAILS on a pre-W5-7 tree: ``sigil.spine.upgrade_harness`` does not exist, so the module import
errors (observe it: ``git stash`` the module, run this file, see the collection error, ``git stash pop``).

Run: PYTHONPATH=apps/sigil python -m pytest apps/sigil/tests/test_upgrade_harness.py -q
(In CI the required ``SIGIL governor gates (P7 …)`` job runs the whole ``apps/sigil/tests/`` directory.)
"""
from __future__ import annotations

import copy
import os
import re
from pathlib import Path

import pytest

from sigil.spine.models import LEGACY_SCHEMA_VERSION, SCHEMA_VERSION
from sigil.spine.payload_contract import load_committed_shapes
from sigil.spine.store import SpineStore
from sigil.spine.upgrade_harness import (
    CompatCell,
    build_n_minus_1_signed_spine,
    matrix_ok,
    run_compat_matrix,
    run_full_harness,
    run_upgrade_rollback_roundtrip,
    schema_version_is_load_bearing,
    verify_signed_spine,
)


# ====================================================================================================
# ROUNDTRIP — signed N-1 -> N -> rollback
# ====================================================================================================
def test_roundtrip_signature_survives_upgrade_and_rollback_with_data_intact(tmp_path):
    r = run_upgrade_rollback_roundtrip(tmp_path, records=15, n_writer_records=4)
    assert r.ok, r.detail
    # the two version axes moved as intended
    assert r.n_minus_1_layout == "legacy" and r.n_layout == "segment"
    assert set(r.schema_versions_after_n_write) == {LEGACY_SCHEMA_VERSION, SCHEMA_VERSION}
    # the owner SIGNATURE (not just the unkeyed chain) held at every gate
    assert r.signed_before and r.signed_after_upgrade and r.signed_after_rollback
    assert r.signed_mixed_spine, "a mixed {0,1} schema-version spine must verify under one owner signature"
    # the chain verified after the migration and after the rollback, and no record was lost
    assert r.chain_ok_after_upgrade and r.chain_ok_after_rollback
    assert r.data_intact_after_rollback and r.rolled_back_to_legacy
    assert r.count_n_minus_1 == 15


def test_build_n_minus_1_baseline_is_legacy_signed_and_pre_w5_1(tmp_path):
    store, head, kp, tr = build_n_minus_1_signed_spine(tmp_path / "spine", records=6)
    # legacy layout, and EVERY record is a true pre-W5-1 (no schema_version key) record
    from sigil.spine.manifest import read_manifest
    assert read_manifest(store._layout) is None, "build-(N-1) baseline must be the legacy single-file layout"
    assert all(rec.schema_version == LEGACY_SCHEMA_VERSION for rec in store.iter_records())
    ok, why = verify_signed_spine(store, head, tr)
    assert ok, why


# ====================================================================================================
# COMPAT MATRIX — forward/backward × additive/non-additive
# ====================================================================================================
def test_compat_matrix_is_all_green_on_the_live_tree():
    cells = run_compat_matrix()
    assert matrix_ok(cells), [c for c in cells if not c.ok]
    # the matrix actually spans both directions AND both change kinds (not a degenerate one-cell matrix)
    assert {c.direction for c in cells} == {"forward", "backward"}
    assert {c.change for c in cells} == {"additive", "non-additive"}
    # a forward non-additive cell (refuse-newer) and a backward additive cell (legacy read) both exist
    assert any(c.direction == "forward" and c.change == "non-additive" and c.expected == "refused"
               for c in cells)
    assert any(c.direction == "backward" and c.change == "additive" and c.expected == "compatible"
               for c in cells)


def test_full_harness_verdict_is_green_on_the_live_tree(tmp_path):
    result = run_full_harness(tmp_path, records=12)
    assert result.ok, result.detail
    assert result.roundtrip.ok and matrix_ok(list(result.matrix))
    assert result.contract_breaking == ()


# ====================================================================================================
# NEGATIVE CONTROLS — each proves a gate is not a no-op, in the SAME run
# ====================================================================================================
def test_negative_control_a_non_additive_schema_change_makes_the_harness_FAIL(tmp_path):
    """THE acceptance-criterion negative control: a deliberately NON-ADDITIVE schema change (a committed
    field removed) flips the whole-harness verdict to FAIL — proving the harness is a real gate, not a
    rubber stamp. Injected via the override so the live models are untouched."""
    committed = load_committed_shapes()
    broken = copy.deepcopy(committed)
    del broken["snapshot"]["folded_state"]              # remove a security-critical committed field
    result = run_full_harness(tmp_path, records=8, current_shapes_override=broken)
    assert result.ok is False, "a non-additive schema change MUST make the harness fail"
    assert any("snapshot.folded_state" in b and "REMOVED" in b for b in result.contract_breaking), \
        result.contract_breaking
    # and the corresponding matrix cell flipped from its 'compatible' expectation to a mismatch
    assert any(c.change == "non-additive" and not c.ok for c in result.matrix)


def test_negative_control_a_retyped_field_also_makes_the_harness_FAIL(tmp_path):
    committed = load_committed_shapes()
    broken = copy.deepcopy(committed)
    broken["snapshot"]["base_seq"]["type"] = "str"      # int -> str: a C2 meaning change
    result = run_full_harness(tmp_path, records=6, current_shapes_override=broken)
    assert result.ok is False
    assert any("base_seq" in b and "type changed" in b for b in result.contract_breaking)


def test_negative_control_signed_verify_gate_rejects_a_corrupted_store(tmp_path):
    """The roundtrip's per-gate check (``verify_signed_spine``) is not a rubber stamp: corrupt a record's
    payload (same length → still valid JSON, but no longer hashes to its cert_digest) and the gate fails."""
    store, head, kp, tr = build_n_minus_1_signed_spine(tmp_path / "spine", records=8)
    ok, _ = verify_signed_spine(store, head, tr)
    assert ok, "precondition: the pristine signed spine verifies"

    data = tmp_path / "spine" / "spine.jsonl"
    lines = data.read_bytes().splitlines(keepends=True)
    assert b"compressible" in lines[3]
    lines[3] = lines[3].replace(b"compressible", b"CORRUPTED123", 1)
    data.write_bytes(b"".join(lines))

    ok, why = verify_signed_spine(SpineStore(str(data)), head, tr)
    assert ok is False and "chain integrity" in why, why


def test_negative_control_refuse_newer_accepts_the_same_version(tmp_path):
    """The forward non-additive cell proves refuse-newer REJECTS a newer artifact; its additive sibling
    proves it ACCEPTS the same version — together they show the gate is not 'refuse always'."""
    cells = run_compat_matrix()
    same_version = [c for c in cells if c.subject.startswith("a same-version versioned artifact")]
    newer = [c for c in cells if "newer than this build is refused" in c.subject]
    assert same_version and same_version[0].observed == "compatible"
    assert newer and newer[0].observed == "refused"


def test_negative_control_schema_version_exclusion_is_load_bearing(tmp_path):
    """The upgrade is safe *because* ``schema_version`` is excluded from the digest. Prove that exclusion is
    load-bearing: for a real record, the true cert_digest equals the digest WITHOUT schema_version, and a
    hypothetical NON-ADDITIVE change that folded it IN would produce a DIFFERENT digest — which would break
    the owner signature and be caught. (A future edit that digested schema_version fails this.)"""
    store, _head, _kp, _tr = build_n_minus_1_signed_spine(tmp_path / "spine", records=5)
    recs = list(store.iter_records())
    assert recs
    assert all(schema_version_is_load_bearing(r) for r in recs)


# ====================================================================================================
# FULL-STACK SOAK — heavier multi-segment variant, wired to a SCHEDULED job (opt-in via env), NOT the
# required PR job. Honestly labelled: it skips (never silently passes) unless explicitly enabled.
# ====================================================================================================
@pytest.mark.skipif(
    not os.environ.get("VIGIL_UPGRADE_HARNESS_SOAK"),
    reason="heavier multi-segment soak — runs only in the scheduled upgrade-harness-soak job "
           "(set VIGIL_UPGRADE_HARNESS_SOAK=1); the required PR job runs the fast deterministic core above")
def test_fullstack_soak_large_multisegment_spine(tmp_path):
    """A large spine that forces MANY sealed segments + real gzip compaction across the migration — the
    same falsifiable properties as the fast roundtrip, at a scale too slow for the required PR job."""
    result = run_full_harness(tmp_path, records=3000, n_writer_records=50, seg_max_records=200)
    assert result.ok, result.detail
    assert result.roundtrip.n_layout == "segment"
    assert result.roundtrip.count_n_minus_1 == 3000


# ====================================================================================================
# DOC-TRUTH — the harness is documented and its claim registered
# ====================================================================================================
_REPO = Path(__file__).resolve().parents[3]
_DECISION = _REPO / "docs" / "decisions" / "W5-7-upgrade-rollback-harness.md"


def _norm(s: str) -> str:
    return re.sub(r"[\s#]+", " ", (s or "").replace("`", " ")).strip().lower()


def test_decision_record_exists_and_states_the_harness_properties():
    assert _DECISION.exists(), f"the W5-7 harness decision record is missing: {_DECISION}"
    doc = _norm(_DECISION.read_text(encoding="utf-8"))
    assert "n-1" in doc and "rollback" in doc
    assert "owner signature" in doc or "signed" in doc
    assert "additive" in doc
    assert "upgrade_harness" in doc


def test_module_docstring_documents_the_harness():
    from sigil.spine import upgrade_harness
    doc = _norm(upgrade_harness.__doc__ or "")
    assert "n-1" in doc and "rollback" in doc and "additive" in doc


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
