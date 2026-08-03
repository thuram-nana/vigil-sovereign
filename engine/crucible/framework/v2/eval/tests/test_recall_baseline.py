"""
Tests for the DETERMINISTIC, signed, committed recall baseline (TRUTHENOVATION M1).

These assert the honesty properties the baseline stakes its credibility on:

  (a) the deterministic scanner over the broadened planted corpus REPRODUCES the
      committed accuracy-core document byte-for-byte;
  (b) CRUCIBLE's recall equals the committed value and precision is 1.0 (the SAFE
      controls stay clean);
  (c) the committed signature verifies OFFLINE against the committed JSON;
  (d) a single flipped number BREAKS verification (tamper-evidence);
  (e) determinism — two independent scans yield identical canonical bytes.

Scope note (kept honest): this is the recall of the DETERMINISTIC scanner on a
planted loopback corpus for the on-path classes, NOT LLM-engage recall.
"""

from __future__ import annotations

import json

from vigil_core import canonical_json

from framework.v2.eval.benchmark_run import verify_scorecard
from framework.v2.eval.recall_baseline import (
    ACCURACY_CORE_PATH,
    SCHEMA,
    build_accuracy_core,
    canonical_bytes,
    crucible_recall,
)


def _committed_core() -> dict:
    return json.loads(ACCURACY_CORE_PATH.read_bytes())


def _committed_sig() -> dict:
    return json.loads(ACCURACY_CORE_PATH.with_suffix(".sig.json").read_bytes())


def test_committed_accuracy_core_is_byte_identically_reproduced() -> None:
    """(a) A fresh deterministic scan re-derives the exact committed bytes."""
    committed_bytes = ACCURACY_CORE_PATH.read_bytes()
    rebuilt = build_accuracy_core()
    assert canonical_bytes(rebuilt) == committed_bytes
    # the on-disk file is itself canonical (no drift between write and re-derive)
    assert canonical_json(json.loads(committed_bytes)) == committed_bytes


def test_committed_recall_and_precision() -> None:
    """(b) CRUCIBLE recall matches the committed value and precision is perfect."""
    core = _committed_core()
    assert core["schema"] == SCHEMA
    row = next(r for r in core["results"] if r["tool"] == "crucible")
    # the corpus is fully solved by the deterministic scanner for the on-path classes
    assert row["recall"] == 1.0
    assert row["precision"] == 1.0
    assert row["fp"] == 0
    assert row["fn"] == 0
    assert row["tp"] == core["ground_truth_count"] == 11
    # the freshly measured recall agrees with the committed number
    assert crucible_recall(build_accuracy_core()) == row["recall"]


def test_broadened_planted_classes_present() -> None:
    """The broadened corpus carries the newly-added on-path classes."""
    core = _committed_core()
    assert {"ssti", "host_header_injection"} <= set(core["planted_classes"])
    assert len(core["planted_classes"]) == 9  # distinct classes over 11 bugs


def test_committed_signature_verifies_offline() -> None:
    """(c) The committed signature verifies offline against the committed JSON."""
    assert verify_scorecard(ACCURACY_CORE_PATH, _committed_sig()) is True


def test_flipped_number_breaks_verification(tmp_path) -> None:
    """(d) A single flipped number invalidates the signature (tamper-evidence)."""
    core = _committed_core()
    core["results"][0]["recall"] = 0.5  # a lie about coverage
    tampered = tmp_path / "recall-accuracy-core.json"
    tampered.write_bytes(canonical_bytes(core))
    assert verify_scorecard(tampered, _committed_sig()) is False


def test_determinism_two_runs_identical() -> None:
    """(e) Two independent deterministic scans produce identical canonical bytes."""
    assert canonical_bytes(build_accuracy_core()) == canonical_bytes(build_accuracy_core())


def test_private_key_is_not_committed() -> None:
    """The signing PRIVATE key must never be tracked in the repo — only the public
    authorizer (embedded in the .sig.json) + the fingerprint are committed."""
    import subprocess

    priv = ACCURACY_CORE_PATH.with_suffix(".privkey")
    cwd = str(ACCURACY_CORE_PATH.parent)  # git resolves the repo from any subdir
    # It must never be a tracked file: `git ls-files --error-unmatch` exits non-zero
    # for an untracked/ignored path.
    tracked = subprocess.run(
        ["git", "ls-files", "--error-unmatch", str(priv)],
        cwd=cwd, capture_output=True, text=True,
    )
    assert tracked.returncode != 0, "the signing private key is TRACKED in git"
    # And the path is explicitly gitignored (belt and suspenders).
    ignored = subprocess.run(
        ["git", "check-ignore", str(priv)], cwd=cwd, capture_output=True, text=True,
    )
    assert ignored.returncode == 0, "the .privkey path is not gitignored"
