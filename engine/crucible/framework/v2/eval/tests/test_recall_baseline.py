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
    TRUST_ROOT_FINGERPRINT,
    build_accuracy_core,
    canonical_bytes,
    crucible_recall,
    verify_committed_recall_baseline,
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
    """(c) The committed signature verifies offline against the committed JSON — through the
    PINNED verify path (the trust root is checked against the source-held out-of-band pin,
    not taken from the signature file)."""
    assert verify_committed_recall_baseline() is True
    # the committed fingerprint.txt equals the source-held pin (no in-band drift)
    committed_fp = ACCURACY_CORE_PATH.with_suffix(".fingerprint.txt").read_text().strip()
    assert committed_fp == TRUST_ROOT_FINGERPRINT


def test_flipped_number_breaks_verification(tmp_path) -> None:
    """(d) A single flipped number invalidates the signature (tamper-evidence)."""
    core = _committed_core()
    core["results"][0]["recall"] = 0.5  # a lie about coverage
    tampered = tmp_path / "recall-accuracy-core.json"
    tampered.write_bytes(canonical_bytes(core))
    assert verify_committed_recall_baseline(tampered, _committed_sig()) is False


def test_forged_resign_with_fresh_key_is_rejected_by_the_pin(tmp_path) -> None:
    """(d') The trust root is PINNED out of band. A repo-write adversary who flips a number,
    mints a FRESH keypair, re-signs the tampered bytes, and embeds that fresh key as the
    authorizer produces a sig that is internally self-consistent — verify WITHOUT the pin
    would accept it — but the pinned verify path rejects it because the forged authorizer set
    hashes to a different fingerprint than the source-held pin."""
    import hashlib

    from vigil_core import canonical_json, generate_keypair, sign

    core = _committed_core()
    core["results"][0]["recall"] = 0.42  # the lie
    tampered = tmp_path / "recall-accuracy-core.json"
    tampered.write_bytes(canonical_bytes(core))
    body = canonical_bytes(core)

    kp = generate_keypair()  # the forger's OWN key — never authorized out of band
    forged_sig = {
        "schema": "vigil-benchmark-scorecard-sig/1",
        "scorecard": "recall-accuracy-core.json",
        "scorecard_digest": "sha256:" + hashlib.sha256(body).hexdigest(),
        "threshold": 1,
        "trust_root": {"threshold": 1, "authorizers": [
            {"key_id": "recall-baseline-owner", "public_key_b64": kp.public_key_b64}]},
        "signatures": [{"key_id": "recall-baseline-owner",
                        "signature_b64": sign(kp.private_key_b64, body)}],
    }
    # Without a pin the forgery is self-consistent and would pass (the old, broken behaviour).
    assert verify_scorecard(tampered, forged_sig) is True
    # With the out-of-band pin enforced, the forged trust root is rejected outright.
    assert verify_scorecard(tampered, forged_sig,
                            trust_root_fingerprint=TRUST_ROOT_FINGERPRINT) is False
    assert verify_committed_recall_baseline(tampered, forged_sig) is False


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
