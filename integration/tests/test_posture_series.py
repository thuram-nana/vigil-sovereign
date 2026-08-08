"""P3 — the continuous posture re-proof SERIES: a signed, anti-rollback attestation chain of posture
certificates. Appending grows a hash-chained, governance-signed series; the series verifies end-to-end;
a rollback/truncation is refused; and N deterministic cycles produce identical chain digests.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from vigil_core.capability import sign_identity_attestation
from vigil_core.crypto import generate_keypair
from vigil_core.models import AuthorizerKey, TrustRoot
from vigil_integration.posture.certificate import build_posture_certificate
from vigil_integration.posture.reprove import run_posture_reprove
from vigil_integration.posture.series import (
    PostureSeriesError,
    append_posture_tick,
    verify_posture_series,
)

GOV = generate_keypair()
OWNER = generate_keypair()
SIGNERS = [("posture-gov", GOV.private_key_b64)]
TRUST = TrustRoot(threshold=1, authorizers=[
    AuthorizerKey(key_id="posture-gov", name="posture-gov", public_key_b64=GOV.public_key_b64)])


def _coverage(host: str = "127.0.0.1") -> dict:
    return {
        "schema": "vigil-coverage-certificate/1", "scope": "reached-surface coverage", "target_host": host,
        "denominator": {"surfaces_reached": 1, "insertion_points_probed": 1, "distinct_classes_probed": 1,
                        "frontier_truncated": 0, "max_pages": 25, "max_depth": 4, "budget_exhausted": False},
        "probes": [{"surface": "/", "insertion_point": "query", "param": "q", "check_id": "x",
                    "class": "reflected_xss", "verdict": "clean", "oracle_kinds_run": ["reflection"]}],
        "summary": {"n_finding": 0, "n_clean": 1, "n_inconclusive": 0},
    }


def _cert(tag: str = "a") -> dict:
    att = sign_identity_attestation(OWNER, engagement="demo", policy={"host": ["127.0.0.1"]},
                                    not_after=9_999_999_999)
    return build_posture_certificate(_coverage(), target_identity=att,
                                     target_sample={"host": "127.0.0.1"}, residual=f"residual-{tag}")


def test_append_grows_a_verifiable_series(tmp_path: Path):
    d = tmp_path / "series"
    for tag in ("a", "b", "c"):
        head = append_posture_tick(d, _cert(tag), engagement_slug="demo", signers=SIGNERS)
    assert head.entry_count == 3
    ok, reason = verify_posture_series(d, TRUST)
    assert ok is True, reason
    assert "3 tick" in reason


def test_run_posture_reprove_appends_n_witnessed_ticks(tmp_path: Path):
    d = tmp_path / "series"
    res = run_posture_reprove(d, cycles=3, owner_key=OWNER, gov_key=GOV, engagement="demo",
                              interval=0.0, sleep=lambda _s: None, build_cert=lambda: _cert("z"))
    assert res["cycles"] == 3 and res["entry_count"] == 3
    ok, _ = verify_posture_series(d, TRUST)
    assert ok is True


def test_deterministic_two_runs_identical_head(tmp_path: Path):
    a = run_posture_reprove(tmp_path / "A", cycles=2, owner_key=OWNER, gov_key=GOV, engagement="demo",
                            sleep=lambda _s: None, build_cert=lambda: _cert("d"))
    b = run_posture_reprove(tmp_path / "B", cycles=2, owner_key=OWNER, gov_key=GOV, engagement="demo",
                            sleep=lambda _s: None, build_cert=lambda: _cert("d"))
    assert a["head_hash"] == b["head_hash"] and a["head_hash"]  # nothing wallclock/rng in the signed chain


def test_rollback_is_refused(tmp_path: Path):
    d = tmp_path / "series"
    for tag in ("a", "b", "c"):
        append_posture_tick(d, _cert(tag), engagement_slug="demo", signers=SIGNERS)
    # a durable floor higher than the series (a rollback/truncation attempt) → fail-closed
    ok, reason = verify_posture_series(d, TRUST, prev_highwater={"entry_count": 99, "last_seq": 98})
    assert ok is False and "head" in reason


def test_tampered_tick_breaks_the_series(tmp_path: Path):
    d = tmp_path / "series"
    for tag in ("a", "b"):
        append_posture_tick(d, _cert(tag), engagement_slug="demo", signers=SIGNERS)
    # flip a byte in a persisted tick certificate → its digest no longer matches the signed chain
    tick0 = d / "ticks" / "0.json"
    doc = json.loads(tick0.read_text())
    doc["summary"]["n_closed"] = 999
    tick0.write_text(json.dumps(doc))
    ok, reason = verify_posture_series(d, TRUST)
    assert ok is False and "does not match its chain digest" in reason
