"""Trust Center — the console's signed-certificate provider (api.certs) + its OFFLINE
verify action (actions.verify_cert).

These assert the load-bearing honesty properties of the "provable" claim made legible:
  * the COMMITTED recall accuracy-core baseline is surfaced AS a certificate — its trust
    root (m-of-n authorizers + threshold), out-of-band fingerprint pin, and signed digest;
  * a live offline verify PASSES for the committed cert AND reports fingerprint-matches-pin;
  * a byte-flipped copy FAILS (tamper-evident: the re-derived digest no longer matches);
  * a fresh-key re-signed copy FAILS AND fingerprint-matches-pin is False (the SOURCE pin
    rejects a forger who re-signs the lie with a key it controls);
  * an unsafe run id is refused fail-closed (no traversal), and the action never takes a
    scope/target (READ/VERIFY-only).
"""

from __future__ import annotations

import shutil
from pathlib import Path

from framework.v2.console import actions, api
from framework.v2.eval import recall_baseline as rb
from framework.v2.eval.benchmark_run import sign_scorecard
from vigil_core import generate_keypair

_BASELINES = Path(rb.ACCURACY_CORE_PATH).parent


def _copy_recall_triple(dst: Path) -> Path:
    """Copy the committed recall core + sig into ``dst`` (a private base the test can mutate)."""
    dst.mkdir(parents=True, exist_ok=True)
    for name in ("recall-accuracy-core.json", "recall-accuracy-core.sig.json"):
        shutil.copy(_BASELINES / name, dst / name)
    return dst / "recall-accuracy-core.json"


# ---------------------------------------------------------------------------
# provider: the committed recall cert is surfaced as a certificate
# ---------------------------------------------------------------------------

def test_certs_surfaces_committed_recall_metadata():
    d = api.certs()
    assert "OFFLINE" in d["doctrine"]
    certs = d["certs"]
    recall = next(c for c in certs if c["kind"] == "recall")
    assert recall["present"] is True
    assert recall["schema"] == "vigil-recall-accuracy-core/1"
    assert str(recall["scorecard_digest"]).startswith("sha256:")
    # trust root: m-of-n authorizers + threshold
    tr = recall["trust_root"]
    assert tr["threshold"] == 1
    assert tr["authorizers"] and tr["authorizers"][0]["key_id"] == "recall-baseline-owner"
    assert tr["authorizers"][0]["public_key_b64"]
    # the OUT-OF-BAND fingerprint pin is present and equals the source-held pin
    assert recall["fingerprint"] == rb.TRUST_ROOT_FINGERPRINT
    assert recall["source_pin"] == rb.TRUST_ROOT_FINGERPRINT
    # the accuracy summary numbers are carried
    res = recall["summary"]["results"][0]
    assert res["tool"] == "crucible" and res["recall"] == 1.0


def test_certs_lists_absent_per_run_cert_as_not_present(tmp_path, monkeypatch):
    # a run whose coverage/plan cert has not been signed is honestly present:false, never faked.
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path / ".console")
    (tmp_path / ".console" / "runs" / "run-x").mkdir(parents=True)
    d = api.certs()
    per_run = [c for c in d["certs"] if c.get("run_id") == "run-x"]
    assert per_run, "expected the known run's certs to be enumerated"
    assert all(c["present"] is False for c in per_run)
    assert all("not yet produced" in (c.get("note") or "") for c in per_run)


# ---------------------------------------------------------------------------
# verify action: PASS on the committed cert, FAIL on tamper / fresh-key
# ---------------------------------------------------------------------------

def test_verify_recall_committed_passes_and_matches_pin():
    r = actions.verify_cert("recall-accuracy-core")
    assert r["verified"] is True
    assert r["present"] is True
    assert r["fingerprint_matches_pin"] is True
    assert r["which_authorizers"] == ["recall-baseline-owner"]
    assert str(r["digest"]).startswith("sha256:")


def test_verify_recall_byte_flip_fails(tmp_path):
    core = _copy_recall_triple(tmp_path / "tamper")
    raw = core.read_bytes()
    # flip a byte inside the signed accuracy numbers — the re-derived digest no longer matches.
    flipped = raw.replace(b'"recall":1.0', b'"recall":0.5', 1)
    assert flipped != raw
    core.write_bytes(flipped)
    r = actions.verify_cert("recall", _recall_base=tmp_path / "tamper")
    assert r["verified"] is False


def test_verify_recall_fresh_key_resign_fails_on_pin(tmp_path):
    base = tmp_path / "forge"
    base.mkdir()
    shutil.copy(_BASELINES / "recall-accuracy-core.json", base / "recall-accuracy-core.json")
    # a forger re-signs the (unchanged) baseline with a FRESH key and embeds it as the authorizer.
    kp = generate_keypair()
    sign_scorecard(base / "recall-accuracy-core.json",
                   signers=[("forger", kp.private_key_b64)],
                   authorizers=[{"key_id": "forger", "public_key_b64": kp.public_key_b64}],
                   threshold=1)
    r = actions.verify_cert("recall", _recall_base=base)
    # the Ed25519 signature is internally valid, but the OOB pin rejects the fresh authorizer set.
    assert r["verified"] is False
    assert r["fingerprint_matches_pin"] is False


def test_verify_cert_refuses_unsafe_run_id():
    r = actions.verify_cert("coverage-certificate.json", "../etc")
    assert r["verified"] is False
    assert "unsafe run id" in r.get("error", "")


def test_verify_cert_unknown_name_is_fail_closed():
    r = actions.verify_cert("not-a-real-cert")
    assert r["verified"] is False
    assert "unknown certificate" in r.get("error", "")
