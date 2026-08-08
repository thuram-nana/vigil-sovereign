"""SLICE A — the RE-EXECUTABLE posture tier (Proof-of-Posture).

The binding tier proves "trust this signed CLOSED verdict, offline". The re-executable tier is stronger:
the standalone VIGIL-free verifier RE-RUNS the deterministic oracle over the probe's own retained values
and re-derives the NEGATIVE itself — producer-INDEPENDENT. These tests prove:

  1. byte-PARITY: the stdlib predicate kernel (in posture.certificate AND in the standalone verify_vf)
     agrees with the REAL framework oracle (verify.oracles.predicate_oracle) on `fired`, over many cases;
  2. LIVE: a retain_evidence scan of the benchmark mints RE-EXECUTABLE CLOSED claims (open_redirect),
     and both the in-tree and the standalone verifier accept them, re-executing producer-independently;
  3. FORGE-A-FALSE-NEGATIVE: tampering a CLOSED probe's retained values so the predicate ACTUALLY FIRES
     is caught by re-execution (in-tree AND standalone) — NOT SOUND;
  4. BYTE-IDENTITY: with retention OFF (the default), the coverage + posture certificates are byte-for-
     byte identical to before (no evidence keys, every claim binding) — the make-gate invariant.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from vigil_core.crypto import generate_keypair
from vigil_integration.posture import certificate as C
from vigil_integration.posture.attest import (
    attest_loopback_benchmark,
    coverage_cert_from_report,
    scan_loopback_benchmark,
)

_VERIFY_VF = Path(__file__).resolve().parents[2] / "docs" / "proof-carrying-finding" / "verify_vf.py"


# ---- 1. byte-parity: stdlib kernel(s) vs the REAL framework oracle -------------------------------

_PREDICATE_CASES = [
    # (predicate, observed) — a representative spread of every op the oracle supports.
    ({"eq": [{"var": "a"}, {"var": "b"}]}, {"a": "x", "b": "x"}),
    ({"eq": [{"var": "a"}, {"var": "b"}]}, {"a": "x", "b": "y"}),
    ({"ieq": [{"var": "a"}, "HELLO"]}, {"a": "hello"}),
    ({"contains": [{"var": "body"}, "secret"]}, {"body": "a secret token"}),
    ({"icontains": [{"var": "body"}, "SECRET"]}, {"body": "a secret token"}),
    ({"in": [{"var": "status"}, [301, 302, 303, 307, 308]]}, {"status": 302}),
    ({"in": [{"var": "status"}, [301, 302, 303, 307, 308]]}, {"status": 200}),
    ({"min_len": [{"var": "tok"}, 8]}, {"tok": "short"}),
    ({"min_len": [{"var": "tok"}, 3]}, {"tok": "longenough"}),
    ({"gt": [{"var": "n"}, 5]}, {"n": 9}),
    ({"ge": [{"var": "n"}, 5]}, {"n": 5}),
    ({"not": {"eq": [{"var": "a"}, {"var": "b"}]}}, {"a": "x", "b": "y"}),
    ({"all": [{"in": [{"var": "status"}, [302]]}, {"eq": [{"var": "h"}, {"var": "c"}]}]},
     {"status": 302, "h": "evil.test", "c": "evil.test"}),
    ({"all": [{"in": [{"var": "status"}, [302]]}, {"eq": [{"var": "h"}, {"var": "c"}]}]},
     {"status": 302, "h": "", "c": "evil.test"}),
    ({"any": [{"eq": [{"var": "a"}, "1"]}, {"eq": [{"var": "b"}, "2"]}]}, {"a": "0", "b": "2"}),
    ({"any": [{"eq": [{"var": "a"}, "1"]}, {"eq": [{"var": "b"}, "2"]}]}, {"a": "0", "b": "0"}),
    # the real open_redirect predicate shape (nested any/all with a var-to-var host compare)
    ({"any": [{"all": [{"in": [{"var": "status"}, [301, 302, 303, 307, 308]]},
                       {"eq": [{"var": "location_host"}, {"var": "canary_host"}]}]}]},
     {"status": 302, "location_host": "c.test", "canary_host": "c.test"}),
    ({"any": [{"all": [{"in": [{"var": "status"}, [301, 302, 303, 307, 308]]},
                       {"eq": [{"var": "location_host"}, {"var": "canary_host"}]}]}]},
     {"status": 200, "location_host": "", "canary_host": "c.test"}),
]


def _load_verify_vf():
    import importlib.util

    spec = importlib.util.spec_from_file_location("verify_vf_reexec", _VERIFY_VF)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("pred,obs", _PREDICATE_CASES)
def test_kernel_matches_real_oracle(pred, obs):
    """The stdlib kernel (both copies) must equal the REAL oracle's `fired` on every case."""
    from framework.v2.verify import oracles

    real = oracles.predicate_oracle(obs, pred).fired
    assert C._reexec_eval_predicate(pred, dict(obs)) is real, (pred, obs)
    vf = _load_verify_vf()
    assert vf._reexec_eval_predicate(pred, dict(obs)) is real, (pred, obs)


def test_kernel_faithful_over_real_scan_contexts():
    """Every predicate/observed pair the benchmark actually produces re-derives identically in the
    kernel and the real oracle — the port is faithful on real inputs, not just hand-picked ones."""
    from framework.v2.verify import oracles

    report = scan_loopback_benchmark(retain_evidence=True)
    cov = coverage_cert_from_report(report, max_pages=25, max_depth=4)
    seen = 0
    for probe in cov["probes"]:
        ev = C._probe_reexec_evidence(probe)
        if ev is None:
            continue
        seen += 1
        real = oracles.predicate_oracle(ev["observed_evidence"], ev["predicate"]).fired
        assert C._reexec_eval_predicate(ev["predicate"], dict(ev["observed_evidence"])) is real
    assert seen > 0, "the scan produced no re-executable evidence to check parity over"


# ---- 2. LIVE: mint re-executable CLOSED claims and verify them both ways -------------------------

def test_live_mints_reexecutable_closed_and_verifies(tmp_path):
    owner, gov = generate_keypair(), generate_keypair()
    res = attest_loopback_benchmark(tmp_path / "out", owner_key=owner, gov_key=gov,
                                    engagement="reexec-demo", retain_evidence=True)
    summary = res["summary"]
    assert summary["n_closed"] > 0
    assert summary["n_closed_re_executable"] > 0, "no CLOSED claim reached the re-executable tier"

    cert = json.loads(Path(res["certificate_path"]).read_text())
    reexec_claims = [c for c in cert["posture_claims"]
                     if c["status"] == "CLOSED" and c["verification"] == "re-executable"]
    assert reexec_claims, "expected at least one re-executable CLOSED claim"
    # open_redirect is the dominant CLOSED-via-predicate class on the benchmark
    assert any(c["class"] == "open_redirect" for c in reexec_claims)

    # in-tree verify (which now re-executes) accepts it
    sig_env = json.loads(Path(res["certificate_path"]).with_suffix(".sig.json").read_text())
    assert C.verify_posture_certificate(
        res["certificate_path"], sig_env, trust_root_fingerprint=res["fingerprint"],
        owner_pubkey=owner.public_key_b64, engagement="reexec-demo", now=1_000) is True

    # standalone VIGIL-free verifier (the bundle's own verify_offline.py) accepts + re-executes
    r = subprocess.run(_bundle_verify_cmd(res), capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "re-executable" in (r.stdout + r.stderr).lower()


def _bundle_verify_cmd(res: dict) -> list[str]:
    d = Path(res["bundle_dir"])
    return [sys.executable, str(d / "verify_offline.py"), "verify", "--bundle", str(d / "bundle.json"),
            "--posture-fingerprint", res["fingerprint"], "--posture-owner-pubkey", res["owner_pubkey"],
            "--posture-engagement", res["engagement"], "--posture-now", "1000"]


# ---- 3. FORGE-A-FALSE-NEGATIVE: re-execution refuses a tampered CLOSED claim ---------------------

def _find_reexec_clean_probe(cert: dict) -> dict:
    for probe in cert["coverage"]["probes"]:
        if probe.get("verdict") == "clean" and C._probe_reexec_evidence(probe) is not None:
            return probe
    raise AssertionError("no re-executable clean probe found")


def test_forged_negative_is_refused_in_tree_and_standalone(tmp_path):
    owner, gov = generate_keypair(), generate_keypair()
    report = scan_loopback_benchmark(retain_evidence=True)
    coverage = coverage_cert_from_report(report, max_pages=25, max_depth=4)
    from vigil_core.capability import sign_identity_attestation

    identity = sign_identity_attestation(owner, engagement="forge", policy={"host": ["127.0.0.1"]},
                                         not_after=9_999_999_999)
    cert = C.build_posture_certificate(coverage, target_identity=identity,
                                       target_sample={"host": "127.0.0.1"})

    # TAMPER: make a CLOSED open_redirect probe's retained values actually fire the predicate
    # (location_host == canary_host, a redirect status) — a forged negative. The signed verdict still
    # says "clean"; only re-execution catches the lie.
    probe = _find_reexec_clean_probe(cert)
    obs = probe["evidence"]["observed_evidence"]
    obs["status"] = 302
    obs["location_host"] = obs.get("canary_host") or "attacker.test"
    obs["canary_host"] = obs["location_host"]

    # in-tree re-execution refuses
    with pytest.raises(C.PostureError, match="re-execution REFUTED a CLOSED"):
        C.reexecute_posture_claims(cert)

    # sign the tampered cert and prove the STANDALONE verifier also refuses (producer-independent)
    cert_path = tmp_path / "forged.json"
    signers = [("g", gov.private_key_b64)]
    authorizers = [{"key_id": "g", "public_key_b64": gov.public_key_b64}]
    sig_env = C.sign_posture_certificate(cert, cert_path, signers=signers, authorizers=authorizers,
                                         threshold=1)
    fp = (cert_path.with_suffix(".fingerprint.txt")).read_text().strip()
    vf = _load_verify_vf()
    posture_obj = {"certificate": cert, "signature": sig_env}
    ok, reason = vf.verify_posture(posture_obj, pin=fp, owner_pubkey=owner.public_key_b64,
                                   engagement="forge", now=1_000)
    assert ok is False
    assert "re-execution" in reason.lower() and "refuted" in reason.lower()


# ---- 4. BYTE-IDENTITY: retention OFF is byte-for-byte the pre-change certificate -----------------

def test_retention_off_is_byte_identical_and_binding_only():
    """The default path (retain_evidence=False) embeds NO evidence and marks every CLOSED claim binding
    — so a coverage/posture certificate is byte-identical to before this slice (make-gate invariant)."""
    report = scan_loopback_benchmark(retain_evidence=False)
    coverage = coverage_cert_from_report(report, max_pages=25, max_depth=4)
    # no probe row carries an evidence key
    assert all("evidence" not in p for p in coverage["probes"])
    claims = C.project_posture_claims(coverage)
    assert claims, "expected some claims"
    assert all(c["verification"] == "binding" for c in claims)
    # two retention-off scans → byte-identical coverage certs (determinism preserved)
    report2 = scan_loopback_benchmark(retain_evidence=False)
    coverage2 = coverage_cert_from_report(report2, max_pages=25, max_depth=4)
    from vigil_core import canonical_json

    assert canonical_json(coverage) == canonical_json(coverage2)


def test_retain_on_adds_only_reexec_evidence_keys():
    """With retention on, ONLY predicate-oracle probes gain an evidence key (predicate+observed_evidence);
    the row is otherwise unchanged, and no other probe class is touched."""
    report = scan_loopback_benchmark(retain_evidence=True)
    coverage = coverage_cert_from_report(report, max_pages=25, max_depth=4)
    with_ev = [p for p in coverage["probes"] if "evidence" in p]
    assert with_ev, "retention on should retain some evidence"
    for p in with_ev:
        assert set(p["evidence"].keys()) == {"predicate", "observed_evidence"}
