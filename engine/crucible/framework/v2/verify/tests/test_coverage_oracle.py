"""
verify.coverage_oracle (TRUTHENOVATION M2) — the SIGNED coverage / completeness certificate.

These tests prove the M2 property end to end against the deterministic benchmark app:
the certificate distinguishes exercised-AND-oracle-adjudicated-clean from
payload-sent-but-no-oracle-ran, is byte-deterministic, and is tamper-evident under an
out-of-band trust-root pin. The honesty rule (a surface is `clean` ONLY when an
applicable oracle actually ran) is asserted at the decision function AND on real scans.
"""

from __future__ import annotations

import json

import pytest
from vigil_core import generate_keypair

from framework.v2.eval.benchmark_app import serve
from framework.v2.eval.benchmark_run import loopback_send, _scorecard_fingerprint
from framework.v2.report import standards
from framework.v2.scanner.campaign import WebScanCampaign
from framework.v2.scanner.engine import probe_verdict
from framework.v2.scanner.insertion import InsertionKind
from framework.v2.verify import coverage_oracle as co
from framework.v2.verify.models import OracleKind, OracleSignal, VerificationResult


def _scan():
    """One real scan of the benchmark app → its ScanReport (with exercised_probes)."""
    with serve() as base:
        return WebScanCampaign(
            loopback_send, max_pages=25, max_depth=4, enable_oob=False,
            insertion_kinds=(InsertionKind.QUERY_VALUE,),
        ).run(base)


@pytest.fixture(scope="module")
def report():
    return _scan()


@pytest.fixture(scope="module")
def cert(report):
    return co.build_coverage_certificate(
        report, max_pages=25, max_depth=4, budget_exhausted=False)


# ---------------------------------------------------------------------------
# (a) a planted class at a reached surface → verdict "finding"
# ---------------------------------------------------------------------------
def test_planted_class_is_a_finding_in_the_cert(cert):
    findings = {(r["class"], r["verdict"]) for r in cert["probes"] if r["verdict"] == "finding"}
    classes = {c for c, _ in findings}
    # boolean_sqli is planted at /users?name in the benchmark corpus.
    assert "boolean_sqli" in classes, classes
    assert cert["summary"]["n_finding"] >= 1
    # every finding row names the oracle kind(s) that ran.
    for r in cert["probes"]:
        if r["verdict"] == "finding":
            assert r["oracle_kinds_run"], r


# ---------------------------------------------------------------------------
# (b) a SAFE control where an applicable oracle RAN → verdict "clean"
# ---------------------------------------------------------------------------
def test_safe_control_with_a_run_oracle_is_clean(cert):
    # /api/health is a SAFE endpoint; a sqli/differential oracle runs on its param and
    # does not fire → the surface is exercised-and-clean, not a finding, not untested.
    clean_health = [
        r for r in cert["probes"]
        if r["verdict"] == "clean" and r["surface"].startswith("/api/health")
    ]
    assert clean_health, "expected a clean-adjudicated probe on the safe /api/health surface"
    for r in clean_health:
        assert r["oracle_kinds_run"], r
    assert cert["summary"]["n_clean"] >= 1


# ---------------------------------------------------------------------------
# (c) THE honesty rule — no surface is "clean" unless an oracle actually ran
# ---------------------------------------------------------------------------
def test_no_clean_without_an_oracle_that_ran(report, cert):
    # On real probes: every clean/finding verdict is backed by a run oracle; only an
    # inconclusive verdict may (must) have no oracle_kinds_run.
    for p in report.exercised_probes:
        if p.verdict in ("clean", "finding"):
            assert p.oracle_kinds_run, p
        else:
            assert p.verdict == "inconclusive"
    for r in cert["probes"]:
        if r["verdict"] in ("clean", "finding"):
            assert r["oracle_kinds_run"], r


def test_probe_verdict_decision_rule():
    # confirmed → finding
    fired = OracleSignal(kind=OracleKind.DIFFERENTIAL_RESPONSE, fired=True, confidence=0.95)
    assert probe_verdict(VerificationResult(
        confirmed=True, bug_class="boolean_sqli", signals=[fired]))[0] == "finding"
    # ONE-SIDED oracle ran but did not fire with NO observable channel (a single-shot
    # differential over indistinguishable responses) → INCONCLUSIVE, never clean: it
    # cannot tell 'safe' from 'blind/inert'. This is the honesty line M2 must hold —
    # a non-conclusive non-signal is not 'provably-tested-clean'.
    ran = OracleSignal(kind=OracleKind.DIFFERENTIAL_RESPONSE, fired=False, confidence=0.0)
    assert ran.conclusive is False
    verdict, kinds = probe_verdict(VerificationResult(
        confirmed=False, bug_class="boolean_sqli", signals=[ran]))
    assert verdict == "inconclusive" and kinds == ()
    # a CHANNEL-CONFIRMED negative (conclusive=True — e.g. a definite predicate over the
    # observed response, or a payload seen reaching an inert sink) → clean.
    concl = OracleSignal(kind=OracleKind.ACHIEVED_STATE, fired=False, confidence=0.0,
                         conclusive=True)
    verdict, kinds = probe_verdict(VerificationResult(
        confirmed=False, bug_class="open_redirect", signals=[concl]))
    assert verdict == "clean" and kinds == ("achieved_state",)
    # a fired signal is conclusive by construction (the validator enforces it).
    assert fired.conclusive is True
    # payload sent but NO oracle adjudicated (no signals) → inconclusive, NEVER clean
    verdict, kinds = probe_verdict(VerificationResult(
        confirmed=False, bug_class="xss", signals=[]))
    assert verdict == "inconclusive" and kinds == ()


# ---------------------------------------------------------------------------
# (d) determinism — two scans → identical cert canonical bytes
# ---------------------------------------------------------------------------
def test_two_scans_yield_identical_cert_bytes():
    c1 = co.build_coverage_certificate(_scan(), max_pages=25, max_depth=4, budget_exhausted=False)
    c2 = co.build_coverage_certificate(_scan(), max_pages=25, max_depth=4, budget_exhausted=False)
    assert co.canonical_cert_bytes(c1) == co.canonical_cert_bytes(c2)
    # the volatile ephemeral port must not have leaked into the signed bytes.
    assert ":" not in c1["target_host"] or c1["target_host"] == ""
    for r in c1["probes"]:
        assert "http://" not in r["surface"] and "127.0.0.1" not in r["surface"]


def test_scope_and_caps_are_in_the_signed_bytes(cert):
    assert cert["schema"] == co.SCHEMA
    assert "NOT proof of surface completeness" in cert["scope"]
    denom = cert["denominator"]
    for k in ("surfaces_reached", "insertion_points_probed", "distinct_classes_probed",
              "frontier_truncated", "max_pages", "max_depth", "budget_exhausted"):
        assert k in denom
    assert denom["max_pages"] == 25 and denom["max_depth"] == 4


# ---------------------------------------------------------------------------
# (e) sign + offline-verify roundtrip; flipped byte → False; fresh-key resign rejected
# ---------------------------------------------------------------------------
def test_sign_verify_roundtrip_and_tamper_and_pin(cert, tmp_path):
    path = tmp_path / "coverage-cert.json"
    owner = generate_keypair()
    authz = [{"key_id": "owner", "public_key_b64": owner.public_key_b64}]
    pin = _scorecard_fingerprint(authz)
    sig = co.sign_coverage_certificate(
        cert, path, signers=[("owner", owner.private_key_b64)], authorizers=authz, threshold=1)
    assert co.verify_coverage_certificate(path, sig, trust_root_fingerprint=pin) is True

    # flipped byte → digest changes → fail-closed
    raw = json.loads(path.read_text())
    raw["summary"]["n_clean"] = int(raw["summary"]["n_clean"]) + 1
    path.write_text(json.dumps(raw))
    assert co.verify_coverage_certificate(path, sig, trust_root_fingerprint=pin) is False

    # fresh-key re-sign of the (restored) cert is rejected by the out-of-band pin
    co.write_coverage_certificate(path, cert)
    attacker = generate_keypair()
    atkz = [{"key_id": "attacker", "public_key_b64": attacker.public_key_b64}]
    sig2 = co.sign_coverage_certificate(
        cert, path, signers=[("attacker", attacker.private_key_b64)], authorizers=atkz, threshold=1)
    # internally self-consistent (no pin) but rejected against the owner pin
    assert co.verify_coverage_certificate(path, sig2) is True
    assert co.verify_coverage_certificate(path, sig2, trust_root_fingerprint=pin) is False


# ---------------------------------------------------------------------------
# (f) the starved distinction is now reachable — a probed class grades tested_clear
# ---------------------------------------------------------------------------
def test_coverage_matrix_tested_clear_is_reachable(report):
    tested = co.tested_bug_classes(report.exercised_probes)
    assert "xss" in tested  # probed clean on the safe surfaces
    with_tested = standards.coverage_matrix([], tested_bug_classes=tested)
    without = standards.coverage_matrix([])
    assert with_tested["summary"]["total"]["tested_clear"] > 0
    assert without["summary"]["total"]["tested_clear"] == 0
    # a control an untested class maps to stays not_tested (no coverage implied).
    # xss → OWASP A03; assert that same cell is tested_clear only WITH the probed set.
    a03_with = with_tested["frameworks"]["owasp"].get("A03:2021", {}).get("status")
    a03_without = without["frameworks"]["owasp"].get("A03:2021", {}).get("status")
    assert a03_with == "tested_clear" and a03_without == "not_tested"


def test_inconclusive_class_is_not_tested_clean():
    # an inconclusive-only probe set must NOT feed tested_bug_classes (no oracle ran).
    class _P:
        def __init__(self, v, bc):
            self.verdict, self.bug_class = v, bc
    probes = [_P("inconclusive", "ssrf"), _P("clean", "xss"), _P("finding", "boolean_sqli")]
    assert co.tested_bug_classes(probes) == ["boolean_sqli", "xss"]
