"""SLICE A — the RE-EXECUTABLE posture tier (Proof-of-Posture).

The binding tier proves "trust this signed CLOSED verdict, offline". The re-executable tier is stronger:
the standalone VIGIL-free verifier RE-DERIVES the verdict by re-running the deterministic oracle over the
probe's own retained values — confirming the verdict is the correct function of that evidence WITHOUT
trusting the producer's asserted verdict. HONEST BOUND: the values are producer-supplied, so this proves
the verdict↔evidence binding, NOT that the evidence is live (trusting the negative reflects reality still
needs a live re-run). These tests prove:

  1. byte-PARITY: the stdlib predicate kernel (in posture.certificate AND in the standalone verify_vf)
     agrees with the REAL framework oracle (verify.oracles.predicate_oracle) on `fired`, over many cases,
     INCLUDING ill-typed children (eager eval + exception→non-conclusive, faithful to the oracle);
  2. LIVE: a retain_evidence scan of the benchmark mints RE-EXECUTABLE CLOSED claims (open_redirect),
     and both the in-tree and the standalone verifier accept them, re-deriving the verdict from evidence;
  3. FORGE-A-FALSE-NEGATIVE: tampering a CLOSED probe's retained values so the predicate ACTUALLY FIRES
     (or becomes non-conclusive) is caught by re-execution (in-tree AND standalone) — NOT SOUND;
  4. BYTE-IDENTITY: with retention OFF (the default), the coverage + posture certificates are byte-for-
     byte identical to before (no evidence keys, every claim binding) — the make-gate invariant;
  5. RED-PEN FIXES: malformed predicates fail CLOSED (not crash); the residual/reason carry the honest
     bound (no 'producer-independent' overclaim).
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

# (predicate, observed, provenance_refs) — a representative spread of every op the oracle supports, pinned
# to the Lane S structural FACT-eligibility grammar. The grammar gates FIRING: a predicate mints (and a
# non-fire is a conclusive clean) ONLY when a firing path carries a positive discriminator (PD2 canary / PD3
# strict floor / PD-NUM / PD-VALUE / PD4 differential). So the parity is proven on BOTH paths:
#   * the REFUSE path — a bare shape with NO provenance-ref and no differential (eq[a,b] a==b, a lone
#     contains/in/ieq against a captured/producer value, min_len, ge-vs-literal, not(...), the canary-less
#     open_redirect all/any) is INELIGIBLE: all three (both kernels AND the real oracle) return `fired=False`,
#     even where a RAW evaluation would have said True (that raw-True-vs-grammar-False gap is exactly what
#     this slice closes);
#   * the FIRE path — a shape with a genuine discriminator fires: gt[n,5] is a PD-VALUE (no canary needed);
#     the real open_redirect canary shape fires once `canary_host` is marked a provenance-ref (PD2), and the
#     same shape over a non-redirect status is eligible-but-non-firing (value-dependent, so still False).
_PREDICATE_CASES = [
    # --- REFUSE path: ineligible bare shapes -> all three agree fired=False (raw eval would over-fire) ---
    ({"eq": [{"var": "a"}, {"var": "b"}]}, {"a": "x", "b": "x"}, {}),
    ({"eq": [{"var": "a"}, {"var": "b"}]}, {"a": "x", "b": "y"}, {}),
    ({"ieq": [{"var": "a"}, "HELLO"]}, {"a": "hello"}, {}),
    ({"contains": [{"var": "body"}, "secret"]}, {"body": "a secret token"}, {}),
    ({"icontains": [{"var": "body"}, "SECRET"]}, {"body": "a secret token"}, {}),
    ({"in": [{"var": "status"}, [301, 302, 303, 307, 308]]}, {"status": 302}, {}),
    ({"in": [{"var": "status"}, [301, 302, 303, 307, 308]]}, {"status": 200}, {}),
    ({"min_len": [{"var": "tok"}, 8]}, {"tok": "short"}, {}),
    ({"min_len": [{"var": "tok"}, 3]}, {"tok": "longenough"}, {}),
    # --- FIRE path: PD-VALUE (a captured quantity strictly over a numeric literal) is eligible, no canary ---
    ({"gt": [{"var": "n"}, 5]}, {"n": 9}, {}),
    # ge-vs-literal is NOT a PD (vacuous at a floor) -> ineligible refuse path even though raw eval is True
    ({"ge": [{"var": "n"}, 5]}, {"n": 5}, {}),
    ({"not": {"eq": [{"var": "a"}, {"var": "b"}]}}, {"a": "x", "b": "y"}, {}),
    ({"all": [{"in": [{"var": "status"}, [302]]}, {"eq": [{"var": "h"}, {"var": "c"}]}]},
     {"status": 302, "h": "evil.test", "c": "evil.test"}, {}),
    ({"all": [{"in": [{"var": "status"}, [302]]}, {"eq": [{"var": "h"}, {"var": "c"}]}]},
     {"status": 302, "h": "", "c": "evil.test"}, {}),
    ({"any": [{"eq": [{"var": "a"}, "1"]}, {"eq": [{"var": "b"}, "2"]}]}, {"a": "0", "b": "2"}, {}),
    ({"any": [{"eq": [{"var": "a"}, "1"]}, {"eq": [{"var": "b"}, "2"]}]}, {"a": "0", "b": "0"}, {}),
    # --- FIRE path: the real open_redirect canary shape, with canary_host marked a provenance-ref (PD2) ---
    ({"any": [{"all": [{"in": [{"var": "status"}, [301, 302, 303, 307, 308]]},
                       {"eq": [{"var": "location_host"}, {"var": "canary_host"}]}]}]},
     {"status": 302, "location_host": "c.test", "canary_host": "c.test"}, {"canary_host": "canary"}),
    # same eligible shape, but the value does not satisfy it (non-redirect) -> eligible-but-non-firing, False
    ({"any": [{"all": [{"in": [{"var": "status"}, [301, 302, 303, 307, 308]]},
                       {"eq": [{"var": "location_host"}, {"var": "canary_host"}]}]}]},
     {"status": 200, "location_host": "", "canary_host": "c.test"}, {"canary_host": "canary"}),
    # ill-typed child under any/all: ineligible by shape (no PD among literal-only leaves) -> fired=False in
    # all three; the real oracle reaches the grammar gate BEFORE eval, so the TypeError is never raised.
    ({"any": [{"eq": [1, 1]}, {"gt": ["x", 1]}]}, {}, {}),
    ({"all": [{"eq": [1, 1]}, {"gt": ["x", 1]}]}, {}, {}),
]


def _load_verify_vf():
    import importlib.util

    spec = importlib.util.spec_from_file_location("verify_vf_reexec", _VERIFY_VF)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("pred,obs,prefs", _PREDICATE_CASES)
def test_kernel_matches_real_oracle(pred, obs, prefs):
    """The stdlib kernel (both copies) must equal the REAL oracle's `fired` on every case — over the SAME
    (predicate, observed, provenance_refs). Each kernel now ports the Lane S structural FACT-eligibility
    grammar, so it refuses the ineligible bare shapes the oracle refuses (fired=False in all three, even
    where a raw evaluation would have said True) AND fires exactly where the oracle fires (a PD-VALUE / a
    provenance-ref canary) — faithful parity on BOTH the refuse and the fire path."""
    from framework.v2.verify import oracles

    real = oracles.predicate_oracle(obs, pred, provenance_refs=prefs).fired
    assert C._reexec_fired_conclusive(pred, dict(obs), prefs)[0] is real, (pred, obs, prefs)
    vf = _load_verify_vf()
    assert vf._reexec_fired_conclusive(pred, dict(obs), prefs)[0] is real, (pred, obs, prefs)


def test_kernel_faithful_over_real_scan_contexts():
    """Every predicate/observed/provenance triple the benchmark actually produces re-derives identically in
    the kernel and the real oracle — the port is faithful on real inputs, not just hand-picked ones. The
    retained provenance-ref slot (when present) is threaded into BOTH so they evaluate the SAME grammar."""
    from framework.v2.verify import oracles

    report = scan_loopback_benchmark(retain_evidence=True)
    cov = coverage_cert_from_report(report, max_pages=25, max_depth=4)
    seen = 0
    for probe in cov["probes"]:
        ev = C._probe_reexec_evidence(probe)
        if ev is None:
            continue
        seen += 1
        prefs = ev.get("provenance_refs")
        real = oracles.predicate_oracle(ev["observed_evidence"], ev["predicate"], provenance_refs=prefs).fired
        assert C._reexec_fired_conclusive(ev["predicate"], dict(ev["observed_evidence"]), prefs)[0] is real
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
    # The forge below tampers open_redirect-specific fields (location_host / canary_host / status),
    # so select an OPEN_REDIRECT clean re-executable probe specifically. Selecting "the first clean
    # re-executable probe of any class" is fragile: a scanner-roster reorder or a new re-executable
    # class (e.g. graphql_introspection at "/") can float a different class first, and the
    # open_redirect forge would then not fire that probe's predicate — the test would spuriously pass
    # the tamper. Bind the probe class to the forge.
    for probe in cert["coverage"]["probes"]:
        if (probe.get("verdict") == "clean" and probe.get("class") == "open_redirect"
                and C._probe_reexec_evidence(probe) is not None):
            return probe
    raise AssertionError("no re-executable clean open_redirect probe found")


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
    """With retention on, ONLY predicate-oracle probes gain an evidence key: the re-execution kernel the
    oracle re-derives over — ``predicate`` + ``observed_evidence``, plus the ``provenance_refs`` slot WHEN
    the probe carries one (Lane S: the structural grammar gate reads it, so a faithful re-execution must
    carry it). The row is otherwise unchanged, and no other probe class is touched."""
    report = scan_loopback_benchmark(retain_evidence=True)
    coverage = coverage_cert_from_report(report, max_pages=25, max_depth=4)
    with_ev = [p for p in coverage["probes"] if "evidence" in p]
    assert with_ev, "retention on should retain some evidence"
    for p in with_ev:
        keys = set(p["evidence"].keys())
        assert {"predicate", "observed_evidence"} <= keys <= {"predicate", "observed_evidence", "provenance_refs"}
    # at least one benchmark predicate probe (open_redirect / cors / host-header) carries a provenance-ref
    assert any("provenance_refs" in p["evidence"] for p in with_ev), (
        "expected some retained predicate probe to carry a VIGIL-injected provenance-ref")


# ---- 5. red-pen fixes: malformed fails CLOSED; honest bound (no producer-independent overclaim) --------

def _reexec_cert_with_probe(evidence: dict, verdict: str = "clean"):
    """A minimal coverage cert carrying one predicate-oracle probe with the given evidence + verdict."""
    return {"coverage": {"probes": [{
        "surface": "http://t/", "insertion_point": "query_value:0", "param": "url",
        "check_id": "open-redirect", "class": "open_redirect", "verdict": verdict,
        "oracle_kinds_run": ["achieved_state"], "evidence": evidence,
    }]}}


def test_malformed_predicate_fails_closed_not_crash():
    """MEDIUM fix: a re-executable probe whose predicate is a dict but ill-formed ({"eq": []} -> IndexError
    upstream) must FAIL-CLOSED — the in-tree re-execution raises PostureError (not IndexError), and the
    standalone _reexecute_posture returns (False, ...) (not an uncaught traceback)."""
    cert = _reexec_cert_with_probe({"predicate": {"eq": []}, "observed_evidence": {}}, verdict="clean")
    with pytest.raises(C.PostureError):
        C.reexecute_posture_claims(cert)
    vf = _load_verify_vf()
    ok, reason = vf._reexecute_posture(cert["coverage"])
    assert ok is False and "REFUTED a CLOSED" in reason


def test_non_conclusive_clean_is_refused():
    """A probe recorded `clean` whose retained values make the re-derivation NON-CONCLUSIVE (an ill-typed
    child) does not support a conclusive-clean and is refused (fail-closed), in-tree and standalone."""
    cert = _reexec_cert_with_probe(
        {"predicate": {"any": [{"gt": ["x", 1]}]}, "observed_evidence": {}}, verdict="clean")
    with pytest.raises(C.PostureError):
        C.reexecute_posture_claims(cert)
    vf = _load_verify_vf()
    ok, _ = vf._reexecute_posture(cert["coverage"])
    assert ok is False


def test_honest_bound_no_producer_independent_overclaim(tmp_path):
    """BLOCK fix (honesty): re-execution proves the verdict is the correct function of the RETAINED values
    — it does NOT claim producer-INDEPENDENCE of the observation. The signed residual and the standalone
    SOUND reason must state the values are producer-supplied and a live re-run is still required, and must
    NOT contain the old overclaim ('producer-independent' / 'trusting no producer')."""
    # the residual carried in the signed bytes
    residual = C.POSTURE_RESIDUAL.lower()
    assert "producer-supplied" in residual
    assert "live" in residual
    assert "producer-independent" not in residual        # no overclaim (the honest phrase avoids it too)
    assert "trusting no producer" not in residual

    # the standalone SOUND reason string over a real re-executable cert
    owner, gov = generate_keypair(), generate_keypair()
    res = attest_loopback_benchmark(tmp_path / "out", owner_key=owner, gov_key=gov,
                                    engagement="honesty", retain_evidence=True)
    r = subprocess.run(_bundle_verify_cmd_eng(res, "honesty"), capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    out = (r.stdout + r.stderr).lower()
    assert "re-executable" in out                     # the tier is still surfaced
    assert "producer-independent" not in out          # but not the overclaim
    assert ("producer-supplied" in out) or ("live re-run" in out)


def _bundle_verify_cmd_eng(res: dict, engagement: str):
    d = Path(res["bundle_dir"])
    return [sys.executable, str(d / "verify_offline.py"), "verify", "--bundle", str(d / "bundle.json"),
            "--posture-fingerprint", res["fingerprint"], "--posture-owner-pubkey", res["owner_pubkey"],
            "--posture-engagement", engagement, "--posture-now", "1000"]


# ---- 6. red-pen re-check fixes: overclaim absent EVERYWHERE + projection fails closed ----------------

_REPO = Path(__file__).resolve().parents[2]
_POSTURE_PATH_FILES = [
    "integration/vigil_integration/posture/certificate.py",
    "integration/vigil_integration/posture/cli.py",
    "integration/vigil_integration/posture/attest.py",
    "docs/proof-carrying-finding/verify_vf.py",
    "engine/crucible/framework/v2/scanner/engine.py",
    "engine/crucible/framework/v2/verify/coverage_oracle.py",
    "docs/POSTURE.md",
    "docs/TRUTHENOVATION.md",
]


def test_no_producer_independent_overclaim_anywhere_in_posture_path():
    """BLOCK-1b: the overclaim must be absent from EVERY relying-party/operator/code surface — not just
    POSTURE_RESIDUAL + the verifier stdout (the two the first fix covered). Greps the whole posture path so
    the overclaim cannot regress in a doc, CLI help, the Pydantic Field schema, or a code comment."""
    forbidden = ("producer-independent", "re-derives the negative producer", "trusting no producer")
    offenders = []
    for rel in _POSTURE_PATH_FILES:
        text = (_REPO / rel).read_text(encoding="utf-8").lower()
        for phrase in forbidden:
            if phrase in text:
                offenders.append(f"{rel}: {phrase!r}")
    assert not offenders, "producer-independent overclaim still present:\n  " + "\n  ".join(offenders)


def test_projection_fails_closed_on_non_iterable_oracle_kinds():
    """MEDIUM: a probe whose oracle_kinds_run is a non-iterable scalar must FAIL-CLOSED in the projection
    (which runs before re-execution) — PostureError in-tree, ValueError caught → (False, ...) standalone —
    never an uncaught TypeError."""
    bad = {"coverage": {"probes": [{
        "surface": "/x", "insertion_point": "query_value:0", "param": "q", "check_id": "c",
        "class": "sqli", "verdict": "clean", "oracle_kinds_run": 5,
    }]}}
    with pytest.raises(C.PostureError):
        C.project_posture_claims(bad["coverage"])
    vf = _load_verify_vf()
    # the standalone projection raises ValueError (caught by verify_posture's wrapper → NOT SOUND, no crash)
    with pytest.raises(ValueError):
        vf._project_posture_claims(bad["coverage"])
