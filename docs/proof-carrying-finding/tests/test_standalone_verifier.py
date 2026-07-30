"""Conformance test for the STANDALONE proof-carrying-finding verifier (docs/proof-carrying-finding).

The property under test is the P6 adoption lever: a VIGIL proof bundle is independently verifiable by
a third party who does NOT trust or run VIGIL. Concretely:

  * a REAL bundle (minted from a genuine oracle fire, exported via vigil_integration.proof.bundle)
    verifies with `verify_pcf.py` running in a clean, VIGIL-UNIMPORTABLE subprocess (system Python,
    neutral cwd, no engine/crucible/integration on PYTHONPATH) — and `--prove-standalone` makes that
    subprocess assert it is VIGIL-free before verifying;
  * flipping a signature byte, or a raw-evidence byte, or presenting a wrong out-of-band fingerprint
    pin, each flips it to NOT SOUND (exit 2);
  * CANONICAL-BYTES PARITY: the standalone verifier's re-implemented canonical digest + trust-root
    fingerprint equal the framework's, byte-for-byte;
  * the JSON Schemas validate a real certificate, the whole bundle, and a real PCF certificate.

Runs under the offense venv (it needs vigil_integration to MINT a real bundle); the standalone check
is a subprocess that must NOT be able to import the framework at all.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

# --- locate the P6 deliverables (this file is <repo>/docs/proof-carrying-finding/tests/…) -----------
_PCF_DIR = Path(__file__).resolve().parents[1]
_REPO_ROOT = Path(__file__).resolve().parents[3]
_VERIFIER = _PCF_DIR / "verify_pcf.py"
_SCHEMAS = _PCF_DIR / "schemas"

# --- offense-env imports (to MINT a real bundle) ---------------------------------------------------
from vigil_core import generate_keypair  # noqa: E402
from vigil_integration.proof.bundle import export_bundle  # noqa: E402
from vigil_integration.proof.run import build_report_mint, read_reverifiable  # noqa: E402
from vigil_integration.proof.sink import CAPTURE_KEY  # noqa: E402

SIGNER = generate_keypair()
SIGNERS = [("root0", SIGNER.private_key_b64)]
_SQL_ERROR = b"HTTP/1.1 500\r\n\r\nYou have an error in your SQL syntax near ''' at line 1"


def _load_standalone():
    """Import verify_pcf.py in-process (offense venv) — legitimate here: the module imports only stdlib
    + cryptography, so loading it does NOT pull in any VIGIL code. Used for the byte-parity assertions."""
    spec = importlib.util.spec_from_file_location("standalone_verify_pcf", _VERIFIER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _mint_a_fact(run_dir: Path) -> None:
    mint = build_report_mint(run_dir=run_dir, signers=SIGNERS, engagement_slug="acme")
    report = {
        "id": "errsqli-001", "bug_class": "error_based_sqli", "poc_script_code": "print('benign repro')",
        CAPTURE_KEY: {"exchanges": [{"channel": "error_signature", "role": "mutated",
                                     "response_bytes_ref": "resp", "bug_class": "error_based_sqli"}],
                      "blobs": {"resp": _SQL_ERROR}},
    }
    res = mint(report)
    assert res is not None and res.is_fact, "the SQL-error response must mint a FACT"


@pytest.fixture
def real_bundle(tmp_path) -> Path:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    _mint_a_fact(run_dir)
    assert read_reverifiable(run_dir)["active_findings"], "the mint must persist a re-verifiable finding"
    out = tmp_path / "bundle"
    res = export_bundle(run_dir=run_dir, out_dir=out, engagement_slug="acme")
    assert res["ok"] and res["certificates"] == 1, res
    return out


def _clean_env() -> dict:
    """An env with NO VIGIL paths: strip PYTHONPATH/PYTHONHOME so the system interpreter sees only its
    own stdlib + site-packages (which do NOT contain framework/vigil_core/vigil_integration/strix)."""
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)   # never inherit engine/crucible:integration:packages/core
    env.pop("PYTHONHOME", None)
    env.pop("VIRTUAL_ENV", None)
    return env


def _run_standalone(bundle: Path, *, cwd: Path, fingerprint: str = "", prove: bool = True,
                    extra: list[str] | None = None) -> subprocess.CompletedProcess:
    """Run verify_pcf.py with the SYSTEM python, from a neutral cwd, VIGIL-unimportable. Uses an absolute
    --bundle path so cwd can be anywhere clean."""
    argv = ["/usr/bin/python3", str(_VERIFIER), "bundle", "--bundle", str(bundle)]
    if fingerprint:
        argv += ["--trust-root-fingerprint", fingerprint]
    if prove:
        argv += ["--prove-standalone"]
    argv += (extra or [])
    return subprocess.run(argv, cwd=str(cwd), env=_clean_env(), capture_output=True, text=True, timeout=120)


def _fingerprint(bundle: Path) -> str:
    return (bundle / "TRUST-ROOT-FINGERPRINT.txt").read_text(encoding="utf-8").strip()


# ---------------------------------------------------------------------------------------------------
# 1. a genuine bundle verifies in a clean, VIGIL-free subprocess
# ---------------------------------------------------------------------------------------------------
def test_the_subprocess_is_actually_vigil_free(real_bundle, tmp_path):
    """--prove-standalone asserts framework/vigil_core/etc are neither imported nor importable; if the
    env were NOT clean this would exit non-zero, so a passing verify below is a real standalone verify."""
    proc = _run_standalone(real_bundle, cwd=tmp_path, fingerprint=_fingerprint(real_bundle), prove=True)
    assert "confirmed VIGIL-free" in proc.stdout, f"env not proven clean:\n{proc.stdout}\n{proc.stderr}"
    # belt-and-braces: the same clean env genuinely cannot import the framework
    check = subprocess.run(
        ["/usr/bin/python3", "-c",
         "import importlib.util as u;"
         "print(any(u.find_spec(m) for m in ('framework','vigil_core','vigil_integration','strix')))"],
        cwd=str(tmp_path), env=_clean_env(), capture_output=True, text=True)
    assert check.stdout.strip() == "False", f"a VIGIL module was importable in the 'clean' env: {check.stdout}"


def test_genuine_bundle_verifies_standalone(real_bundle, tmp_path):
    proc = _run_standalone(real_bundle, cwd=tmp_path, fingerprint=_fingerprint(real_bundle))
    assert proc.returncode == 0, f"a sound bundle must verify (rc={proc.returncode}):\n{proc.stdout}\n{proc.stderr}"
    assert "bundle SOUND" in proc.stdout


# ---------------------------------------------------------------------------------------------------
# 2. tamper → NOT SOUND (signature byte, raw-evidence byte, oracle_context, wrong pin)
# ---------------------------------------------------------------------------------------------------
def _copy(bundle: Path, dst: Path) -> Path:
    shutil.copytree(bundle, dst)
    return dst


def test_flipped_signature_byte_is_rejected(real_bundle, tmp_path):
    victim = _copy(real_bundle, tmp_path / "tampered")
    bj = victim / "evidence-bundle.json"
    doc = json.loads(bj.read_text())
    import base64
    sig_b64 = doc["certificates"][0]["signatures"][0]["signature_b64"]
    raw = bytearray(base64.b64decode(sig_b64))
    raw[-1] ^= 0x01                                  # a real 64-byte signature, now invalid
    doc["certificates"][0]["signatures"][0]["signature_b64"] = base64.b64encode(bytes(raw)).decode()
    bj.write_text(json.dumps(doc, indent=2, sort_keys=True))
    proc = _run_standalone(victim, cwd=tmp_path, fingerprint=_fingerprint(victim))
    assert proc.returncode == 2, f"a flipped signature MUST fail (authentic):\n{proc.stdout}"
    assert "bundle NOT SOUND" in proc.stdout


def test_flipped_evidence_byte_is_rejected(real_bundle, tmp_path):
    victim = _copy(real_bundle, tmp_path / "tampered")
    ev = victim / "evidence"
    files = [p for p in ev.rglob("*") if p.is_file()] if ev.is_dir() else []
    if not files:
        pytest.skip("this bundle carries no raw artifacts to tamper")
    data = bytearray(files[0].read_bytes())
    data[-1] ^= 0x01
    files[0].write_bytes(bytes(data))
    proc = _run_standalone(victim, cwd=tmp_path, fingerprint=_fingerprint(victim))
    assert proc.returncode == 2, f"a flipped evidence byte MUST fail (artifacts):\n{proc.stdout}"


def test_tampered_oracle_context_is_rejected(real_bundle, tmp_path):
    victim = _copy(real_bundle, tmp_path / "tampered")
    rp = victim / "reverifiable.json"
    doc = json.loads(rp.read_text())
    doc["active_findings"][0]["oracle_context"]["error_observed"] = "totally benign response"
    rp.write_text(json.dumps(doc))
    proc = _run_standalone(victim, cwd=tmp_path, fingerprint=_fingerprint(victim))
    assert proc.returncode == 2, f"an altered oracle_context MUST fail (binding):\n{proc.stdout}"


def test_wrong_fingerprint_pin_is_refused(real_bundle, tmp_path):
    wrong = _run_standalone(real_bundle, cwd=tmp_path, fingerprint="sha256:" + "0" * 64)
    assert wrong.returncode == 2 and "MISMATCH" in wrong.stdout, wrong.stdout
    right = _run_standalone(real_bundle, cwd=tmp_path, fingerprint=_fingerprint(real_bundle))
    assert right.returncode == 0, right.stdout


# ---------------------------------------------------------------------------------------------------
# 3. canonical-bytes parity — the re-implemented serializer is byte-identical to the framework's
# ---------------------------------------------------------------------------------------------------
def test_canonical_bytes_parity_with_the_framework(real_bundle):
    """The standalone verifier's digest_payload(certificate) must equal the framework's cert_digest, and
    its trust_root_fingerprint must equal the framework's — proving the re-implemented canonical bytes
    match the real serializer exactly (not merely 'a bundle verified')."""
    from framework.v2.evidence.certify import trust_root_fingerprint as fw_fingerprint
    from framework.v2.evidence.models import SignedEvidence
    from framework.v2.entitlement.models import TrustRoot

    standalone = _load_standalone()
    bundle = json.loads((real_bundle / "evidence-bundle.json").read_text())

    for raw in bundle["certificates"]:
        # framework's authoritative digest (round-trips the model, exactly as signing does)
        fw_digest = SignedEvidence.model_validate(raw).certificate.cert_digest
        # standalone recomputes over the ON-DISK cert dict via its own canonical_json
        sa_digest = standalone.sha256_hex(standalone.canonical_json(raw["certificate"]))
        assert sa_digest == fw_digest, "standalone canonical cert bytes != framework cert_digest"
        # and the chain links on exactly that digest
        assert sa_digest in {e["cert_digest"] for e in bundle["chain"]}

    tr_raw = json.loads((real_bundle / "trust-root.json").read_text())
    fw_fp = fw_fingerprint(TrustRoot.model_validate(tr_raw))
    sa_fp = standalone.trust_root_fingerprint(tr_raw)
    assert sa_fp == fw_fp == _fingerprint(real_bundle), "standalone fingerprint != framework fingerprint"


# ---------------------------------------------------------------------------------------------------
# 4. JSON Schema validation of real artifacts
# ---------------------------------------------------------------------------------------------------
def _registry():
    from referencing import Registry, Resource
    resources = []
    for path in _SCHEMAS.glob("*.schema.json"):
        doc = json.loads(path.read_text())
        resources.append((doc["$id"], Resource.from_contents(doc)))
    return Registry().with_resources(resources)


def _validator(schema_name: str):
    from jsonschema import Draft202012Validator
    schema = json.loads((_SCHEMAS / schema_name).read_text())
    return Draft202012Validator(schema, registry=_registry())


def test_real_certificate_matches_the_schema(real_bundle):
    bundle = json.loads((real_bundle / "evidence-bundle.json").read_text())
    cert = bundle["certificates"][0]["certificate"]
    _validator("evidence-certificate.schema.json").validate(cert)
    # the drop-when-empty additive members ARE present here (a fresh mint stamps oracle_version + how_to_verify)
    assert cert.get("oracle_version", "").startswith("sha256:")
    assert cert.get("how_to_verify")


def test_whole_bundle_matches_the_schema(real_bundle):
    bundle = json.loads((real_bundle / "evidence-bundle.json").read_text())
    _validator("evidence-bundle.schema.json").validate(bundle)
    _validator("trust-root.schema.json").validate(json.loads((real_bundle / "trust-root.json").read_text()))


def test_real_pcf_certificate_matches_the_schema(real_bundle, tmp_path):
    """Project the signed bundle into a real PCF v0.1 cert and validate it against the wire schema; then
    verify it authenticates standalone (authenticity + binding + no-lying-wrapper)."""
    from framework.v2.evidence.pcf import to_pcf
    from framework.v2.evidence.models import SignedEvidence

    bundle = json.loads((real_bundle / "evidence-bundle.json").read_text())
    rev = json.loads((real_bundle / "reverifiable.json").read_text())
    ctx = {str(f.get("check_id") or f.get("finding_slug") or f.get("bug_class") or "finding"): f["oracle_context"]
           for f in rev["active_findings"] if f.get("oracle_context")}

    sc = SignedEvidence.model_validate(bundle["certificates"][0])
    pcf = to_pcf(sc, oracle_context=ctx[sc.certificate.finding_ref])
    _validator("pcf-certificate.schema.json").validate(pcf)

    # standalone PCF verify (authenticity + binding + faithful-projection subset). The real cert carries
    # raw artifacts, so pass the evidence root so they re-hash (fail-closed without it, by design).
    standalone = _load_standalone()
    tr = json.loads((real_bundle / "trust-root.json").read_text())
    er = real_bundle / "evidence"
    ok, reason = standalone.verify_pcf_cert(pcf, tr, pin=_fingerprint(real_bundle), evidence_root=er)
    assert ok, reason
    # a lying wrapper (relabelled class in the view) is rejected
    lied = json.loads(json.dumps(pcf))
    lied["claim"]["class"] = "sqli"
    bad_ok, _ = standalone.verify_pcf_cert(lied, tr, pin=_fingerprint(real_bundle), evidence_root=er)
    assert not bad_ok, "a relabelled PCF claim must be rejected (lying wrapper)"
