"""Conformance test for the standalone verifier's ``finding`` mode (SPEC §8): ONE signed finding record.

The single-finding bundle is what a VIGIL customer downloads for one finding (``vigil.pcf-finding-bundle/1``): the
governance-signed certificate, its signatures and the trust root — assembled on the customer's own plane from exactly
what crossed the offense→sovereign seam. This proves, over a REAL certificate minted from a genuine oracle fire
(``vigil_integration.proof`` — the same mint the full-bundle conformance test uses):

  * the bundle verifies with ``verify_pcf.py finding`` in a clean, VIGIL-UNIMPORTABLE subprocess
    (``--prove-standalone``), and its output names every layer it did NOT check (binding / artifacts / reproduction /
    chain) instead of passing silently over them;
  * supplying the retained ``oracle_context`` (``--oracle-context``) and the raw evidence (``--evidence-root``) checks
    binding and artifacts too, and an altered context / evidence byte fails them;
  * a flipped signature byte, a changed certificate field, a wrong out-of-band pin, a lying wrapper field
    (``cert_digest`` / ``finding_ref`` / ``trust_root_fingerprint``), a wrong format tag and a NON-FACT provenance
    (``"llm"``) — even when genuinely signed — each refuse (exit 2);
  * CANONICAL PARITY: the mode's certificate digest equals the framework's ``cert_digest``;
  * the real bundle validates against ``schemas/pcf-finding-bundle.schema.json``.

Runs under the offense venv (it needs vigil_integration to MINT a real certificate).
"""
from __future__ import annotations

import base64
import importlib.util
import json
import os
import subprocess
from pathlib import Path

import pytest

_PCF_DIR = Path(__file__).resolve().parents[1]
_VERIFIER = _PCF_DIR / "verify_pcf.py"
_SCHEMAS = _PCF_DIR / "schemas"

# Every plane this test needs, gated by importorskip (the framework FIRST: the proof mint imports it). Names are
# bound from the returned modules, so no import statement follows module code.
pytest.importorskip("framework.v2.evidence.models")
_vc = pytest.importorskip("vigil_core")
_bundle_mod = pytest.importorskip("vigil_integration.proof.bundle")
_run_mod = pytest.importorskip("vigil_integration.proof.run")
_sink_mod = pytest.importorskip("vigil_integration.proof.sink")
evidence_signing_bytes, generate_keypair, sign = _vc.evidence_signing_bytes, _vc.generate_keypair, _vc.sign
export_bundle = _bundle_mod.export_bundle
build_report_mint, read_reverifiable = _run_mod.build_report_mint, _run_mod.read_reverifiable
CAPTURE_KEY = _sink_mod.CAPTURE_KEY

SIGNER = generate_keypair()
SIGNERS = [("root0", SIGNER.private_key_b64)]
_SQL_ERROR = b"HTTP/1.1 500\r\n\r\nYou have an error in your SQL syntax near ''' at line 1"


def _load_standalone():
    spec = importlib.util.spec_from_file_location("standalone_verify_pcf_finding", _VERIFIER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def real(tmp_path) -> dict:
    """A REAL minted, governance-signed certificate (+ its trust root, retained context and evidence tree)."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    mint = build_report_mint(run_dir=run_dir, signers=SIGNERS, engagement_slug="acme",
                             control_fetch=lambda _r: b"HTTP/1.1 200 OK\r\n\r\nok")
    report = {
        "id": "errsqli-001", "bug_class": "error_based_sqli", "poc_script_code": "print('benign repro')",
        CAPTURE_KEY: {"exchanges": [{"channel": "error_signature", "role": "mutated",
                                     "response_bytes_ref": "resp", "request_bytes_ref": "req",
                                     "bug_class": "error_based_sqli", "observed_scheme": "http"}],
                      "blobs": {"resp": _SQL_ERROR, "req": b"GET /items?id=1%27 HTTP/1.1\r\nHost: t\r\n\r\n"}},
    }
    res = mint(report)
    assert res is not None and res.is_fact
    out = tmp_path / "full"
    assert export_bundle(run_dir=run_dir, out_dir=out, engagement_slug="acme")["ok"]
    full = json.loads((out / "evidence-bundle.json").read_text())
    trust_root = json.loads((out / "trust-root.json").read_text())
    se = full["certificates"][0]
    sa = _load_standalone()
    bundle = {"format": "vigil.pcf-finding-bundle/1", "finding_ref": se["certificate"]["finding_ref"],
              "cert_digest": sa.digest_payload(se["certificate"]),
              "signed_evidence": {"certificate": se["certificate"], "signatures": se["signatures"]},
              "trust_root": trust_root, "trust_root_fingerprint": sa.trust_root_fingerprint(trust_root)}
    # the context the SHIPPED certificate binds: export_bundle (re-)signs under the run's provisioned authority over
    # the exported reverifiable.json, keyed by finding_ref exactly as the bundle mode reads it
    exported = json.loads((out / "reverifiable.json").read_text())
    ctx = sa._ctx_by_ref(exported)[se["certificate"]["finding_ref"]]
    assert read_reverifiable(run_dir)["active_findings"], "the mint must persist a re-verifiable finding"
    folder = tmp_path / "finding"
    folder.mkdir()
    (folder / "proof-bundle.json").write_text(json.dumps(bundle, indent=2, sort_keys=True))
    (folder / "oracle-context.json").write_text(json.dumps(ctx))
    return {"folder": folder, "bundle": bundle, "fp": bundle["trust_root_fingerprint"], "full": out,
            "se": se, "ctx": ctx}


def _clean_env() -> dict:
    env = dict(os.environ)
    for k in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV"):
        env.pop(k, None)
    return env


def _run(folder: Path, *extra: str, bundle: str = "proof-bundle.json", prove: bool = True):
    argv = ["/usr/bin/python3", str(_VERIFIER), "finding", "--bundle", str(folder / bundle), *extra]
    if prove:
        argv.append("--prove-standalone")
    return subprocess.run(argv, cwd=str(folder), env=_clean_env(), capture_output=True, text=True, timeout=120,
                          check=False)                     # the exit code IS the verdict under test


def _write(folder: Path, doc: dict, name: str = "t.json") -> str:
    (folder / name).write_text(json.dumps(doc))
    return name


def test_a_real_signed_finding_verifies_standalone_and_names_what_it_did_not_check(real):
    p = _run(real["folder"], "--trust-root-fingerprint", real["fp"])
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    assert "confirmed VIGIL-free" in p.stdout and "PINNED OK" in p.stdout
    assert "[OK ] authentic" in p.stdout and "[OK ] provenance" in p.stdout
    assert "bound: NOT CHECKED" in p.stdout and "reproduced / chained: NOT CHECKED" in p.stdout
    arts = real["bundle"]["signed_evidence"]["certificate"].get("artifacts") or []
    assert (f"{len(arts)} declared, NOT CHECKED" in p.stdout) if arts else ("none declared" in p.stdout)
    assert p.stdout.strip().splitlines()[-1].startswith("finding VERIFIED")


def test_supplied_context_and_evidence_are_checked_and_their_tamper_fails(real):
    folder = real["folder"]
    args = ["--trust-root-fingerprint", real["fp"], "--oracle-context", str(folder / "oracle-context.json"),
            "--evidence-root", str(real["full"] / "evidence")]
    p = _run(folder, *args)
    assert p.returncode == 0 and "[OK ] bound" in p.stdout, p.stdout
    if real["bundle"]["signed_evidence"]["certificate"].get("artifacts"):
        assert "[OK ] artifacts" in p.stdout, p.stdout
    bad = dict(real["ctx"])
    bad["error_observed"] = "a perfectly benign page"
    (folder / "bad-context.json").write_text(json.dumps(bad))
    p = _run(folder, "--trust-root-fingerprint", real["fp"], "--oracle-context", str(folder / "bad-context.json"))
    assert p.returncode == 2 and "[BAD] bound" in p.stdout, p.stdout


@pytest.mark.parametrize("case", ["sig", "field", "pin", "cert_digest", "finding_ref", "fingerprint", "format",
                                  "no_sigs", "hostile_key_id", "hostile_sig_entry", "hostile_threshold"])
def test_every_tamper_refuses(real, case):
    """Each tamper — and each HOSTILE shape the always-checked layers do not anticipate — is a clean refusal: exit 2
    and ``finding NOT VERIFIED``, never a traceback (an auditor is told exactly what a refusal looks like)."""
    doc = json.loads(json.dumps(real["bundle"]))
    pin = real["fp"]
    if case == "sig":
        raw = bytearray(base64.b64decode(doc["signed_evidence"]["signatures"][0]["signature_b64"]))
        raw[0] ^= 0x01
        doc["signed_evidence"]["signatures"][0]["signature_b64"] = base64.b64encode(bytes(raw)).decode()
    elif case == "field":
        doc["signed_evidence"]["certificate"]["surface"] = "elsewhere"
        doc.pop("cert_digest")
    elif case == "pin":
        pin = "sha256:" + "f" * 64
    elif case == "cert_digest":
        doc["cert_digest"] = "0" * 64
    elif case == "finding_ref":
        doc["finding_ref"] = "someone-elses-finding"
    elif case == "fingerprint":
        doc["trust_root_fingerprint"] = "sha256:" + "0" * 64
    elif case == "format":
        doc["format"] = "vigil.pcf-finding-bundle/0"
    elif case == "no_sigs":
        doc["signed_evidence"]["signatures"] = []
    elif case == "hostile_key_id":                       # an unhashable key_id under the GENUINE pinned root
        doc["signed_evidence"]["signatures"] = [{"key_id": ["root0"], "signature_b64": "AAAA"}]
    elif case == "hostile_sig_entry":                    # a signature entry that is not an object at all, then junk
        doc["signed_evidence"]["signatures"] = ["root0", {"key_id": {"x": 1}, "signature_b64": 7}]
    elif case == "hostile_threshold":                    # an UNPINNED run over a root whose threshold is not a number
        doc["trust_root"]["threshold"] = "two"
        doc.pop("trust_root_fingerprint")
        pin = ""
    p = _run(real["folder"], "--trust-root-fingerprint", pin, bundle=_write(real["folder"], doc), prove=False)
    assert p.returncode == 2 and "finding NOT VERIFIED" in p.stdout, (case, p.stdout, p.stderr)
    assert "Traceback" not in p.stderr, (case, p.stderr)


def test_a_genuinely_signed_non_fact_provenance_is_refused(real):
    """An LLM-authored context is never a FACT: a certificate declaring provenance="llm", GENUINELY signed under the
    pinned root, is authentic yet refused on provenance alone — while the same certificate without that member, signed
    the same way under the same root, verifies (the positive control: provenance is the only difference)."""
    from vigil_core import AuthorizerKey, TrustRoot
    sa = _load_standalone()
    root = TrustRoot(threshold=1, authorizers=[AuthorizerKey(key_id="root0", name="root0",
                                                             public_key_b64=SIGNER.public_key_b64)])
    tr = root.model_dump(mode="json")
    pin = sa.trust_root_fingerprint(tr)

    def bundle_for(cert: dict) -> dict:
        return {"format": "vigil.pcf-finding-bundle/1", "trust_root": tr,
                "signed_evidence": {"certificate": cert, "signatures": [
                    {"key_id": "root0", "signature_b64": sign(SIGNER.private_key_b64, evidence_signing_bytes(cert))}]}}

    fact = json.loads(json.dumps(real["bundle"]["signed_evidence"]["certificate"]))
    fact.pop("provenance", None)
    llm = {**fact, "provenance": "llm"}
    ok = _run(real["folder"], "--trust-root-fingerprint", pin, bundle=_write(real["folder"], bundle_for(fact), "f.json"),
              prove=False)
    assert ok.returncode == 0 and "finding VERIFIED" in ok.stdout, ok.stdout
    p = _run(real["folder"], "--trust-root-fingerprint", pin, bundle=_write(real["folder"], bundle_for(llm), "l.json"),
             prove=False)
    assert p.returncode == 2 and "[OK ] authentic" in p.stdout and "[BAD] provenance" in p.stdout, p.stdout


def test_an_unpinned_run_never_claims_the_fingerprint_layer(real):
    """Without an out-of-band pin the verdict line must say authenticity is NOT anchored (and not list the
    fingerprint among the checked layers) — internal consistency is not authenticity (SPEC §6)."""
    p = _run(real["folder"], prove=False)
    last = p.stdout.strip().splitlines()[-1]
    assert p.returncode == 0 and "UNPINNED" in last and "fingerprint +" not in last, p.stdout
    pinned = _run(real["folder"], "--trust-root-fingerprint", real["fp"], prove=False).stdout.strip().splitlines()[-1]
    assert "fingerprint + authenticity" in pinned and "UNPINNED" not in pinned


def test_io_and_usage_errors_exit_3(real):
    p = _run(real["folder"], "--trust-root-fingerprint", real["fp"], bundle="does-not-exist.json", prove=False)
    assert p.returncode == 3
    (real["folder"] / "garbage.json").write_text("{not json")
    p = _run(real["folder"], "--trust-root-fingerprint", real["fp"], bundle="garbage.json", prove=False)
    assert p.returncode == 3
    (real["folder"] / "latin1.json").write_bytes(b'{"format": "\xff\xfe"}')          # not UTF-8
    p = _run(real["folder"], "--trust-root-fingerprint", real["fp"], bundle="latin1.json", prove=False)
    assert p.returncode == 3 and "Traceback" not in p.stderr, p.stderr
    (real["folder"] / "deep.json").write_text("[" * 200000 + "]" * 200000)          # nested past the parser's limit
    p = _run(real["folder"], "--trust-root-fingerprint", real["fp"], bundle="deep.json", prove=False)
    assert p.returncode == 3 and "Traceback" not in p.stderr, p.stderr


def test_canonical_parity_with_the_framework(real):
    from framework.v2.evidence.models import SignedEvidence
    sa = _load_standalone()
    fw = SignedEvidence.model_validate(real["se"]).certificate.cert_digest
    assert sa.digest_payload(real["bundle"]["signed_evidence"]["certificate"]) == fw == real["bundle"]["cert_digest"]
    ok, log = sa.verify_finding_bundle(real["bundle"], pin=real["fp"])
    assert ok is True and fw in "\n".join(log)


def test_the_real_bundle_matches_the_published_schema(real):
    from jsonschema import Draft202012Validator, ValidationError
    from referencing import Registry, Resource
    resources = []
    for path in _SCHEMAS.glob("*.schema.json"):
        d = json.loads(path.read_text())
        resources.append((d["$id"], Resource.from_contents(d)))
    schema = json.loads((_SCHEMAS / "pcf-finding-bundle.schema.json").read_text())
    v = Draft202012Validator(schema, registry=Registry().with_resources(resources))
    v.validate(real["bundle"])
    with pytest.raises(ValidationError, match="unexpected"):
        v.validate({**real["bundle"], "unexpected": 1})          # additionalProperties=false
