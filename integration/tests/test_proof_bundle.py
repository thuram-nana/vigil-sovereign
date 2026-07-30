"""Proof Studio C1 — the client-verifiable proof bundle (proof.bundle.export_bundle + `vigil proof-export`).

The moat property under test: a bundle exported from a run's oracle-confirmed FACTs re-verifies OFFLINE,
with the deterministic verifier and the published PUBLIC trust root ONLY — and a single flipped byte anywhere
(raw evidence OR the retained oracle_context) flips it to NOT SOUND. This is the "prove-don't-guess, made
checkable for a third party" claim, made falsifiable.

Needs framework (mint + verify) → run with PYTHONPATH=integration:engine/crucible:gateway.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from vigil_core import generate_keypair
from vigil_integration.proof.bundle import export_bundle
from vigil_integration.proof.run import build_report_mint, read_reverifiable
from vigil_integration.proof.sink import CAPTURE_KEY

SIGNER = generate_keypair()
SIGNERS = [("root0", SIGNER.private_key_b64)]

# The error-signature oracle fires on a distinctive datastore error in the response body → a response-side
# (target-produced) FACT, exactly the channel the live Strix capture builds.
_SQL_ERROR = b"HTTP/1.1 500\r\n\r\nYou have an error in your SQL syntax near ''' at line 1"


def _mint_a_fact(run_dir: Path) -> object:
    mint = build_report_mint(run_dir=run_dir, signers=SIGNERS, engagement_slug="acme")
    report = {
        "id": "errsqli-001", "bug_class": "error_based_sqli", "poc_script_code": "print('benign repro')",
        CAPTURE_KEY: {"exchanges": [{"channel": "error_signature", "role": "mutated",
                                     "response_bytes_ref": "resp", "bug_class": "error_based_sqli"}],
                      "blobs": {"resp": _SQL_ERROR}},
    }
    res = mint(report)
    assert res is not None and res.is_fact, "the SQL-error response must mint a FACT"
    return res


def _verify(bundle: Path, *, fingerprint: str = "") -> subprocess.CompletedProcess:
    """Run the third-party offline verify exactly as the README prescribes (optionally with a pinned root)."""
    env = dict(os.environ)
    # the verifier needs framework (engine/crucible) + vigil_core on the path — nothing else.
    env["PYTHONPATH"] = os.pathsep.join(
        [str(Path.cwd() / "engine" / "crucible"), env.get("PYTHONPATH", "")])
    argv = [sys.executable, "-m", "framework.v2", "evidence", "verify",
            "--report", "reverifiable.json", "--bundle", ".",
            "--trust-root", "trust-root.json", "--evidence-root", "evidence"]
    if fingerprint:
        argv += ["--trust-root-fingerprint", fingerprint]
    return subprocess.run(argv, cwd=str(bundle), env=env, capture_output=True, text=True, timeout=120)


def test_exported_bundle_verifies_offline(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    _mint_a_fact(run_dir)
    assert read_reverifiable(run_dir)["active_findings"], "the mint must persist a re-verifiable finding"

    out = tmp_path / "bundle"
    res = export_bundle(run_dir=run_dir, out_dir=out, engagement_slug="acme")
    assert res["ok"] and res["certificates"] == 1
    for name in ("evidence-bundle.json", "trust-root.json", "reverifiable.json", "README.md",
                 "HOW-TO-VERIFY.md"):
        assert (out / name).is_file(), f"{name} missing from the bundle"

    proc = _verify(out)
    assert proc.returncode == 0, f"a sound bundle must verify (rc={proc.returncode}):\n{proc.stdout}\n{proc.stderr}"

    # B1: the per-finding how-to companion carries real per-finding guidance (surface + oracle + verify),
    # and the same note is signed into the certificate (tamper-evident, not just docs).
    howto = (out / "HOW-TO-VERIFY.md").read_text()
    assert "How to verify" in howto and "oracle" in howto.lower() and "Verify:" in howto
    bundle_json = json.loads((out / "evidence-bundle.json").read_text())
    assert bundle_json["certificates"][0]["certificate"]["how_to_verify"], "the cert must carry how_to_verify"


def test_a_flipped_evidence_byte_makes_the_bundle_not_sound(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    _mint_a_fact(run_dir)
    out = tmp_path / "bundle"
    assert export_bundle(run_dir=run_dir, out_dir=out, engagement_slug="acme")["ok"]
    assert _verify(out).returncode == 0                       # sound before tamper

    # flip a byte in the raw captured evidence the certificate binds by sha256
    victim = next((out / "evidence").rglob("*"))
    while victim.is_dir():
        victim = next(victim.rglob("*"))
    data = bytearray(victim.read_bytes())
    data[-1] ^= 0x01
    victim.write_bytes(bytes(data))

    assert _verify(out).returncode != 0, "a tampered evidence byte MUST fail verification (artifact integrity)"


def test_a_tampered_oracle_context_makes_the_bundle_not_sound(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    _mint_a_fact(run_dir)
    out = tmp_path / "bundle"
    assert export_bundle(run_dir=run_dir, out_dir=out, engagement_slug="acme")["ok"]

    # rewrite the retained oracle_context so it no longer matches the signed certificate digest
    rp = out / "reverifiable.json"
    doc = json.loads(rp.read_text(encoding="utf-8"))
    doc["active_findings"][0]["oracle_context"]["error_observed"] = "totally benign response"
    rp.write_text(json.dumps(doc), encoding="utf-8")

    assert _verify(out).returncode != 0, "an altered oracle_context MUST fail (bound-digest + reproduction)"


def test_export_refuses_when_there_are_no_proven_facts(tmp_path):
    run_dir = tmp_path / "run"
    (run_dir / "proofs").mkdir(parents=True)
    res = export_bundle(run_dir=run_dir, out_dir=tmp_path / "bundle", engagement_slug="acme")
    assert res["ok"] is False and "no proven findings" in res["error"]


def test_trust_root_fingerprint_pin_is_enforced(tmp_path):
    """The authenticity anchor: a CORRECT out-of-band fingerprint pin verifies; a WRONG pin is refused even
    though the bundle is internally sound (adversarial review — the in-bundle root must be pinnable)."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    _mint_a_fact(run_dir)
    out = tmp_path / "bundle"
    res = export_bundle(run_dir=run_dir, out_dir=out, engagement_slug="acme")
    fp = (out / "TRUST-ROOT-FINGERPRINT.txt").read_text(encoding="utf-8").strip()
    assert fp == res["trust_root_fingerprint"] and fp.startswith("sha256:")

    assert _verify(out, fingerprint=fp).returncode == 0                       # the right pin verifies
    wrong = _verify(out, fingerprint="sha256:" + "0" * 64)
    assert wrong.returncode != 0                                             # a wrong pin is REFUSED
    assert "MISMATCH" in (wrong.stdout + wrong.stderr)


def test_hostile_action_id_does_not_traverse_outside_the_evidence_tree(tmp_path):
    """Adversarial review (fail-closed): a reverifiable.json whose action_id is an absolute/`..` path must NOT
    make the export walk + hash files outside the evidence tree — it drops artifacts, never traverses."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    _mint_a_fact(run_dir)
    # poison the retained action_id with an absolute path (a hostile proofs/reverifiable.json)
    rp = run_dir / "proofs" / "reverifiable.json"
    doc = json.loads(rp.read_text(encoding="utf-8"))
    doc["active_findings"][0]["action_id"] = "/etc"
    rp.write_text(json.dumps(doc), encoding="utf-8")

    out = tmp_path / "bundle"
    res = export_bundle(run_dir=run_dir, out_dir=out, engagement_slug="acme")
    assert res["ok"] and res["certificates"] == 1
    # the cert dropped its artifacts (hostile id rejected) — nothing under /etc was walked or embedded
    bundle = json.loads((out / "evidence-bundle.json").read_text(encoding="utf-8"))
    arts = bundle["certificates"][0]["certificate"].get("artifacts") or []
    assert arts == [], "a hostile action_id must yield NO artifact manifest (no traversal)"
    # and it still verifies on reproduction alone (no evidence tree needed for an artifact-less cert)
    assert _verify(out, fingerprint=res["trust_root_fingerprint"]).returncode == 0
