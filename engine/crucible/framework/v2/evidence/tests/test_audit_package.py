"""H4 — the external-audit package re-verifies OFFLINE with NO VIGIL import, and a tamper is rejected.

The package generator (``evidence.audit_package``) bundles the signed evidence + a STANDALONE verifier
(``verify_offline.py``, stdlib + cryptography only) + scope/charter + a runbook. These tests prove:

  * the shipped ``verify_offline.py`` imports NOTHING from ``framework`` / ``vigil`` / ``vigil_core``
    (AST-checked) — so an external team runs it with no VIGIL runtime;
  * running it as a SUBPROCESS over a freshly generated package exits 0 (SOUND); and
  * every tamper class — flipped signature, altered oracle_context (binding), mutated raw artifact,
    deleted chain entry, wrong out-of-band fingerprint pin — makes it exit non-zero (NOT SOUND).

The oracle REPRODUCTION step is deliberately NOT part of the standalone verifier (it needs the oracle's
code — the open-source VIGIL verifier); this is the honest residual, documented in the runbook.
"""
from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

from framework.v2.entitlement.crypto import generate_keypair
from framework.v2.entitlement.models import AuthorizerKey, TrustRoot
from framework.v2.evidence.audit_package import build_audit_package
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.confirmation import confirm_finding

_BASE = {"status": 200, "body": "No results found."}
_DIVERGENT = {"status": 200,
              "body": "id=1 name=alice role=user\nid=2 name=bob role=admin\nid=3 name=carol role=user"}


def _finding(action_id: str = "act-1") -> dict:
    ctx = FindingContext.from_http_responses(
        _BASE, _DIVERGENT, bug_class="boolean_sqli",
        discriminator={"dimensions": ["status", "length", "lexical"]})
    confirmed = confirm_finding(finding={"bug_class": "boolean_sqli"}, context=ctx)
    return {
        "check_id": "boolean-sqli", "bug_class": "boolean_sqli", "action_id": action_id,
        "confirmed_by": confirmed.confirmed_by.value if confirmed else "differential_response",
        "confidence": confirmed.confidence if confirmed else 0.9,
        "oracle_context": ctx.model_dump(mode="json"),
    }


def _trust_root(threshold: int = 2, n: int = 3):
    keys = [generate_keypair() for _ in range(n)]
    tr = TrustRoot(schema_version=1, threshold=threshold, authorizers=[
        AuthorizerKey(key_id=f"gov-{i}", name=f"Authoriser {i}", public_key_b64=k.public_key_b64)
        for i, k in enumerate(keys)])
    signers = [(f"gov-{i}", k.private_key_b64) for i, k in enumerate(keys)]
    return tr, signers


def _make_package(tmp_path: Path):
    tr, signers = _trust_root()
    evidence_root = tmp_path / "evidence"
    (evidence_root / "act-1").mkdir(parents=True)
    (evidence_root / "act-1" / "response.http").write_text("HTTP/1.1 200 OK\n\nadmin row leaked", "utf-8")
    out = tmp_path / "pkg"
    summary = build_audit_package(
        out, findings=[_finding("act-1")], signers=signers, trust_root=tr,
        evidence_root=evidence_root, scope="# Scope\n127.0.0.1 only", charter="# Charter\nauthorized",
        engagement_slug="demo")
    assert summary["ok"], summary
    return out, summary["fingerprint"]


def _run_verifier(pkg: Path, *, fingerprint: str | None, cwd: Path) -> subprocess.CompletedProcess:
    args = [sys.executable, str(pkg / "verify_offline.py"), "--package", str(pkg)]
    if fingerprint is not None:
        args += ["--trust-root-fingerprint", fingerprint]
    return subprocess.run(args, capture_output=True, text=True, cwd=str(cwd))


# ---- the standalone verifier truly imports no VIGIL ----------------------------------------------

def test_offline_verifier_imports_no_vigil(tmp_path: Path) -> None:
    pkg, _ = _make_package(tmp_path)
    src = (pkg / "verify_offline.py").read_text("utf-8")
    tree = ast.parse(src)
    banned = ("framework", "vigil", "vigil_core")
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                assert root not in banned, f"verify_offline.py imports {alias.name!r}"
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            assert root not in banned, f"verify_offline.py imports from {node.module!r}"


# ---- happy path: generated package re-verifies OFFLINE ------------------------------------------

def test_generated_package_reverifies_offline(tmp_path: Path) -> None:
    pkg, fingerprint = _make_package(tmp_path)
    # sanity: the package is self-contained.
    for name in ("evidence-bundle.json", "contexts.json", "trust-root.json", "TRUST-ROOT-FINGERPRINT.txt",
                 "reverifiable.json", "verify_offline.py", "SCOPE.md", "CHARTER.md", "RUNBOOK.md"):
        assert (pkg / name).exists(), f"missing {name}"
    assert (pkg / "TRUST-ROOT-FINGERPRINT.txt").read_text("utf-8").strip() == fingerprint

    r = _run_verifier(pkg, fingerprint=fingerprint, cwd=tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "SOUND" in r.stdout and "NOT SOUND" not in r.stdout


# ---- every tamper class is rejected --------------------------------------------------------------

def test_wrong_fingerprint_pin_rejected(tmp_path: Path) -> None:
    pkg, _ = _make_package(tmp_path)
    r = _run_verifier(pkg, fingerprint="sha256:" + "0" * 64, cwd=tmp_path)
    assert r.returncode != 0 and "NOT SOUND" in r.stdout


def test_flipped_signature_rejected(tmp_path: Path) -> None:
    pkg, fingerprint = _make_package(tmp_path)
    bundle = json.loads((pkg / "evidence-bundle.json").read_text("utf-8"))
    # corrupt ALL of the cert's signatures — below the m-of-n threshold, authenticity must fail.
    for s in bundle["certificates"][0]["signatures"]:
        sig = s["signature_b64"]
        s["signature_b64"] = ("B" if sig[0] != "B" else "C") + sig[1:]
    (pkg / "evidence-bundle.json").write_text(json.dumps(bundle, indent=2, sort_keys=True), "utf-8")
    r = _run_verifier(pkg, fingerprint=fingerprint, cwd=tmp_path)
    assert r.returncode != 0 and "NOT SOUND" in r.stdout


def test_altered_oracle_context_breaks_binding(tmp_path: Path) -> None:
    pkg, fingerprint = _make_package(tmp_path)
    contexts = json.loads((pkg / "contexts.json").read_text("utf-8"))
    ref = next(iter(contexts))
    contexts[ref]["_tamper"] = "injected"      # any change flips the digest → binding fails
    (pkg / "contexts.json").write_text(json.dumps(contexts, sort_keys=True), "utf-8")
    r = _run_verifier(pkg, fingerprint=fingerprint, cwd=tmp_path)
    assert r.returncode != 0 and "NOT SOUND" in r.stdout


def test_mutated_artifact_rejected(tmp_path: Path) -> None:
    pkg, fingerprint = _make_package(tmp_path)
    art = pkg / "evidence" / "act-1" / "response.http"
    assert art.exists(), "artifact should have been packaged"
    art.write_text("HTTP/1.1 200 OK\n\nTAMPERED", "utf-8")
    r = _run_verifier(pkg, fingerprint=fingerprint, cwd=tmp_path)
    assert r.returncode != 0 and "NOT SOUND" in r.stdout


def test_deleted_chain_entry_rejected(tmp_path: Path) -> None:
    pkg, fingerprint = _make_package(tmp_path)
    bundle = json.loads((pkg / "evidence-bundle.json").read_text("utf-8"))
    if len(bundle["chain"]) >= 1:
        bundle["chain"] = bundle["chain"][:-1]     # drop the last entry → cert-set mismatch + head mismatch
    (pkg / "evidence-bundle.json").write_text(json.dumps(bundle, indent=2, sort_keys=True), "utf-8")
    r = _run_verifier(pkg, fingerprint=fingerprint, cwd=tmp_path)
    assert r.returncode != 0 and "NOT SOUND" in r.stdout
