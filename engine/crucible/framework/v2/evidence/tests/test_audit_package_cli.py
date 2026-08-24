"""W16-16 (#522) — the H4 external-audit package has a REAL invocation path: `evidence audit-package`.

`evidence.audit_package.build_audit_package` shipped tested but was reachable from no verb/route/button (it
was imported only by evidence/__init__.py's re-export + its own tests). This proves the new
`python3 -m framework.v2 evidence audit-package` subcommand builds a package end-to-end AND that the shipped
standalone verifier re-verifies it OFFLINE (RESULT: SOUND) — the same offline property test_audit_package.py
proves for the library, now reached through the CLI a human actually types.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from framework.v2.entitlement.crypto import generate_keypair
from framework.v2.entitlement.models import AuthorizerKey, TrustRoot
from framework.v2.evidence import cli as ecli
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.confirmation import confirm_finding

_BASE = {"status": 200, "body": "No results found."}
_DIVERGENT = {"status": 200, "body": "id=1 name=alice role=user\nid=2 name=bob role=admin"}


def _finding() -> dict:
    ctx = FindingContext.from_http_responses(
        _BASE, _DIVERGENT, bug_class="boolean_sqli",
        discriminator={"dimensions": ["status", "length", "lexical"]})
    confirmed = confirm_finding(finding={"bug_class": "boolean_sqli"}, context=ctx)
    return {
        "check_id": "boolean-sqli", "bug_class": "boolean_sqli", "action_id": "act-1",
        "confirmed_by": confirmed.confirmed_by.value if confirmed else "differential_response",
        "confidence": 0.9, "oracle_context": ctx.model_dump(mode="json"),
    }


def test_audit_package_cli_builds_a_package_that_reverifies_offline(tmp_path: Path):
    kps = [generate_keypair() for _ in range(2)]
    tr = TrustRoot(schema_version=1, threshold=2, authorizers=[
        AuthorizerKey(key_id=f"gov-{i}", name=f"a{i}", public_key_b64=k.public_key_b64)
        for i, k in enumerate(kps)])
    (tmp_path / "report.json").write_text(json.dumps({"active_findings": [_finding()]}), "utf-8")
    (tmp_path / "tr.json").write_text(tr.model_dump_json(), "utf-8")
    pkg = tmp_path / "pkg"

    argv = ["audit-package", "--report", str(tmp_path / "report.json"), "--out", str(pkg),
            "--trust-root", str(tmp_path / "tr.json"), "--slug", "cli-test"]
    for i, k in enumerate(kps):
        argv += ["--signer", f"gov-{i}:{k.private_key_b64}"]
    assert ecli.main(argv) == 0

    # the shipped standalone verifier (stdlib + cryptography, NO VIGIL import) re-verifies OFFLINE.
    fp = (pkg / "TRUST-ROOT-FINGERPRINT.txt").read_text(encoding="utf-8").strip()
    r = subprocess.run([sys.executable, "verify_offline.py", "--package", ".",
                        "--trust-root-fingerprint", fp], cwd=str(pkg), capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "RESULT: SOUND" in r.stdout


def test_audit_package_cli_refuses_without_a_signer(tmp_path: Path, capsys):
    # NEGATIVE CONTROL: an audit package carries SIGNED certificates — no --signer is refused, not a silent
    # unsigned package.
    tr = TrustRoot(schema_version=1, threshold=1, authorizers=[
        AuthorizerKey(key_id="gov-0", name="a", public_key_b64=generate_keypair().public_key_b64)])
    (tmp_path / "report.json").write_text(json.dumps({"active_findings": [_finding()]}), "utf-8")
    (tmp_path / "tr.json").write_text(tr.model_dump_json(), "utf-8")
    rc = ecli.main(["audit-package", "--report", str(tmp_path / "report.json"),
                    "--out", str(tmp_path / "pkg"), "--trust-root", str(tmp_path / "tr.json")])
    assert rc == 2
    assert not (tmp_path / "pkg").exists()
    assert "signer" in capsys.readouterr().err.lower()
