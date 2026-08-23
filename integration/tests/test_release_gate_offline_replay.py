"""Release gate — OFFLINE BUNDLE REPLAY ON A SEPARATE MACHINE, as an honest scoreboard.

WHAT THIS FILE IS. The release gate (plan Part III / gate #6) requires that "Every FACT re-verifies offline
on a clean machine", proven by ``python -m framework.v2 evidence verify … --trust-root-fingerprint …`` on a
"separate machine with no VIGIL on the path". The genuinely VIGIL-free realisation of that is the STANDALONE
verifier VIGIL ships VERBATIM inside every audit package — ``verify_offline.py`` (``evidence.audit_package``
→ ``audit_offline_verifier``), which imports NOTHING from ``framework`` / ``vigil`` (stdlib + ``cryptography``
only). The reference engine verifier exists too, but it *needs* the engine; this board proves the claim that
matters for an external auditor — the bundle replays SOUND with neither framework NOR VIGIL importable.

The existing ``framework/v2/evidence/tests/test_audit_package.py`` proves the verifier's SOURCE imports no
VIGIL (AST) and runs it as a subprocess — but it does not control the subprocess's import PATH, so on a box
where ``framework`` is on ``PYTHONPATH`` (both CI legs) that subprocess COULD still import it. This board
closes that gap: it runs the verifier in an interpreter whose path genuinely cannot reach ``framework`` /
``vigil_integration`` / ``vigil_core`` (``python -S`` disables editable ``.pth``/finder installs; a
``PYTHONPATH`` of ONLY the ``cryptography`` site-dir removes the engine path while keeping the verifier's one
real dependency) — and it PROVES that scrub with an in-band probe before trusting the verdict.

HOW IT STAYS HONEST (model: ``test_production_invariants.py``). Each row asserts the TRUE bar; a bar the
infra cannot meet in CI is ``@pytest.mark.xfail(strict=True, reason="<slice>")``. The SOUND row is paired
with tamper negative controls (mutated artifact, wrong pin, missing pin) proving "SOUND" is a real
difference, not a verifier that always exits 0.

FRAMEWORK-DEPENDENT (the MINTING side builds the package). This file ``importorskip``s ``framework`` and MUST
be listed in the ci.yml offense-leg run-list (enforced by ``test_ci_framework_tests_run_in_offense_leg``). It
skips cleanly in the sovereign leg. The VERIFYING side is what runs framework-free, in a scrubbed subprocess.
"""
from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("framework.v2.evidence.audit_package", reason="CRUCIBLE (framework) not importable in this leg")
_crypto = pytest.importorskip("cryptography", reason="the standalone verifier's one real dependency is absent")

from framework.v2.entitlement.crypto import generate_keypair  # noqa: E402
from framework.v2.entitlement.models import AuthorizerKey, TrustRoot  # noqa: E402
from framework.v2.evidence.audit_package import build_audit_package  # noqa: E402
from framework.v2.verify.adapter import FindingContext  # noqa: E402
from framework.v2.verify.confirmation import confirm_finding  # noqa: E402

_BASE = {"status": 200, "body": "No results found."}
_DIVERGENT = {"status": 200,
              "body": "id=1 name=alice role=user\nid=2 name=bob role=admin\nid=3 name=carol role=user"}

# The cryptography site-dir — the ONLY third-party path the scrubbed verifier is allowed to see.
_CRYPTO_SITE = str(Path(_crypto.__file__).resolve().parent.parent)

_SEPARATE_HOST_SLICE = "air-gapped SEPARATE-HOST replay (transfer the package to a different physical machine over no shared filesystem, then verify) — needs a second host the single-runner P5 job does not have"


# ---------------------------------------------------------------------------------------------------------
# Building a real signed package (the minting side — uses framework, in-process).
# ---------------------------------------------------------------------------------------------------------
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


def _make_package(tmp_path: Path) -> tuple[Path, str]:
    keys = [generate_keypair() for _ in range(3)]
    tr = TrustRoot(schema_version=1, threshold=2, authorizers=[
        AuthorizerKey(key_id=f"gov-{i}", name=f"Authoriser {i}", public_key_b64=k.public_key_b64)
        for i, k in enumerate(keys)])
    signers = [(f"gov-{i}", k.private_key_b64) for i, k in enumerate(keys)]
    ev = tmp_path / "evidence"
    (ev / "act-1").mkdir(parents=True)
    (ev / "act-1" / "response.http").write_text("HTTP/1.1 200 OK\n\nadmin row leaked", "utf-8")
    out = tmp_path / "pkg"
    summary = build_audit_package(
        out, findings=[_finding("act-1")], signers=signers, trust_root=tr, evidence_root=ev,
        scope="# Scope\n127.0.0.1 only", charter="# Charter\nauthorized", engagement_slug="demo")
    assert summary["ok"], summary
    return out, summary["fingerprint"]


# ---------------------------------------------------------------------------------------------------------
# The scrub: an interpreter that CANNOT import framework / vigil, but CAN import cryptography.
# ---------------------------------------------------------------------------------------------------------
def _scrub_env() -> dict[str, str]:
    """Env for the VIGIL-free verifier: PYTHONPATH is REPLACED with only the cryptography site-dir, so the
    engine path (integration:engine/crucible:gateway in CI) is gone; combined with ``python -S`` (which
    disables site processing, hence every editable ``.pth`` / finder install) neither framework nor any
    vigil_* package can be reached."""
    return {**os.environ, "PYTHONPATH": _CRYPTO_SITE}


def _scrub_argv(*args: str) -> list[str]:
    return [sys.executable, "-S", *args]


def _run_scrubbed(*args: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(_scrub_argv(*args), capture_output=True, text=True, cwd=str(cwd), env=_scrub_env())


def _run_verifier(pkg: Path, *, fingerprint: str | None, cwd: Path) -> subprocess.CompletedProcess:
    argv = [str(pkg / "verify_offline.py"), "--package", str(pkg)]
    if fingerprint is not None:
        argv += ["--trust-root-fingerprint", fingerprint]
    return _run_scrubbed(*argv, cwd=cwd)


# =========================================================================================================
# THE PROOF: the verifier's interpreter genuinely has neither framework nor VIGIL on the path.
# =========================================================================================================
_PROBE = (
    "import importlib.util as u, sys, json;"
    "print(json.dumps({"
    "'framework': u.find_spec('framework') is not None,"
    "'vigil_integration': u.find_spec('vigil_integration') is not None,"
    "'vigil_core': u.find_spec('vigil_core') is not None,"
    "'vigil_gateway': u.find_spec('vigil_gateway') is not None,"
    "'cryptography': u.find_spec('cryptography') is not None}))"
)


def test_the_verifier_runs_with_framework_and_vigil_OFF_the_path(tmp_path):
    """Run the SAME scrubbed interpreter the verifier uses and probe its import world: framework and every
    vigil_* package must be UNreachable, while cryptography (the verifier's one real dependency) IS reachable.
    This is the "separate machine, no VIGIL on the path" claim, proven — not assumed from the source."""
    proc = _run_scrubbed("-c", _PROBE, cwd=tmp_path)
    assert proc.returncode == 0, proc.stderr or proc.stdout
    world = json.loads(proc.stdout.strip())
    assert world["framework"] is False, "framework IS importable in the verifier env — the scrub failed"
    assert world["vigil_integration"] is False and world["vigil_core"] is False and world["vigil_gateway"] is False, (
        f"a vigil_* package is importable in the verifier env — not a VIGIL-free machine: {world}"
    )
    assert world["cryptography"] is True, (
        "cryptography is NOT importable in the scrubbed env — this is a blanket outage, so 'no framework' "
        "would prove nothing (the verifier itself could not run)"
    )


def test_the_shipped_verifier_source_imports_no_vigil(tmp_path):
    """Complements the runtime proof with a source proof: the shipped ``verify_offline.py`` imports nothing
    from framework / vigil / vigil_core (AST). Runtime absence + source cleanliness together mean the
    verifier neither wants nor can reach any VIGIL code."""
    pkg, _ = _make_package(tmp_path)
    tree = ast.parse((pkg / "verify_offline.py").read_text("utf-8"))
    banned = {"framework", "vigil", "vigil_core", "vigil_integration", "vigil_gateway"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] not in banned, f"imports {alias.name!r}"
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] not in banned, f"imports from {node.module!r}"


# =========================================================================================================
# THE REPLAY: a signed bundle re-verifies SOUND with framework off the path.
# =========================================================================================================
def test_a_signed_bundle_replays_SOUND_on_a_vigil_free_verifier(tmp_path):
    pkg, fingerprint = _make_package(tmp_path)
    r = _run_verifier(pkg, fingerprint=fingerprint, cwd=tmp_path)
    assert r.returncode == 0, f"the bundle did NOT replay on a VIGIL-free verifier: {r.stdout}\n{r.stderr}"
    assert "SOUND" in r.stdout and "NOT SOUND" not in r.stdout, r.stdout


def test_negative_control_a_mutated_artifact_is_NOT_SOUND(tmp_path):
    """Non-vacuity: the SAME VIGIL-free verifier rejects a package whose raw evidence artifact was changed
    after signing. So "SOUND" above is a real re-computation over the bytes, not a verifier that always
    exits 0."""
    pkg, fingerprint = _make_package(tmp_path)
    (pkg / "evidence" / "act-1" / "response.http").write_text("HTTP/1.1 200 OK\n\nTAMPERED", "utf-8")
    r = _run_verifier(pkg, fingerprint=fingerprint, cwd=tmp_path)
    assert r.returncode != 0 and "NOT SOUND" in r.stdout, r.stdout


def test_a_wrong_out_of_band_pin_is_rejected(tmp_path):
    pkg, _ = _make_package(tmp_path)
    r = _run_verifier(pkg, fingerprint="sha256:" + "0" * 64, cwd=tmp_path)
    assert r.returncode != 0 and "NOT SOUND" in r.stdout, r.stdout


def test_a_missing_out_of_band_pin_is_fail_closed_not_sound(tmp_path):
    """Without the out-of-band pin the shipped trust root is unauthenticated, so even a structurally-perfect
    package must be NOT SOUND / non-zero — a forgotten pin can never surface as a clean SOUND."""
    pkg, _ = _make_package(tmp_path)
    r = _run_verifier(pkg, fingerprint=None, cwd=tmp_path)
    assert r.returncode != 0 and "authenticity UNPROVEN" in r.stdout, r.stdout
    assert r.stdout.count("SOUND") == r.stdout.count("NOT SOUND"), (
        "a 'SOUND' token appeared outside 'NOT SOUND' with no pin"
    )


# =========================================================================================================
# A truly SEPARATE physical host (air-gap transfer) is not runnable in CI — an honest xfail.
# =========================================================================================================
@pytest.mark.xfail(strict=True, reason=_SEPARATE_HOST_SLICE)
def test_replay_on_a_second_physical_host_over_an_air_gap(tmp_path):
    """The literal "separate machine": transfer the package to a DIFFERENT physical host with no shared
    filesystem and verify there. The single-runner P5 job has no second host, so this is driven by a harness
    that does not exist yet and xfails cleanly (strict → flips red when a real cross-host harness lands). The
    STRONGER-than-usual same-host proof — framework genuinely off the path — is real above."""
    from framework.v2.evidence import air_gapped_second_host_replay  # noqa: F401  (no such harness yet)

    raise AssertionError("no in-CI harness ships the package to a second physical host and verifies there")


# =========================================================================================================
# The scoreboard itself.
# =========================================================================================================
def test_no_row_is_a_non_strict_xfail():
    module = __import__(__name__, fromlist=["*"])
    for name, obj in vars(module).items():
        if not (name.startswith("test_") and callable(obj)):
            continue
        for mark in getattr(obj, "pytestmark", []):
            if mark.name == "xfail":
                assert mark.kwargs.get("strict"), f"{name} uses a non-strict xfail and would hide a regression"
