"""APEX PR-3 Deliverable 2 — the autonomous proof-carrying-remediation CLOSE-THE-LOOP.

The through-line: a confirmed FACT is driven through the gated auto-patch PR to a signed NEGATIVE remediation
certificate that re-verifies OFFLINE — and NOTHING weaker is ever reported as a clearance. Reuses the
``error_signature`` / ``error_based_sqli`` oracle (fires on a SQL error, silent on a benign body — the same
drivable oracle ``test_remediation_cert`` uses) and the ``autopatch`` fake executors.

Needs framework (reverify + the oracle) → PYTHONPATH=integration:engine/crucible:gateway:packages/core/vigil_core.
"""
from __future__ import annotations

import pytest

from vigil_core import generate_keypair
from vigil_integration.autopatch import BuildResult, CloneResult, PatchApproval, PrResult, QuorumOutcome
from vigil_integration.remediation import TriageFinding
from vigil_integration.remediation.apex_pcr import ApexPcrResult, close_remediation_loop

SIGNER = generate_keypair()
SIGNERS = [("root0", SIGNER.private_key_b64)]
PUBKEYS = {"root0": SIGNER.public_key_b64}

_SQL_ERROR = b"HTTP/1.1 500\r\n\r\nYou have an error in your SQL syntax near ''"
_BENIGN = b"HTTP/1.1 200\r\n\r\n{\"results\": []}"

DIFF = (
    "diff --git a/src/app.py b/src/app.py\n"
    "--- a/src/app.py\n+++ b/src/app.py\n@@ -1,3 +1,3 @@\n def q(u):\n"
    '-    db.execute("SELECT * FROM t WHERE u=" + u)\n'
    '+    db.execute("SELECT * FROM t WHERE u=?", (u,))\n'
)


def _context(body: bytes) -> dict:
    """An error_signature oracle_context from a captured response (the translator the mint/verify use)."""
    from framework.v2.evidence.poc import CapturedExchange
    from framework.v2.verify.poc_translate import context_from_exchanges
    ex = CapturedExchange(channel="error_signature", role="mutated", response_bytes_ref="resp")
    ctx = context_from_exchanges([ex], bug_class="error_based_sqli", resolve=lambda r: body)
    assert ctx is not None
    return ctx.model_dump(mode="json")


def _fact(ref="errsqli-1"):
    return TriageFinding(ref=ref, confirmed=True, evidence_ref=f"cert:{ref}", bug_class="error_based_sqli",
                         severity="critical", title=f"{ref}", target="127.0.0.1:18080", spine_hash=f"sh-{ref}",
                         target_repo="git@example.com:app/app.git")


def _lead(ref="lead-1"):
    return TriageFinding(ref=ref, confirmed=False, bug_class="error_based_sqli", severity="critical", title=ref)


def _redrive(body: bytes):
    """A re-drive that hands back the PATCHED build's response to the original exploit (the shape fix_oracle
    expects): a benign body ⇒ the oracle goes silent (fixed); the SQL error ⇒ still fires (not fixed)."""
    def redrive(_request, _patched_build):
        return {"exchanges": [{"channel": "error_signature", "role": "mutated", "response_bytes_ref": "resp"}],
                "blobs": {"resp": body}}
    return redrive


class _V:
    def __init__(self, allowed, outcome, reason=""):
        self.allowed, self.outcome, self.reason = allowed, outcome, reason


def _allow_gate(tool, target, destructive=False, **_k):
    return _V(True, "allow", f"allow {tool}")


def _deny_gate(tool, target, destructive=False, **_k):
    return _V(False, "deny", f"deny {tool}")


def _clone_ok(req):
    return CloneResult(ok=True, workdir="/sandbox/wd", branch=req.fix_branch)


def _build_ok(req, approved):
    return BuildResult(ok=True, build_ref="build:patched:1")


def _pr_ok(req, approved):
    return PrResult(ok=True, pr_ref="pr:1")


def _quorum_yes(req):
    return QuorumOutcome(approved=True, reason="2-of-3 (owner-inclusive)")


def _quorum_no(req):
    return QuorumOutcome(approved=False, reason="only 1 of 2 signers")


def _approve(pf):
    return PatchApproval(decision="approve", deadline=100.0)


def _clock():
    return 50.0


def _propose(req):
    return DIFF


def _close(finding, *, control, redrive, gate=_allow_gate, quorum=_quorum_yes, **over):
    return close_remediation_loop(
        finding, positive_control_context=control, signers=SIGNERS, signer_pubkeys=PUBKEYS,
        engagement_slug="acme", redrive=redrive, propose_patch=_propose, gate=gate, clone=_clone_ok,
        build=_build_ok, open_pr=_pr_ok, quorum=quorum, approval=_approve, now=_clock,
        bug_class="error_based_sqli", expected_channel="error_signature",
        target_repo="git@example.com:app/app.git", **over)


# =====================================================================================================
# the happy path — a confirmed FACT → gated PR → signed NEGATIVE cert that re-verifies offline
# =====================================================================================================


def test_close_loop_mints_and_verifies_negative_cert(monkeypatch):
    monkeypatch.setenv("VIGIL_APEX_IMPACT", "1")
    res = _close(_fact(), control=_context(_SQL_ERROR), redrive=_redrive(_BENIGN))
    assert isinstance(res, ApexPcrResult)
    assert res.status == "remediated-certified", res.reason
    assert res.certified and res.remediated
    # a gated PR actually opened
    assert res.patch_result is not None and res.patch_result.opened_pr and res.patch_result.pr_ref == "pr:1"
    # the v2 NEGATIVE cert was minted and re-verifies OFFLINE (silent + control fires + live + bound + authentic)
    assert isinstance(res.remediation_cert, dict)
    assert res.remediation_cert["schema"] == "vigil-remediation-cert-v2"
    v = res.offline_verification
    assert v is not None and v.ok and v.silent and v.control_fires and v.live and v.bound and v.authentic, v.reason


def test_certificate_re_verifies_independently_offline(monkeypatch):
    monkeypatch.setenv("VIGIL_APEX_IMPACT", "1")
    res = _close(_fact(), control=_context(_SQL_ERROR), redrive=_redrive(_BENIGN))
    # re-verify the MINTED cert from scratch, as an auditor would (no target, no trust in the loop that made it)
    from vigil_integration.remediation.remediation_cert import verify_remediation_certificate
    v = verify_remediation_certificate(res.remediation_cert, signer_pubkeys=PUBKEYS)
    assert v.ok, v.reason
    # a wrong pinned key fails authenticity (the signature is load-bearing)
    attacker = generate_keypair()
    v2 = verify_remediation_certificate(res.remediation_cert, signer_pubkeys={"root0": attacker.public_key_b64})
    assert not v2.ok and not v2.authentic


# =====================================================================================================
# the sovereign FACT-gate — a LEAD can never be remediated
# =====================================================================================================


def test_lead_is_refused(monkeypatch):
    monkeypatch.setenv("VIGIL_APEX_IMPACT", "1")
    res = _close(_lead(), control=_context(_SQL_ERROR), redrive=_redrive(_BENIGN))
    assert res.status == "refused-not-confirmed"
    assert not res.certified and not res.remediated
    assert res.remediation_cert is None and res.patch_result is None   # nothing proposed, no PR, no cert


# =====================================================================================================
# default-OFF — inert, byte-identical
# =====================================================================================================


def test_flag_off_is_inert(monkeypatch):
    monkeypatch.delenv("VIGIL_APEX_IMPACT", raising=False)
    res = _close(_fact(), control=_context(_SQL_ERROR), redrive=_redrive(_BENIGN))
    assert res.status == "disabled"
    assert not res.certified and not res.remediated
    assert res.remediation_cert is None and res.patch_result is None


# =====================================================================================================
# fail-closed — a still-vulnerable patched build is never certified; a missing twin is refused
# =====================================================================================================


def test_still_vulnerable_patched_build_is_not_certified(monkeypatch):
    monkeypatch.setenv("VIGIL_APEX_IMPACT", "1")
    # the patched build STILL answers with the SQL error ⇒ the oracle fires ⇒ not remediated, no cert
    res = _close(_fact(), control=_context(_SQL_ERROR), redrive=_redrive(_SQL_ERROR))
    assert not res.certified and not res.remediated
    assert res.remediation_cert is None
    assert res.status.startswith("patch-")   # the PR opened but the fix was not oracle-confirmed


def test_non_firing_positive_control_is_not_certified(monkeypatch):
    monkeypatch.setenv("VIGIL_APEX_IMPACT", "1")
    # the "twin" does not fire (benign body) ⇒ silence on the patched build is not a proof ⇒ mint refuses,
    # the oracle reports no silence, and the loop returns an uncertified PR (never a fabricated clearance).
    res = _close(_fact(), control=_context(_BENIGN), redrive=_redrive(_BENIGN))
    assert not res.certified and not res.remediated
    assert res.remediation_cert is None


def test_missing_positive_control_is_refused(monkeypatch):
    monkeypatch.setenv("VIGIL_APEX_IMPACT", "1")
    res = _close(_fact(), control={}, redrive=_redrive(_BENIGN))
    assert res.status == "refused-not-confirmed" and res.remediation_cert is None


def test_pr_quorum_not_met_blocks_certification(monkeypatch):
    monkeypatch.setenv("VIGIL_APEX_IMPACT", "1")
    # the m-of-n destruction quorum is the gate on the PR leg: without it, no PR opens and nothing is certified.
    res = _close(_fact(), control=_context(_SQL_ERROR), redrive=_redrive(_BENIGN), quorum=_quorum_no)
    assert not res.certified and not res.remediated
    assert res.remediation_cert is None   # the mint is reached only AFTER the gated PR opens


def test_request_side_class_is_not_oracle_provable(monkeypatch):
    monkeypatch.setenv("VIGIL_APEX_IMPACT", "1")
    # a request-side oracle family cannot be soundly re-verified by a patch (the patch changes the response,
    # not the request) — an honest, named boundary, never a false clearance.
    res = close_remediation_loop(
        _fact(), positive_control_context=_context(_SQL_ERROR), signers=SIGNERS, signer_pubkeys=PUBKEYS,
        engagement_slug="acme", redrive=_redrive(_BENIGN), propose_patch=_propose, gate=_allow_gate,
        clone=_clone_ok, build=_build_ok, open_pr=_pr_ok, quorum=_quorum_yes, approval=_approve, now=_clock,
        bug_class="error_based_sqli", expected_channel="request_payload")
    assert res.status == "not-oracle-provable" and res.remediation_cert is None
