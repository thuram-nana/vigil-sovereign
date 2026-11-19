"""APEX PR-3 — END-TO-END acceptance: a confirmed FACT → chained impact path → gated fix PR → signed NEGATIVE
remediation cert that re-verifies OFFLINE → scheduled retest proves-clean → a re-introduced regression RE-OPENS.

This is the whole "Impact & Closure" story in one test, over a single drivable oracle (``error_based_sqli`` on
the ``error_signature`` channel — fires on a SQL error, silent on a benign body). Every promotion is earned by
oracle re-execution; nothing is asserted. Needs framework → the ``off`` leg (integration + engine/crucible).
"""
from __future__ import annotations

import pytest

from vigil_core import generate_keypair
from vigil_core.retest_reproof import CLEARED, STILL_PRESENT
from vigil_integration.autopatch import BuildResult, CloneResult, PatchApproval, PrResult, QuorumOutcome
from vigil_integration.jobs.apex_retest_scheduler import RetestRegistry, WatchedFinding, run_cadence_tick
from vigil_integration.remediation import TriageFinding
from vigil_integration.remediation.apex_pcr import close_remediation_loop

# OFFENSE plane: the real framework imports are LAZY (inside the test body / oracle-context builder), so this
# module-scope probe makes the suite SKIP in the sovereign (keyless) leg of the two-env job and RUN in the
# offense leg — the framework-guard pattern (cf. test_backup_dr_drill_coverage.py). Listed in ci.yml offense leg.
pytest.importorskip("framework.v2.evidence.poc")

SIGNER = generate_keypair()
SIGNERS = [("root0", SIGNER.private_key_b64)]
PUBKEYS = {"root0": SIGNER.public_key_b64}

_SQL_ERROR = b"HTTP/1.1 500\r\n\r\nYou have an error in your SQL syntax near ''"
_BENIGN = b"HTTP/1.1 200\r\n\r\n{\"results\": []}"

DIFF = ("--- a/src/app.py\n+++ b/src/app.py\n@@ -1,3 +1,3 @@\n def q(u):\n"
        '-    db.execute("SELECT * FROM t WHERE u=" + u)\n'
        '+    db.execute("SELECT * FROM t WHERE u=?", (u,))\n')


def _context(body: bytes) -> dict:
    from framework.v2.evidence.poc import CapturedExchange
    from framework.v2.verify.poc_translate import context_from_exchanges
    ex = CapturedExchange(channel="error_signature", role="mutated", response_bytes_ref="resp")
    ctx = context_from_exchanges([ex], bug_class="error_based_sqli", resolve=lambda r: body)
    return ctx.model_dump(mode="json")


def _fact():
    return TriageFinding(ref="errsqli-1", confirmed=True, evidence_ref="cert:errsqli-1",
                         bug_class="error_based_sqli", severity="critical", title="SQLi",
                         target="127.0.0.1:18080", spine_hash="sh-1", target_repo="git@example.com:app/app.git")


class _V:
    def __init__(self, allowed, outcome, reason=""):
        self.allowed, self.outcome, self.reason = allowed, outcome, reason


def test_apex_impact_and_closure_end_to_end(monkeypatch):
    monkeypatch.setenv("VIGIL_APEX_IMPACT", "1")
    finding = _fact()
    confirmed_ctx = _context(_SQL_ERROR)       # the ORIGINAL confirmed finding's context — the FACT (it fires)

    # ---- 1) CHAINED IMPACT PATH — the confirmed foothold re-reproduces and reaches a DATASTORE crown jewel ----
    from framework.v2.apex_impact import ImpactReport, pursue_impact
    from framework.v2.scanner.campaign import ScanReport
    from framework.v2.scanner.engine import AuditFinding
    from framework.v2.scanner.orchestrator import AttackPath, ChainedConclusion
    from framework.v2.worldmodel.graph import WorldModel
    from framework.v2.worldmodel.models import Node, NodeKind

    report = ScanReport(target="http://t/", active_findings=[
        AuditFinding(check_id="errsqli-1", bug_class="error_based_sqli", insertion_point="query_value:q",
                     param="q", confidence=0.95, confirmed_by="error_signature", oracle_context=confirmed_ctx)])
    world = WorldModel()
    world.add_node(Node(id="datastore:x", kind=NodeKind.DATASTORE, attrs={"detail": "backing store"},
                        provenance="t", confidence=1.0, first_seen=1, last_seen=1))
    path = AttackPath(steps=[
        ChainedConclusion(src="attacker:self", edge="REACHED", dst="endpoint:q",
                          technique="finding:error_based_sqli"),
        ChainedConclusion(src="endpoint:q", edge="TRUSTS_FOR", dst="datastore:x",
                          technique="finding:error_based_sqli")])
    impact = pursue_impact(report, world, [path], slug="acme", target_url="http://127.0.0.1:18080/")
    assert isinstance(impact, ImpactReport) and impact.demonstrated_paths == 1
    demo = impact.demonstrations[0]
    assert demo.demonstrated and demo.terminal_impact == "data_access" and "errsqli-1" in demo.foothold_findings

    # ---- 2) GATED FIX PR → signed NEGATIVE remediation cert that RE-VERIFIES OFFLINE ----
    def _redrive(_req, _pb):   # the PATCHED build answers benign ⇒ the original exploit oracle goes SILENT
        return {"exchanges": [{"channel": "error_signature", "role": "mutated", "response_bytes_ref": "resp"}],
                "blobs": {"resp": _BENIGN}}

    pcr = close_remediation_loop(
        finding, positive_control_context=confirmed_ctx, signers=SIGNERS, signer_pubkeys=PUBKEYS,
        engagement_slug="acme", redrive=_redrive, propose_patch=lambda req: DIFF,
        gate=lambda tool, target, destructive=False, **_k: _V(True, "allow"),
        clone=lambda req: CloneResult(ok=True, workdir="/wd", branch=req.fix_branch),
        build=lambda req, approved: BuildResult(ok=True, build_ref="build:1"),
        open_pr=lambda req, approved: PrResult(ok=True, pr_ref="pr:1"),
        quorum=lambda req: QuorumOutcome(approved=True, reason="2-of-3"),
        approval=lambda pf: PatchApproval(decision="approve", deadline=100.0), now=lambda: 50.0,
        bug_class="error_based_sqli", expected_channel="error_signature",
        target_repo="git@example.com:app/app.git")
    assert pcr.status == "remediated-certified" and pcr.certified, pcr.reason
    assert pcr.patch_result.opened_pr and pcr.patch_result.pr_ref == "pr:1"
    # the NEGATIVE cert re-verifies OFFLINE, independently (an auditor trusting neither the loop nor a target)
    from vigil_integration.remediation.remediation_cert import verify_remediation_certificate
    v = verify_remediation_certificate(pcr.remediation_cert, signer_pubkeys=PUBKEYS)
    assert v.ok and v.silent and v.control_fires and v.live and v.bound and v.authentic, v.reason

    # ---- 3) CONTINUOUS RETEST — the fix is proven to STAY fixed, then a regression RE-OPENS the finding ----
    reg = RetestRegistry()
    reg.watch(WatchedFinding(slug="acme", finding_ref="errsqli-1", bug_class="error_based_sqli",
                             interval_s=100.0))

    # the patched build stays silent ⇒ the scheduled re-fire proves clean (positive evidence of clearance)
    clean = run_cadence_tick(reg, now=0.0, refire=lambda wf: {"fired": False, "reason": "fix holds"})
    assert clean[0].verdict == CLEARED and not clean[0].reopened

    # a regression is re-introduced (the vulnerability comes back) ⇒ the next cadence tick RE-OPENS the finding
    regression = run_cadence_tick(reg, now=100.0, refire=lambda wf: {"fired": True, "reason": "SQLi is back"})
    assert regression[0].verdict == STILL_PRESENT and regression[0].regression and regression[0].reopened
    assert [w.finding_ref for w in reg.reopened_findings()] == ["errsqli-1"]
