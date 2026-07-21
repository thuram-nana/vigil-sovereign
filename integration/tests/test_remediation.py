"""
F10 — CypherFix-style gated autonomous remediation.

The through-line every test defends is the SOVEREIGN INVARIANT of remediation:

  * NO remediation is spawned without an oracle-confirmed FACT — a LEAD triage finding is refused.
  * The per-block approval TIMEOUT auto-REJECTS (fail-closed), never auto-accepts (the redamon flip).
  * A PR opens ONLY after the m-of-n threshold.
  * 'remediated' is signed ONLY after the fix-verification oracle goes SILENT on the patched build.
  * Never a blanket 'git add -A' (explicit, path-validated staging only).
  * Total on malformed triage input; deterministic ordering.

The gate, oracle, executors, quorum, and approval are injected callables, so the whole pipeline runs
without a live kernel, git, or sandbox.
"""

from __future__ import annotations

import pytest

from vigil_integration.graph import SpineRecord, project
from vigil_integration.remediation import (
    TRIAGE_QUERIES,
    ApprovalOutcome,
    BuildResult,
    CloneResult,
    CodeFixRequest,
    CodeFixResult,
    EditBlock,
    FixVerification,
    PrResult,
    QuorumOutcome,
    TriageFinding,
    WriteResult,
    is_safe_repo_path,
    may_remediate,
    parse_edit_blocks,
    render_untrusted_finding,
    run_codefix,
    run_triage,
    severity_rank,
    spawn_remediation,
    verify_fix,
)


# --- graph fixtures --------------------------------------------------------------------------

def _fact(seq, h, ref, severity="high", *, parent_step_id="", targets=None, **props):
    """A signed, oracle-CONFIRMED finding record (evidence_ref + signature_ref ⇒ CONFIRMED node)."""
    return SpineRecord(seq=seq, hash=h, kind="finding", finding_ref=ref, status="fact",
                       evidence_ref=f"cert:{ref}", signature_ref=f"sig:{ref}",
                       parent_step_id=parent_step_id,
                       props={"ref": ref, "severity": severity, **props}, targets=targets or [])


def _lead(seq, h, ref, severity="high", **props):
    return SpineRecord(seq=seq, hash=h, kind="finding", finding_ref=ref, status="lead",
                       props={"ref": ref, "severity": severity, **props})


def _step(seq, h, sid):
    return SpineRecord(seq=seq, hash=h, kind="step", step_id=sid, props={"tool": "sqlmap"})


# --- injected stubs --------------------------------------------------------------------------

class _V:
    def __init__(self, allowed, outcome, reason=""):
        self.allowed, self.outcome, self.reason = allowed, outcome, reason


def _allow_gate(tool, target, destructive):
    return _V(True, "allow", f"allow {tool}")


def _clone_ok(req):
    return CloneResult(ok=True, workdir="/sandbox/wd", branch=req.fix_branch)


def _write_ok(block):
    return WriteResult(ok=True, path=block.path)


def _build_ok(req, paths):
    return BuildResult(ok=True, build_ref="build:patched:1")


class _PrExec:
    """Records exactly what path list the PR stage was asked to stage (to prove it is never 'git add -A')."""

    def __init__(self, ok=True):
        self.ok = ok
        self.staged = None
        self.calls = 0

    def __call__(self, req, paths):
        self.calls += 1
        self.staged = list(paths)
        return PrResult(ok=self.ok, pr_ref="pr:1", reason="" if self.ok else "gh error")


def _quorum_yes(req):
    return QuorumOutcome(approved=True, reason="2-of-3 (owner-inclusive)")


def _quorum_no(req):
    return QuorumOutcome(approved=False, reason="only 1 of 2 signers")


def _approve(block):
    return ApprovalOutcome(decision="approve")


def _oracle_silent(req, build):
    return None                       # the original exploit no longer fires → oracle SILENT


def _oracle_fires(req, build):
    return "cert:still-exploitable"   # the original exploit STILL fires → NOT remediated


def _sign_remediated(req, build):
    return "cert:remediated:1"


def _confirmed_request(ref="f1", severity="critical", repo="git@example.com:app/app.git"):
    view = project([_fact(1, "h1", ref, severity=severity, title=f"{ref} title")])
    draft = run_triage(view)
    assert draft.findings, "confirmed finding should be drafted"
    return spawn_remediation(draft.findings[0], remediation_id="rem-1", target_repo=repo)


def _run(request, edits, **overrides):
    kwargs = dict(gate=_allow_gate, clone=_clone_ok, write_file=_write_ok, build=_build_ok,
                  open_pr=_PrExec(), quorum=_quorum_yes, approve_block=_approve,
                  exploit_oracle=_oracle_silent, sign_remediated=_sign_remediated)
    kwargs.update(overrides)
    return run_codefix(request, edits, **kwargs)


# =============================================================================================
# TRIAGE
# =============================================================================================

def test_nine_deterministic_triage_queries():
    assert len(TRIAGE_QUERIES) == 9
    assert len({q.name for q in TRIAGE_QUERIES}) == 9   # distinct names


def test_only_confirmed_findings_are_drafted_leads_surfaced_separately():
    view = project([
        _fact(1, "h1", "fact-1", severity="high"),
        _lead(2, "h2", "lead-1", severity="critical"),   # a LEAD — never drafted, even at critical
        _fact(3, "h3", "fact-2", severity="low"),
    ])
    draft = run_triage(view)
    assert {f.ref for f in draft.findings} == {"fact-1", "fact-2"}
    assert all(f.confirmed and f.evidence_ref for f in draft.findings)
    assert {lead.ref for lead in draft.leads} == {"lead-1"}
    assert all(not lead.confirmed for lead in draft.leads)


def test_triage_prioritizes_by_severity_then_exploit_signals():
    view = project([
        _fact(1, "h1", "f-med", severity="medium"),
        _fact(2, "h2", "f-high", severity="high"),
        _fact(3, "h3", "f-high-kev", severity="high", cisa_kev=True),
        _fact(4, "h4", "f-crit", severity="critical"),
    ])
    draft = run_triage(view)
    assert [f.ref for f in draft.findings] == ["f-crit", "f-high-kev", "f-high", "f-med"]
    assert [f.priority for f in draft.findings] == [1, 2, 3, 4]


def test_triage_is_deterministic_across_runs():
    recs = [_fact(i, f"h{i}", f"f{i}", severity=s)
            for i, s in enumerate(["high", "critical", "low", "high", "medium"], start=1)]
    view = project(recs)
    a = run_triage(view)
    b = run_triage(view)
    assert [f.ref for f in a.findings] == [f.ref for f in b.findings]
    assert [f.priority for f in a.findings] == [f.priority for f in b.findings]
    assert a.by_severity == b.by_severity


def _fact_prop_ref(seq, h, node_key, prop_ref, severity):
    """A confirmed node whose stable identity (finding_ref) differs from its props 'ref' — used to force
    two DISTINCT graph nodes that resolve to the SAME TriageFinding.ref (a cross-node dedup case)."""
    return SpineRecord(seq=seq, hash=h, kind="finding", finding_ref=node_key, status="fact",
                       evidence_ref=f"cert:{node_key}", signature_ref=f"sig:{node_key}",
                       props={"ref": prop_ref, "severity": severity})


def test_triage_dedups_by_ref_keeping_highest_severity():
    # two DISTINCT confirmed nodes whose props ref collides → collapsed to one, keeping critical.
    view = project([
        _fact_prop_ref(1, "h1", "n-a", "DUP", "high"),
        _fact_prop_ref(2, "h2", "n-b", "DUP", "critical"),
    ])
    draft = run_triage(view)
    dups = [f for f in draft.findings if f.ref == "DUP"]
    assert len(dups) == 1 and dups[0].severity == "critical"


def test_triage_excludes_already_remediated_refs():
    view = project([_fact(1, "h1", "f1"), _fact(2, "h2", "f2")])
    draft = run_triage(view, existing_refs={"f1"})
    assert {f.ref for f in draft.findings} == {"f2"}   # only NEW findings


def test_triage_high_only_filter():
    view = project([_fact(1, "h1", "f-low", severity="low"), _fact(2, "h2", "f-hi", severity="high")])
    draft = run_triage(view, high_only=True)
    assert {f.ref for f in draft.findings} == {"f-hi"}


def test_triage_total_on_malformed_input():
    assert run_triage(None).findings == []
    assert run_triage("not a view").findings == []
    assert run_triage({"nodes": []}).findings == []
    # a garbage prop value never crashes triage
    view = project([_fact(1, "h1", "f1", severity={"weird": "dict"})])
    draft = run_triage(view)
    assert len(draft.findings) == 1


def test_severity_rank_is_total():
    assert severity_rank("CRITICAL") == 4 > severity_rank("high") == 3
    assert severity_rank("nonsense") == -1
    assert severity_rank(None) == -1
    assert severity_rank(12345) == -1


def test_triage_correlation_queries_do_not_admit_leads():
    # a lead correlated to a CVE / on an attack chain is STILL never drafted.
    view = project([
        _step(1, "s1", "st1"),
        _lead(2, "h2", "lead-cve", targets=[{"type": "cve", "value": "CVE-2024-1"}]),
        _fact(3, "h3", "fact-chain", parent_step_id="st1", targets=[{"type": "cve", "value": "CVE-2024-2"}]),
    ])
    draft = run_triage(view)
    assert {f.ref for f in draft.findings} == {"fact-chain"}


# --- the type-level sovereign guard on TriageFinding -----------------------------------------

def test_confirmed_triage_finding_requires_signed_evidence():
    TriageFinding(ref="ok", confirmed=True, evidence_ref="cert:1")     # fine
    TriageFinding(ref="lead", confirmed=False)                          # fine (a lead needs no ref)
    with pytest.raises(ValueError):
        TriageFinding(ref="forged", confirmed=True, evidence_ref="")    # confirmed w/o evidence → refused
    with pytest.raises(ValueError):
        TriageFinding(ref="forged", confirmed=True, evidence_ref="   ")  # whitespace ref is not evidence


# =============================================================================================
# SPAWN BOUNDARY
# =============================================================================================

def test_may_remediate_only_for_confirmed_fact():
    assert may_remediate(TriageFinding(ref="f", confirmed=True, evidence_ref="cert:1"))[0] is True
    assert may_remediate(TriageFinding(ref="f", confirmed=False))[0] is False
    assert may_remediate("not a finding")[0] is False
    assert may_remediate(None)[0] is False


def test_spawn_remediation_refuses_a_lead():
    lead = TriageFinding(ref="lead", confirmed=False)
    assert spawn_remediation(lead, remediation_id="x") is None
    fact = TriageFinding(ref="f1", confirmed=True, evidence_ref="cert:1", title="t", target="host")
    req = spawn_remediation(fact, remediation_id="rem-9", target_repo="git@x")
    assert isinstance(req, CodeFixRequest) and req.remediation_id == "rem-9"
    assert req.fix_branch == "vigil-fix/rem-9"


# =============================================================================================
# CODEFIX PIPELINE
# =============================================================================================

def test_happy_path_remediates_only_after_oracle_goes_silent():
    req = _confirmed_request()
    pr = _PrExec()
    res = _run(req, [EditBlock(path="src/app.py", intent="parametrize query")], open_pr=pr)
    assert res.remediated is True and res.status == "remediated"
    assert res.opened_pr is True and res.evidence_ref == "cert:remediated:1"
    assert res.edited_paths == ["src/app.py"]
    assert pr.staged == ["src/app.py"]                      # explicit path, never 'git add -A'
    # the verify step ran after the PR opened
    stages = [s.stage for s in res.steps]
    assert stages.index("pr-exec") < stages.index("verify")


def test_pipeline_refuses_a_request_not_from_a_confirmed_fact():
    # an attacker constructs a request directly from a LEAD, bypassing spawn_remediation.
    lead_req = CodeFixRequest(remediation_id="evil", finding=TriageFinding(ref="lead", confirmed=False),
                              target_repo="git@x")
    res = _run(lead_req, [EditBlock(path="src/x.py")])
    assert res.status == "refused-not-confirmed"
    assert res.opened_pr is False and res.remediated is False
    assert res.edited_paths == [] and len(res.steps) == 1   # nothing beyond the sovereign check ran


def test_approval_timeout_auto_REJECTS_never_accepts():
    req = _confirmed_request()
    pr = _PrExec()
    # approve_block=None models "no answer / timeout" → the redamon-flip: auto-REJECT, not auto-accept.
    res = run_codefix(req, [EditBlock(path="src/app.py")], gate=_allow_gate, clone=_clone_ok,
                      write_file=_write_ok, build=_build_ok, open_pr=pr, quorum=_quorum_yes,
                      approve_block=None, exploit_oracle=_oracle_silent, sign_remediated=_sign_remediated)
    assert res.status == "no-edits-approved"
    assert res.opened_pr is False and res.edited_paths == []
    assert pr.calls == 0                                    # the PR was NEVER opened


@pytest.mark.parametrize("outcome", [
    ApprovalOutcome(),                          # default decision == "timeout"
    ApprovalOutcome(decision="reject"),
    ApprovalOutcome(decision="modify", reason="use a prepared statement"),
    None,                                       # a callable returning None
])
def test_only_explicit_approve_applies_an_edit(outcome):
    req = _confirmed_request()
    pr = _PrExec()
    res = _run(req, [EditBlock(path="src/app.py")], approve_block=lambda b: outcome, open_pr=pr)
    assert res.status == "no-edits-approved" and pr.calls == 0


def test_a_raising_approval_callable_rejects_the_edit():
    req = _confirmed_request()

    def _boom(block):
        raise RuntimeError("approval service down")

    res = _run(req, [EditBlock(path="src/app.py")], approve_block=_boom)
    assert res.status == "no-edits-approved"


def test_pr_opens_only_after_the_m_of_n_threshold():
    req = _confirmed_request()
    pr = _PrExec()
    res = _run(req, [EditBlock(path="src/app.py")], quorum=_quorum_no, open_pr=pr)
    assert res.status == "pr-quorum-denied"
    assert res.opened_pr is False and pr.calls == 0
    assert res.remediated is False


def test_no_quorum_wired_refuses_the_pr():
    req = _confirmed_request()
    pr = _PrExec()
    res = _run(req, [EditBlock(path="src/app.py")], quorum=None, open_pr=pr)
    assert res.status == "pr-quorum-denied" and pr.calls == 0


def test_never_git_add_dash_A_unsafe_paths_are_rejected():
    req = _confirmed_request()
    pr = _PrExec()
    # an edit block whose path is a bulk/flag token must be rejected and never staged.
    res = _run(req, [EditBlock(path="-A"), EditBlock(path="../etc/passwd"), EditBlock(path="")], open_pr=pr)
    assert res.status == "no-edits-approved" and res.edited_paths == []
    assert pr.calls == 0


def test_only_explicit_written_paths_are_staged():
    req = _confirmed_request()
    pr = _PrExec()
    edits = [EditBlock(path="src/a.py"), EditBlock(path="src/b.py"), EditBlock(path="/abs/evil.py")]
    res = _run(req, edits, open_pr=pr)
    assert res.edited_paths == ["src/a.py", "src/b.py"]      # sorted, explicit, no absolute path
    assert pr.staged == ["src/a.py", "src/b.py"]
    assert "-A" not in pr.staged and "." not in pr.staged


def test_no_gate_wired_denies_clone():
    req = _confirmed_request()
    res = _run(req, [EditBlock(path="src/app.py")], gate=None)
    assert res.status == "clone-denied" and res.opened_pr is False


def test_gate_error_is_a_deny():
    req = _confirmed_request()

    def _boom_gate(tool, target, destructive):
        raise RuntimeError("warden offline")

    res = _run(req, [EditBlock(path="src/app.py")], gate=_boom_gate)
    assert res.status == "clone-denied"


def test_gate_can_deny_a_single_stage():
    req = _confirmed_request()

    def _deny_edit(tool, target, destructive):
        return _V(False, "deny", "edit not allowed") if tool == "code_edit" else _V(True, "allow")

    pr = _PrExec()
    res = _run(req, [EditBlock(path="src/app.py")], gate=_deny_edit, open_pr=pr)
    assert res.status == "no-edits-approved" and pr.calls == 0


def test_queue_verdict_does_not_open_the_pr():
    req = _confirmed_request()

    def _queue_pr(tool, target, destructive):
        return _V(False, "queue", "needs owner approval") if tool == "github_pr" else _V(True, "allow")

    pr = _PrExec()
    res = _run(req, [EditBlock(path="src/app.py")], gate=_queue_pr, open_pr=pr)
    assert res.status == "pr-denied" and pr.calls == 0


def test_build_and_clone_and_pr_failures_are_fail_closed():
    req = _confirmed_request()
    assert _run(req, [EditBlock(path="s.py")], clone=lambda r: CloneResult(ok=False, reason="net")
                ).status == "clone-failed"
    assert _run(req, [EditBlock(path="s.py")], build=lambda r, p: BuildResult(ok=False, reason="compile")
                ).status == "build-failed"
    assert _run(req, [EditBlock(path="s.py")], open_pr=lambda r, p: PrResult(ok=False, reason="403")
                ).status == "pr-failed"


def test_pipeline_total_on_malformed_input():
    assert run_codefix(None, None).status == "refused-not-confirmed"
    assert run_codefix("garbage", []).status == "refused-not-confirmed"
    req = _confirmed_request()
    # a non-list edits arg degrades to "no edits", not a crash
    assert _run(req, "not-a-list").status == "no-edits-approved"
    # a malformed edit element is skipped
    res = _run(req, [{"path": "x"}, EditBlock(path="src/ok.py")])
    assert res.edited_paths == ["src/ok.py"]


def test_steps_are_deterministic_and_secret_free():
    req = _confirmed_request()
    res = _run(req, [EditBlock(path="src/app.py")])
    seqs = [s.seq for s in res.steps]
    assert seqs == list(range(len(seqs)))                    # monotone, deterministic, no wallclock
    # no credential-shaped keys anywhere in the audit payloads (secret-free by construction).
    for s in res.steps:
        keys = " ".join(s.payload.keys()).lower()
        assert "token" not in keys and "password" not in keys and "secret" not in keys
    assert "token" not in set(CodeFixRequest.model_fields)   # the request carries no credential field


# =============================================================================================
# FIX VERIFICATION (sign 'remediated' ONLY when the oracle goes SILENT)
# =============================================================================================

def test_verify_fix_signs_remediated_only_on_silence():
    req = _confirmed_request()
    # oracle silent + signer → remediated
    v = verify_fix(req, "build:1", exploit_oracle=_oracle_silent, sign_remediated=_sign_remediated)
    assert v.remediated is True and v.status == "remediated" and v.evidence_ref == "cert:remediated:1"
    # oracle STILL fires → still-vulnerable, NEVER remediated (even though a signer is present)
    v = verify_fix(req, "build:1", exploit_oracle=_oracle_fires, sign_remediated=_sign_remediated)
    assert v.remediated is False and v.status == "still-vulnerable"


def test_verify_fix_fail_closed_paths():
    req = _confirmed_request()
    # no oracle wired → unverified
    assert verify_fix(req, "b", exploit_oracle=None, sign_remediated=_sign_remediated).status == "unverified"
    # oracle errors → unverified (cannot claim a fix)
    assert verify_fix(req, "b", exploit_oracle=lambda r, b: (_ for _ in ()).throw(RuntimeError()),
                      sign_remediated=_sign_remediated).status == "unverified"
    # oracle silent but NO signer → unverified (silence alone does not sign)
    assert verify_fix(req, "b", exploit_oracle=_oracle_silent, sign_remediated=None).status == "unverified"
    # oracle silent but signer returns empty → unverified
    assert verify_fix(req, "b", exploit_oracle=_oracle_silent,
                      sign_remediated=lambda r, b: "  ").status == "unverified"


def test_pipeline_opens_pr_but_stays_unverified_when_exploit_still_fires():
    req = _confirmed_request()
    pr = _PrExec()
    res = _run(req, [EditBlock(path="src/app.py")], open_pr=pr, exploit_oracle=_oracle_fires)
    assert res.opened_pr is True and pr.calls == 1          # the PR (fix proposal) opened
    assert res.remediated is False and res.status == "opened-pr-still-vulnerable"


def test_fix_verification_type_guard():
    FixVerification(status="remediated", remediated=True, evidence_ref="cert:1")   # fine
    with pytest.raises(ValueError):
        FixVerification(status="remediated", remediated=True, evidence_ref="")     # no ref
    with pytest.raises(ValueError):
        FixVerification(status="still-vulnerable", remediated=True, evidence_ref="cert:1")  # wrong status


def test_codefix_result_type_guard():
    CodeFixResult(status="remediated", opened_pr=True, remediated=True, evidence_ref="cert:1")  # fine
    with pytest.raises(ValueError):
        CodeFixResult(status="remediated", opened_pr=True, remediated=True, evidence_ref="")    # no ref
    with pytest.raises(ValueError):
        CodeFixResult(status="remediated", opened_pr=False, remediated=True, evidence_ref="c")  # no PR


# =============================================================================================
# UNTRUSTED-INPUT HANDLING (F1 reuse)
# =============================================================================================

def test_parse_edit_blocks_is_fail_closed():
    assert parse_edit_blocks('{"edits": [{"path": "a.py"}, {"path": "b.py"}]}') == [
        EditBlock(path="a.py"), EditBlock(path="b.py")]
    assert parse_edit_blocks('[{"path": "a.py"}]') == [EditBlock(path="a.py")]
    assert parse_edit_blocks("not json at all") == []           # malformed → no edits (fail-closed)
    assert parse_edit_blocks('{"edits": "not-a-list"}') == []
    assert parse_edit_blocks('{"edits": [{"no_path": 1}, "junk"]}') == []   # bad elements skipped/refused


def test_render_untrusted_finding_wraps_with_a_nonce_boundary():
    f = TriageFinding(ref="f1", confirmed=True, evidence_ref="cert:1", title="XSS in name field")
    framed = render_untrusted_finding(f)
    assert "<<<UNTRUSTED_FINDING id=" in framed and "<<<END_UNTRUSTED_FINDING id=" in framed
    assert "XSS in name field" in framed


def test_is_safe_repo_path_rejects_bulk_and_traversal():
    assert is_safe_repo_path("src/app.py")[0] is True
    for bad in ["-A", "--all", ".", "*", "", "/etc/passwd", "~/x", "../secret", "a/../b",
                "C:\\win", "-rf", 42, None]:
        assert is_safe_repo_path(bad)[0] is False


# =============================================================================================
# THE NAMED ADVERSARIAL TEST OF THE SOVEREIGN INVARIANT
# =============================================================================================

def test_ADVERSARIAL_sovereign_remediation_invariant():
    """Attack the sovereign invariant from every angle in one place; only the honest path may sign
    'remediated'."""
    # 1. A LEAD triage finding can NEVER spawn a remediation, however severe / correlated.
    lead_view = project([
        _step(1, "s1", "st1"),
        _lead(2, "h2", "lead-crit", severity="critical",
              cisa_kev=True, exploit_available=True, targets=[{"type": "cve", "value": "CVE-2024-9"}]),
    ])
    lead_draft = run_triage(lead_view)
    assert lead_draft.findings == []                                   # no confirmed → nothing to fix
    assert spawn_remediation(lead_draft.leads[0], remediation_id="x") is None

    # 2. Even a forged request built directly from a lead (bypassing spawn) is refused by the pipeline.
    forged = CodeFixRequest(remediation_id="forged", target_repo="git@x",
                            finding=TriageFinding(ref="lead-crit", confirmed=False))
    assert _run(forged, [EditBlock(path="src/app.py")]).status == "refused-not-confirmed"

    # A genuine oracle-confirmed FACT (the ONLY thing that may proceed).
    req = _confirmed_request(ref="sqli-1", severity="critical")
    assert req is not None and req.finding.may_spawn_remediation

    # 3. The approval TIMEOUT auto-REJECTS — a fix is never applied without an explicit approve.
    pr = _PrExec()
    timed_out = run_codefix(req, [EditBlock(path="src/app.py")], gate=_allow_gate, clone=_clone_ok,
                            write_file=_write_ok, build=_build_ok, open_pr=pr, quorum=_quorum_yes,
                            approve_block=None, exploit_oracle=_oracle_silent,
                            sign_remediated=_sign_remediated)
    assert timed_out.status == "no-edits-approved" and pr.calls == 0    # NOT auto-accepted

    # 4. A PR opens ONLY after the m-of-n threshold.
    pr = _PrExec()
    no_quorum = _run(req, [EditBlock(path="src/app.py")], quorum=_quorum_no, open_pr=pr)
    assert no_quorum.opened_pr is False and pr.calls == 0

    # 5. 'remediated' is signed ONLY after the exploit oracle goes SILENT: an oracle that still fires
    #    opens the PR (the fix proposal) but never signs remediated.
    pr = _PrExec()
    still_vuln = _run(req, [EditBlock(path="src/app.py")], open_pr=pr, exploit_oracle=_oracle_fires)
    assert still_vuln.opened_pr is True and still_vuln.remediated is False

    # 6. Only the fully-honest path — confirmed fact + explicit approve + m-of-n + oracle SILENT + signer
    #    — mints a signed 'remediated', staging ONLY the explicit edited path (never 'git add -A').
    pr = _PrExec()
    ok = _run(req, [EditBlock(path="src/app.py")], open_pr=pr)
    assert ok.remediated is True and ok.evidence_ref == "cert:remediated:1"
    assert pr.staged == ["src/app.py"] and "-A" not in (pr.staged or [])
