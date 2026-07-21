"""
Phase 32 — the AIxCC AUTO-PATCH loop (``vigil_integration.autopatch``), layered on F10 remediation + F9
fsjob.

The through-line every test defends is the SOVEREIGN INVARIANT of auto-patching:

  * NO patch is applied / PR'd without an oracle-confirmed FACT — a LEAD finding is refused fail-closed.
  * The LLM only PROPOSES: its unified diff is parsed fail-closed and every path re-validated (never a
    glob / flag / absolute / traversal / '/dev/null' path — never 'git add -A').
  * The per-file approval TIMEOUT auto-REJECTS via the INJECTED clock (an expired window never applies an
    edit, even when the decision says 'approve') — the inverse of redamon's auto-accept.
  * A PR opens ONLY after the m-of-n threshold.
  * 'remediated' is minted ONLY after the fix-verification oracle goes SILENT on the patched build.
  * Total on malformed input; deterministic (no wallclock / RNG on the decision path).

Every executor — gate / oracle / LLM / clone / build / open_pr / quorum / approval / clock — is an injected
callable, so the whole loop runs without a live kernel, git, LLM, or sandbox.
"""

from __future__ import annotations

import types

import pytest

from vigil_integration.autopatch import (
    BuildResult,
    CloneResult,
    OracleVerdict,
    PatchApproval,
    PatchFile,
    PatchResult,
    PrResult,
    QuorumOutcome,
    autopatch,
    parse_unified_diff,
    verify_patch,
)
from vigil_integration.remediation import TriageFinding

# =============================================================================================
# fixtures — a confirmed FACT, injected fakes, and unified-diff proposals
# =============================================================================================


def _fact(ref="sqli-1", severity="critical", target_repo="git@example.com:app/app.git"):
    """An oracle-confirmed FACT (confirmed + signed evidence_ref) — the ONLY thing that may be patched."""
    return TriageFinding(ref=ref, confirmed=True, evidence_ref=f"cert:{ref}", severity=severity,
                         title=f"{ref} title", target="127.0.0.1:18080", spine_hash=f"sh-{ref}",
                         target_repo=target_repo)


def _lead(ref="lead-1", severity="critical"):
    return TriageFinding(ref=ref, confirmed=False, severity=severity, title=f"{ref} lead")


DIFF = (
    "diff --git a/src/app.py b/src/app.py\n"
    "index e69de29..abc1234 100644\n"
    "--- a/src/app.py\n"
    "+++ b/src/app.py\n"
    "@@ -1,3 +1,3 @@\n"
    " def q(u):\n"
    '-    db.execute("SELECT * FROM t WHERE u=" + u)\n'
    '+    db.execute("SELECT * FROM t WHERE u=?", (u,))\n'
)

DIFF_TWO = (
    "diff --git a/src/a.py b/src/a.py\n--- a/src/a.py\n+++ b/src/a.py\n@@ -1 +1 @@\n-bad\n+good\n"
    "diff --git a/src/b.py b/src/b.py\n--- a/src/b.py\n+++ b/src/b.py\n@@ -1 +1 @@\n-bad\n+good\n"
)

# a proposal mixing one safe file with a traversal path and an absolute path (both must be dropped)
DIFF_MIXED = (
    "--- a/src/ok.py\n+++ b/src/ok.py\n@@ -1 +1 @@\n-x\n+y\n"
    "--- a/evil\n+++ b/../../etc/passwd\n@@ -1 +1 @@\n-x\n+y\n"
    "--- /dev/null\n+++ /etc/shadow\n@@ -0,0 +1 @@\n+pwn\n"
)


class _V:
    def __init__(self, allowed, outcome, reason=""):
        self.allowed, self.outcome, self.reason = allowed, outcome, reason


def _allow_gate(tool, target, destructive):
    return _V(True, "allow", f"allow {tool}")


def _clone_ok(req):
    return CloneResult(ok=True, workdir="/sandbox/wd", branch=req.fix_branch)


def _build_ok(req, approved):
    return BuildResult(ok=True, build_ref="build:patched:1")


class _PrExec:
    """Records exactly which paths the PR stage was asked to stage (to prove it is never 'git add -A')."""

    def __init__(self, ok=True):
        self.ok = ok
        self.staged = None
        self.calls = 0

    def __call__(self, req, approved):
        self.calls += 1
        self.staged = [pf.path for pf in approved]
        return PrResult(ok=self.ok, pr_ref="pr:1", reason="" if self.ok else "gh error")


def _quorum_yes(req):
    return QuorumOutcome(approved=True, reason="2-of-3 (owner-inclusive)")


def _quorum_no(req):
    return QuorumOutcome(approved=False, reason="only 1 of 2 signers")


def _approve_inwindow(pf):
    return PatchApproval(decision="approve", deadline=100.0)


def _clock_inwindow():
    return 50.0


def _clock_expired():
    return 200.0


def _oracle_silent(req, build):
    return OracleVerdict(fired=False, cert="cert:remediated:1")


def _oracle_fires(req, build):
    return OracleVerdict(fired=True, reason="the SQLi still triggers")


def _run(finding=None, **overrides):
    finding = _fact() if finding is None else finding
    kwargs = dict(gate=_allow_gate, oracle=_oracle_silent, propose_patch=lambda r: DIFF,
                  clone=_clone_ok, build=_build_ok, open_pr=_PrExec(), quorum=_quorum_yes,
                  approval=_approve_inwindow, now=_clock_inwindow)
    kwargs.update(overrides)
    return autopatch(finding, **kwargs)


# =============================================================================================
# UNIFIED-DIFF PARSING (the LLM only PROPOSES; the diff is untrusted)
# =============================================================================================


def test_parse_extracts_and_strips_ab_prefixes():
    files = parse_unified_diff(DIFF)
    assert [f.path for f in files] == ["src/app.py"]
    assert files[0].status == "modify"
    assert "SELECT * FROM t WHERE u=?" in files[0].diff_text     # the per-file patch is captured


def test_parse_two_files_deduped_order_preserved():
    files = parse_unified_diff(DIFF_TWO)
    assert [f.path for f in files] == ["src/a.py", "src/b.py"]
    # a duplicated path collapses to the first occurrence
    dup = parse_unified_diff(DIFF + DIFF)
    assert [f.path for f in dup] == ["src/app.py"]


def test_parse_resolves_add_and_delete():
    add = parse_unified_diff("--- /dev/null\n+++ b/src/new.py\n@@ -0,0 +1 @@\n+created\n")
    assert add == [PatchFile(path="src/new.py", status="add", diff_text=add[0].diff_text)]
    assert add[0].status == "add"
    dele = parse_unified_diff("--- a/src/old.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-gone\n")
    assert [f.path for f in dele] == ["src/old.py"] and dele[0].status == "delete"


def test_parse_drops_unsafe_paths():
    files = parse_unified_diff(DIFF_MIXED)
    assert [f.path for f in files] == ["src/ok.py"]             # traversal + absolute dropped
    for bad in [
        "--- a/x\n+++ b/../../etc/passwd\n@@ @@\n",             # traversal
        "--- a/x\n+++ /etc/passwd\n@@ @@\n",                    # absolute
        "--- a/x\n+++ b/-rf\n@@ @@\n",                          # flag-looking
        "--- /dev/null\n+++ /dev/null\n@@ @@\n",                # nothing stageable
        "--- a/x\n+++ b/.\n@@ @@\n",                            # bulk token
    ]:
        assert parse_unified_diff(bad) == []


def test_parse_is_total_and_fail_closed():
    assert parse_unified_diff("") == []
    assert parse_unified_diff("   \n  ") == []
    assert parse_unified_diff("not a diff at all") == []
    assert parse_unified_diff(None) == []
    assert parse_unified_diff(12345) == []
    assert parse_unified_diff(["--- a/x", "+++ b/x"]) == []
    assert parse_unified_diff("x" * (1_000_001)) == []          # over the byte bound → refused


def test_parse_handles_git_quoted_path():
    files = parse_unified_diff('--- a/src/app.py\n+++ "b/src/app.py"\n@@ @@\n')
    assert [f.path for f in files] == ["src/app.py"]


# =============================================================================================
# THE SOVEREIGN ENTRY — only an oracle-confirmed FACT may be auto-patched
# =============================================================================================


def test_happy_path_remediates_only_after_oracle_goes_silent():
    pr = _PrExec()
    res = _run(open_pr=pr)
    assert res.remediated is True and res.status == "remediated"
    assert res.opened_pr is True and res.evidence_ref == "cert:remediated:1"
    assert res.patched_paths == ["src/app.py"]
    assert pr.staged == ["src/app.py"]                          # explicit path, never 'git add -A'
    stages = [s.stage for s in res.steps]
    assert stages.index("pr-exec") < stages.index("verify")    # verify ran after the PR opened


def test_a_lead_can_never_be_auto_patched():
    pr = _PrExec()
    res = _run(_lead(), open_pr=pr)
    assert res.status == "refused-not-confirmed"
    assert res.opened_pr is False and res.remediated is False
    assert res.patched_paths == [] and len(res.steps) == 1     # nothing beyond the sovereign check ran
    assert pr.calls == 0


def test_non_finding_inputs_are_refused():
    assert autopatch(None, gate=_allow_gate).status == "refused-not-confirmed"
    assert autopatch("not a finding", gate=_allow_gate).status == "refused-not-confirmed"
    assert autopatch({"confirmed": True}, gate=_allow_gate).status == "refused-not-confirmed"


# =============================================================================================
# PROPOSE — no valid patch → no PR
# =============================================================================================


@pytest.mark.parametrize("propose", [
    lambda r: "",                                              # empty
    lambda r: "totally not a diff",                            # garbage
    lambda r: "--- a/x\n+++ b/../../etc/passwd\n@@ @@\n",      # only an unsafe (traversal) file
    None,                                                      # no LLM wired
    lambda r: (_ for _ in ()).throw(RuntimeError("llm down")),  # a raising LLM
])
def test_no_valid_patch_means_no_pr(propose):
    pr = _PrExec()
    res = _run(propose_patch=propose, open_pr=pr)
    assert res.status == "no-patch-proposed"
    assert res.opened_pr is False and pr.calls == 0


# =============================================================================================
# THE CRITICAL FLIP — the approval TIMEOUT auto-REJECTS via the injected clock
# =============================================================================================


def test_expired_window_auto_rejects_even_when_decision_is_approve():
    pr = _PrExec()
    # the approval SAYS approve, but the injected clock is past the deadline → the window EXPIRED → REJECT.
    res = _run(open_pr=pr, approval=_approve_inwindow, now=_clock_expired)
    assert res.status == "no-edits-approved"
    assert res.opened_pr is False and pr.calls == 0            # NEVER auto-accepted on timeout


def test_in_window_boundary_is_inclusive():
    # now == deadline is still IN-WINDOW (expired iff now > deadline).
    pr = _PrExec()
    res = _run(open_pr=pr, approval=lambda pf: PatchApproval(decision="approve", deadline=100.0),
               now=lambda: 100.0)
    assert res.remediated is True and pr.calls == 1


def test_no_approval_or_no_clock_or_default_deadline_all_reject():
    for kw in [dict(approval=None), dict(now=None),
               dict(approval=lambda pf: PatchApproval(decision="approve"))]:   # default deadline 0.0 < now
        pr = _PrExec()
        res = _run(open_pr=pr, **kw)
        assert res.status == "no-edits-approved" and pr.calls == 0


def test_a_raising_approval_callable_rejects():
    def _boom(pf):
        raise RuntimeError("approval service down")

    assert _run(approval=_boom).status == "no-edits-approved"


def test_approval_without_a_numeric_deadline_rejects():
    # an approval object that carries no numeric deadline cannot be bounded → auto-REJECT.
    res = _run(approval=lambda pf: types.SimpleNamespace(decision="approve"))
    assert res.status == "no-edits-approved"


@pytest.mark.parametrize("decision", ["reject", "modify", "timeout", None, "garbage"])
def test_only_explicit_approve_applies(decision):
    pr = _PrExec()
    res = _run(open_pr=pr, approval=lambda pf: PatchApproval(decision=decision, deadline=100.0))
    assert res.status == "no-edits-approved" and pr.calls == 0


# =============================================================================================
# GATED, TIERED STAGES (reusing the remediation fail-closed normalizers)
# =============================================================================================


def test_no_gate_wired_denies_clone():
    assert _run(gate=None).status == "clone-denied"


def test_gate_error_is_a_deny():
    def _boom_gate(tool, target, destructive):
        raise RuntimeError("warden offline")

    assert _run(gate=_boom_gate).status == "clone-denied"


def test_gate_can_deny_a_single_stage():
    def _deny_edit(tool, target, destructive):
        return _V(False, "deny", "edit not allowed") if tool == "code_edit" else _V(True, "allow")

    pr = _PrExec()
    res = _run(gate=_deny_edit, open_pr=pr)
    assert res.status == "no-edits-approved" and pr.calls == 0


def test_queue_verdict_on_pr_does_not_open_it():
    def _queue_pr(tool, target, destructive):
        return _V(False, "queue", "needs owner approval") if tool == "github_pr" else _V(True, "allow")

    pr = _PrExec()
    res = _run(gate=_queue_pr, open_pr=pr)
    assert res.status == "pr-denied" and pr.calls == 0


def test_build_gate_denied():
    def _deny_build(tool, target, destructive):
        return _V(False, "deny", "no build") if tool == "sandbox_build" else _V(True, "allow")

    assert _run(gate=_deny_build).status == "build-denied"


def test_clone_build_pr_executor_failures_are_fail_closed():
    assert _run(clone=lambda r: CloneResult(ok=False, reason="net")).status == "clone-failed"
    assert _run(build=lambda r, a: BuildResult(ok=False, reason="compile")).status == "build-failed"
    assert _run(open_pr=lambda r, a: PrResult(ok=False, reason="403")).status == "pr-failed"


# =============================================================================================
# m-of-n QUORUM (a PR opens ONLY after the threshold)
# =============================================================================================


def test_pr_opens_only_after_the_m_of_n_threshold():
    pr = _PrExec()
    res = _run(quorum=_quorum_no, open_pr=pr)
    assert res.status == "pr-quorum-denied"
    assert res.opened_pr is False and pr.calls == 0 and res.remediated is False


def test_no_quorum_wired_refuses_the_pr():
    pr = _PrExec()
    res = _run(quorum=None, open_pr=pr)
    assert res.status == "pr-quorum-denied" and pr.calls == 0


# =============================================================================================
# NEVER 'git add -A' — only explicit, approved, path-validated files are staged
# =============================================================================================


def test_only_the_safe_proposed_file_is_staged():
    pr = _PrExec()
    res = _run(propose_patch=lambda r: DIFF_MIXED, open_pr=pr)
    assert res.patched_paths == ["src/ok.py"]                  # traversal/absolute never reached staging
    assert pr.staged == ["src/ok.py"]
    assert "-A" not in (pr.staged or []) and "." not in (pr.staged or [])


def test_two_files_staged_sorted_and_explicit():
    pr = _PrExec()
    res = _run(propose_patch=lambda r: DIFF_TWO, open_pr=pr)
    assert res.patched_paths == ["src/a.py", "src/b.py"]       # sorted, explicit
    assert pr.staged == ["src/a.py", "src/b.py"]


# =============================================================================================
# FIX VERIFICATION — sign 'remediated' ONLY when the oracle goes SILENT
# =============================================================================================


def test_verify_patch_signs_only_on_silence():
    v = verify_patch("req", "build:1", oracle=_oracle_silent)
    assert v.remediated is True and v.status == "remediated" and v.evidence_ref == "cert:remediated:1"
    v = verify_patch("req", "build:1", oracle=_oracle_fires)
    assert v.remediated is False and v.status == "still-vulnerable"


def test_verify_patch_fail_closed_paths():
    assert verify_patch("r", "b", oracle=None).status == "unverified"                      # no oracle
    assert verify_patch("r", "b",
                        oracle=lambda r, b: (_ for _ in ()).throw(RuntimeError())).status == "unverified"
    # silent but NO signed cert → unverified (silence alone does not certify)
    assert verify_patch("r", "b", oracle=lambda r, b: OracleVerdict(fired=False)).status == "unverified"
    # no usable verdict → unverified (never a false 'silent')
    assert verify_patch("r", "b", oracle=lambda r, b: None).status == "unverified"
    assert verify_patch("r", "b", oracle=lambda r, b: 12345).status == "unverified"
    # a bare exploit-ref string still counts as 'fired' → still-vulnerable
    assert verify_patch("r", "b", oracle=lambda r, b: "cert:still").status == "still-vulnerable"
    # a default verdict is fail-closed 'still vulnerable'
    assert verify_patch("r", "b", oracle=lambda r, b: OracleVerdict()).status == "still-vulnerable"


def test_pipeline_opens_pr_but_stays_unverified_when_exploit_still_fires():
    pr = _PrExec()
    res = _run(open_pr=pr, oracle=_oracle_fires)
    assert res.opened_pr is True and pr.calls == 1            # the fix PROPOSAL opened as a PR
    assert res.remediated is False and res.status == "opened-pr-still-vulnerable"


@pytest.mark.parametrize("oracle,expected", [
    (None, "opened-pr-unverified"),
    (lambda r, b: OracleVerdict(fired=False), "opened-pr-unverified"),     # silent, no cert
    (lambda r, b: (_ for _ in ()).throw(RuntimeError()), "opened-pr-unverified"),
])
def test_pipeline_verify_states(oracle, expected):
    res = _run(oracle=oracle)
    assert res.status == expected and res.remediated is False and res.opened_pr is True


# =============================================================================================
# DETERMINISM, SECRET-FREE, TYPE GUARDS
# =============================================================================================


def test_deterministic_id_seqs_and_secret_free_steps():
    a, b = _run(), _run()
    assert a.remediation_id == b.remediation_id and a.remediation_id.startswith("ap-")
    assert a.status == b.status
    seqs = [s.seq for s in a.steps]
    assert seqs == list(range(len(seqs)))                     # monotone, deterministic, no wallclock
    for s in a.steps:
        keys = " ".join(str(k) for k in s.payload).lower()
        assert "token" not in keys and "password" not in keys and "secret" not in keys


def test_caller_supplied_remediation_id_is_honored():
    assert _run(remediation_id="rem-42").remediation_id == "rem-42"


def test_patch_result_type_guard():
    PatchResult(status="remediated", opened_pr=True, remediated=True, evidence_ref="cert:1")   # fine
    with pytest.raises(ValueError):
        PatchResult(status="remediated", opened_pr=True, remediated=True, evidence_ref="")     # no ref
    with pytest.raises(ValueError):
        PatchResult(status="remediated", opened_pr=False, remediated=True, evidence_ref="c")   # no PR


# =============================================================================================
# THE NAMED ADVERSARIAL TEST OF THE SOVEREIGN INVARIANT
# =============================================================================================


def test_ADVERSARIAL_sovereign_autopatch_invariant():
    """Attack the sovereign invariant from every angle in one place; only the fully-honest path may mint a
    signed 'remediated' certificate."""
    fact = _fact(ref="sqli-9", severity="critical")

    # 1. A LEAD — however critical — can NEVER be auto-patched, and nothing downstream runs.
    pr = _PrExec()
    lead_res = _run(_lead("lead-crit"), open_pr=pr)
    assert lead_res.status == "refused-not-confirmed" and pr.calls == 0

    # 2. The LLM only PROPOSES: a diff smuggling a traversal / absolute path stages NEITHER; a diff with no
    #    safe file opens no PR at all.
    pr = _PrExec()
    only_evil = _run(fact, propose_patch=lambda r: "--- a/x\n+++ b/../../etc/passwd\n@@ @@\n", open_pr=pr)
    assert only_evil.status == "no-patch-proposed" and pr.calls == 0

    # 3. THE FLIP: the approval says 'approve' but the clock is past the deadline → the window EXPIRED →
    #    auto-REJECT (redamon would auto-accept).
    pr = _PrExec()
    timed_out = _run(fact, approval=_approve_inwindow, now=_clock_expired, open_pr=pr)
    assert timed_out.status == "no-edits-approved" and pr.calls == 0

    # 4. A PR opens ONLY after the m-of-n threshold.
    pr = _PrExec()
    no_quorum = _run(fact, quorum=_quorum_no, open_pr=pr)
    assert no_quorum.opened_pr is False and pr.calls == 0

    # 5. 'remediated' is minted ONLY after the oracle goes SILENT: an exploit that still fires opens the PR
    #    (the fix proposal) but never certifies remediated.
    pr = _PrExec()
    still_vuln = _run(fact, oracle=_oracle_fires, open_pr=pr)
    assert still_vuln.opened_pr is True and still_vuln.remediated is False

    # 6. Only the fully-honest path — confirmed FACT + path-safe diff + in-window approve + m-of-n +
    #    oracle SILENT + signed cert — mints 'remediated', staging ONLY the explicit approved path.
    pr = _PrExec()
    ok = _run(fact, open_pr=pr)
    assert ok.remediated is True and ok.evidence_ref == "cert:remediated:1"
    assert pr.staged == ["src/app.py"] and "-A" not in (pr.staged or [])
