"""The Fixes screen's served ladder must describe the GATE, not a nicer story about it.

``framework.v2.console.api._REMEDIATION_LADDER`` is shipped to the command UI and rendered as the "gated fix
ladder" on the Fixes screen, tier pill and all. It is prose in the OFFENSE tree; the thing it describes is the
WARDEN gate in the SOVEREIGN tree. Nothing structural connects them, so the ladder once claimed tiers the gate
does not assign — clone "A1" (i.e. auto-eligible under the A1 offense ceiling) for a stage that in fact QUEUES
for owner approval, which is the opposite of what happens.

This file is the missing connection. It hard-imports BOTH trees, so it can only run in the ONE CI leg where
both are on the path (the offense leg of ci.yml, where it is listed; it is ``--ignore``d in the sovereign leg,
which cannot import ``framework`` at all — see test_ci_framework_tests_run_in_offense_leg.py, which fails the
build if either half of that pair is missing). It pins each ladder row against the gate the console's own
Apply button really drives:

    Apply click → ``actions.apply_fix`` → ``vigil patch --apply-edits --approve``
                → ``live.codefix_runner.autopatch_live`` → ``autopatch.loop.autopatch``
                → per-stage ``CodefixSession.gate`` → ``decide_tool(..., floor="A2", ceiling="A1")``

Note what is NOT asserted: the pipeline's ledger step LABELS (``loop.TIER_CLONE`` = "A1" etc.) are recorded on
each step record and are deliberately left alone — they are a label, not a decision. The ladder shows the
decision, and the decision is what these tests measure.
"""
from __future__ import annotations

import inspect
from pathlib import Path

from framework.v2.console import api
from vigil_integration.autopatch import loop as loop_mod
from vigil_integration.live.codefix_runner import CodefixConfig, CodefixSession
from vigil_integration.live.wiring import default_classify
from vigil_integration.remediation.triage import TriageFinding
from vigil_integration.warden_gate import decide_tool

# A cross-tree test is only worth anything if BOTH halves come from THIS checkout. An editable install of
# another VIGIL tree on the venv's path silently satisfies `import framework` / `import vigil_integration`,
# and the suite would then measure a ladder this commit never touched. Fail loudly at collection instead.
_REPO = Path(__file__).resolve().parents[2]
for _mod in (api, loop_mod):
    _p = Path(_mod.__file__).resolve()
    assert _p.is_relative_to(_REPO), (
        f"{_mod.__name__} resolved to {_p}, outside this checkout ({_REPO}) — run with "
        "PYTHONPATH=integration:engine/crucible:gateway from the repo root")

#: ladder stage → (the tool name the loop really gates it with, whether the loop calls it destructive).
_STAGE_TOOL = {
    "clone": ("git_clone", False),
    "edit": ("code_edit", False),
    "build": ("sandbox_build", False),
    "open-pr": ("github_pr", True),
}
_TIER_TOKENS = ("A0", "A1", "A2", "A3")


def _rows() -> dict:
    return {s["stage"]: s for s in api._REMEDIATION_LADDER}


def _session(*, operator_present: bool, pr_enabled: bool = False) -> CodefixSession:
    """A gate-only session. Nothing here touches disk: ``CodefixSession.gate`` consults the kill-switch
    (None) and ``decide_tool``, so the paths below are never opened."""
    cfg = CodefixConfig(target_repo="/nonexistent-repo", base_dir="/nonexistent-base", pr_enabled=pr_enabled)
    return CodefixSession(cfg, operator_present=operator_present)


def test_the_ladder_gates_exactly_the_stages_the_loop_gates():
    """A new gated stage in the pipeline (or a renamed tool) must show up on the screen, not silently not."""
    src = inspect.getsource(loop_mod.autopatch)
    gated_in_loop = {name for name, _d in _STAGE_TOOL.values() if f'"{name}"' in src}
    assert gated_in_loop == {name for name, _d in _STAGE_TOOL.values()}, gated_in_loop
    rows = _rows()
    for stage in _STAGE_TOOL:
        assert stage in rows, f"the loop gates {stage!r} but the served ladder has no such row"


def test_every_gated_row_shows_the_tier_the_warden_gate_really_assigns():
    """The pill is a measurement. For each gated stage the row's tier must START with the tier
    ``decide_tool`` returns for that stage's tool under the floor/ceiling the live runner wires — and must
    not name any OTHER tier, so 'A1' can never reappear on a stage that queues."""
    rows = _rows()
    for stage, (tool, destructive) in _STAGE_TOOL.items():
        d = decide_tool(tool, classify=default_classify, floor="A2", ceiling="A1")
        tier = str(rows[stage]["tier"])
        assert d.outcome == "queue", (stage, tool, d)          # nothing on this ladder auto-runs
        assert tier.startswith(d.tier), (stage, tool, tier, d.tier)
        for other in _TIER_TOKENS:
            if other != d.tier:
                assert other not in tier, (stage, tier, other)
        # ...and the pill says out loud what an A2 tier MEANS on this path. For the three non-destructive
        # stages that is "queues" (the Apply click releases them). For the PR stage it is NOT: the session
        # gate short-circuits to DENY while `pr_enabled` is False (the console/CLI default), so claiming it
        # merely "queues" would be the same kind of flattering-but-false pill this file exists to prevent.
        if destructive:
            assert "off by default" in tier.lower() and "m-of-n" in tier.lower(), (stage, tier)
        else:
            assert "queue" in tier.lower(), (stage, tier)


def test_every_gated_row_names_the_approval_that_opens_it():
    """A queue the operator cannot see how to satisfy is not honest. Every gated row must either name the
    approval itself or point at the row that does (the clone row carries the full explanation)."""
    rows = _rows()
    clone = rows["clone"]["what"].lower()
    assert "--approve" in clone and "apply button" in clone, clone
    for stage in _STAGE_TOOL:
        what = rows[stage]["what"].lower()
        assert "--approve" in what or "same operator approval" in what or "same a2 queue" in what, (stage, what)


def test_the_ungated_rows_never_wear_a_tier_pill():
    """triage / propose / verify are not WARDEN tool-gate stages, so they must not claim a tier — a pill
    there would read as 'auto-eligible' to exactly the same operator."""
    for row in api._REMEDIATION_LADDER:
        if row["stage"] in _STAGE_TOOL:
            continue
        assert not any(t in str(row["tier"]) for t in _TIER_TOKENS), row


def test_the_live_gate_agrees__unattended_queues_and_the_apply_click_is_what_opens_it():
    """The end-to-end meaning of the A2 pill, measured through the REAL gate the runner installs: with no
    operator present every non-destructive stage QUEUES (allowed False); with the operator present — which
    is what ``--approve``, i.e. the Apply click, sets — the same stage is allowed."""
    unattended, attended = _session(operator_present=False), _session(operator_present=True)
    for stage, (tool, destructive) in _STAGE_TOOL.items():
        if destructive:
            continue
        v = unattended.gate(tool, "/nonexistent-repo", destructive)
        assert v.allowed is False and v.outcome == "queue", (stage, tool, v)
        v2 = attended.gate(tool, "/nonexistent-repo", destructive)
        assert v2.allowed is True and v2.outcome == "allow", (stage, tool, v2)


def test_the_open_pr_row_is_true__off_by_default__and_m_of_n_sits_on_top_of_the_same_queue():
    """The PR row claims: OFF by default, never from the console, and an m-of-n authorization ON TOP of the
    same A2 queue. Measured: with ``pr_enabled`` False the gate DENIES even for a present operator; with it
    on, the WARDEN leg allows and the m-of-n is a SEPARATE callable the loop also requires."""
    off = _session(operator_present=True, pr_enabled=False).gate("github_pr", "/nonexistent-repo", True)
    assert off.allowed is False and off.outcome == "deny", off
    on = _session(operator_present=True, pr_enabled=True).gate("github_pr", "/nonexistent-repo", True)
    assert on.allowed is True, on                       # the WARDEN leg alone — the quorum is orthogonal
    src = inspect.getsource(loop_mod.autopatch)
    assert "_quorum_ok(quorum, request)" in src         # ...and the loop demands it separately
    row = _rows()["open-pr"]["what"].lower()
    assert "m-of-n" in row and "off by default" in row and "never run from this console" in row, row
    assert "refused" in row, row        # the row says the ladder REACHES this stage and is refused here


def test_the_propose_row_is_true__the_model_runs_before_any_gate_and_no_model_means_no_patch():
    """The propose row claims the model runs BEFORE any gated stage, and that with no model there is no
    patch at all. Measured on the real loop: a gate that would allow everything is never consulted, and the
    run ends ``no-patch-proposed``."""
    calls: list[str] = []

    class _V:
        allowed, outcome, reason = True, "allow", "test gate"

    def _gate(tool, _target, _destructive):
        calls.append(tool)
        return _V()

    finding = TriageFinding(ref="sqli-1", title="SQL injection", bug_class="sqli", severity="high",
                            target="app.py:2", confirmed=True, evidence_ref="cert:abc123",
                            target_repo="/nonexistent-repo")
    res = loop_mod.autopatch(finding, gate=_gate, propose_patch=None)   # no coder wired ⇒ no proposal
    assert res.status == "no-patch-proposed", res.status
    assert res.patched_paths == [] and res.opened_pr is False
    assert calls == [], f"the gate was consulted before/without a proposal: {calls}"
    assert any(s.stage == "propose" and s.outcome == "deny" for s in res.steps), res.steps

    row = _rows()["propose"]["what"].lower()
    assert "before any gated stage" in row, row
    assert "no patch at all" in row, row
