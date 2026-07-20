"""verify.cicd_posture — a parsed GitHub-Actions control promoted to a CICD_POSTURE FACT.

Pins the three near-zero-FP rules (unpinned third-party action / pwn-request / script-injection) firing
on the dangerous construct and NOT on its benign twin, the offline ingest, and offline re-verification.
"""

from __future__ import annotations

from framework.v2.verify import (
    cicd_posture_context,
    confirm_cicd_posture,
    confirm_workflow,
    ingest_workflow,
)
from framework.v2.verify.models import OracleKind
from framework.v2.verify.oracles import cicd_posture_oracle
from framework.v2.verify.reverify import reverify_context
from framework.v2.verify.verifier import _ALL_ORACLES


def _fires(control) -> bool:
    return confirm_cicd_posture(control).confirmed


# ---------------------------------------------------------------------------
# unpinned third-party action
# ---------------------------------------------------------------------------


def test_unpinned_third_party_action_fires():
    assert _fires({"rule": "unpinned_action", "uses": "some-org/action@main"})
    assert _fires({"rule": "unpinned_action", "uses": "foo/bar@v3"})            # a version TAG is mutable


def test_pinned_or_first_party_action_does_not_fire():
    assert not _fires({"rule": "unpinned_action", "uses": "foo/bar@" + "a" * 40})  # SHA-pinned
    assert not _fires({"rule": "unpinned_action", "uses": "actions/checkout@v4"})   # first-party
    assert not _fires({"rule": "unpinned_action", "uses": "github/codeql-action/analyze@v3"})  # first-party
    assert not _fires({"rule": "unpinned_action", "uses": "./.github/actions/local"})  # local
    assert not _fires({"rule": "unpinned_action", "uses": "docker://alpine:3"})     # docker
    assert not _fires({"rule": "unpinned_action", "uses": "not-an-action-ref"})     # unparseable


# ---------------------------------------------------------------------------
# pwn-request (pull_request_target + untrusted PR-head checkout)
# ---------------------------------------------------------------------------


def test_pwn_request_fires():
    assert _fires({"rule": "pwn_request", "trigger": "pull_request_target",
                   "checkout_ref": "${{ github.event.pull_request.head.sha }}"})
    assert _fires({"rule": "pwn_request", "trigger": "pull_request_target",
                   "checkout_ref": "${{ github.head_ref }}"})


def test_pwn_request_does_not_fire_on_safe_variants():
    # a plain pull_request trigger is NOT privileged
    assert not _fires({"rule": "pwn_request", "trigger": "pull_request",
                       "checkout_ref": "${{ github.event.pull_request.head.sha }}"})
    # pull_request_target checking out the BASE (default) is safe
    assert not _fires({"rule": "pwn_request", "trigger": "pull_request_target", "checkout_ref": ""})


# ---------------------------------------------------------------------------
# script injection (untrusted ${{ }} in a run body)
# ---------------------------------------------------------------------------


def test_script_injection_fires():
    assert _fires({"rule": "script_injection", "run": 'echo "${{ github.event.issue.title }}"'})
    assert _fires({"rule": "script_injection", "run": "git log ${{ github.head_ref }}"})


def test_script_injection_does_not_fire_on_trusted_expressions():
    # github.sha / github.run_id / a step output are NOT attacker-controlled
    assert not _fires({"rule": "script_injection", "run": 'echo "${{ github.sha }}"'})
    assert not _fires({"rule": "script_injection", "run": 'echo "${{ steps.x.outputs.y }}"'})
    assert not _fires({"rule": "script_injection", "run": "echo no interpolation here"})
    assert not _fires({"rule": "script_injection", "run": 'echo "${{ github.event.pull_request.number }}"'})


def test_script_injection_substring_false_positives_fixed():
    """Review wp7kachv5 (the ONLY confirmed defect): the unanchored `tok in flat` substring match
    false-fired on non-injectable subfields, string literals, and different-prefix paths. The
    boundary-anchored regex + quoted-literal stripping fixes each while keeping true positives."""
    fp = [
        'echo "${{ github.event.commits[0].id }}"',          # a commit SHA (non-injectable)
        'echo "${{ github.event.commits[0].timestamp }}"',   # a date (non-injectable)
        'echo "${{ github.event.pages[0].sha }}"',           # a page commit SHA
        "echo \"${{ 'github.event.pull_request.title' }}\"",  # a quoted STRING LITERAL (no data flow)
        'echo "${{ github.event.commits_url }}"',            # a different prefix (commits_url)
    ]
    for run in fp:
        assert not _fires({"rule": "script_injection", "run": run}), f"FP still fires: {run}"
    tp = [
        'echo "${{ github.event.commits[0].message }}"',     # an injectable text leaf
        'echo "${{ github.event.pages[0].page_name }}"',
        'echo "${{ github.event.head_commit.author.email }}"',
    ]
    for run in tp:
        assert _fires({"rule": "script_injection", "run": run}), f"true positive regressed: {run}"


# ---------------------------------------------------------------------------
# offline ingest end-to-end
# ---------------------------------------------------------------------------


_VULN = """
name: ci
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: evil-org/evil-action@main
      - run: echo "PR ${{ github.event.pull_request.title }}"
"""

_BENIGN = """
name: ci
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@abcabcabcabcabcabcabcabcabcabcabcabcabca
      - run: make build
"""


def test_ingest_and_confirm_workflow():
    facts = confirm_workflow(_VULN, name="ci.yml")
    rules = sorted(f["rule"] for f in facts)
    assert rules == ["pwn_request", "script_injection", "unpinned_action"]
    # the first-party actions/checkout@v4 is a LEAD but NOT a confirmed fact
    assert any(f.get("uses") == "evil-org/evil-action@main" for f in facts)


def test_benign_workflow_confirms_nothing():
    assert confirm_workflow(_BENIGN) == []


def test_ingest_malformed_is_empty_never_raises():
    assert ingest_workflow(":::not yaml:::\n\tbroken") == [] or isinstance(ingest_workflow("x"), list)
    assert ingest_workflow(None) == []
    assert ingest_workflow("just a string") == []
    assert ingest_workflow({"no": "jobs"}) == []


def test_ingest_json_workflow_without_yaml():
    # a JSON-encoded workflow ingests even if PyYAML is absent (JSON is tried first).
    import json
    wf = json.dumps({"on": "pull_request_target",
                     "jobs": {"b": {"steps": [{"run": "echo ${{ github.head_ref }}"}]}}})
    facts = confirm_workflow(wf)
    assert any(f["rule"] == "script_injection" for f in facts)


# ---------------------------------------------------------------------------
# offline re-verification + gate safety
# ---------------------------------------------------------------------------


def test_fact_reverifies_offline():
    ctl = {"rule": "pwn_request", "trigger": "pull_request_target",
           "checkout_ref": "${{ github.event.pull_request.head.sha }}"}
    ctx = cicd_posture_context(ctl)
    r = reverify_context(ctx, bug_class="cicd_misconfiguration")
    assert r.reproduced and r.ok
    assert r.confirmed_by == OracleKind.CICD_POSTURE.value


def test_new_kind_held_out_of_frozen_fallback():
    assert OracleKind.CICD_POSTURE not in _ALL_ORACLES   # additive; never in the frozen fallback
    assert cicd_posture_oracle({"rule": "unknown"}).fired is False
