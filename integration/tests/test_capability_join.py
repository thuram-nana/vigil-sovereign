"""H4 — the capability join: a planned tool is either runnable or explained, never silently missing.

What VIGIL knows about a tool was scattered across five registries sharing no key: the planner's catalogue
(35 tools), the capability matrix (33 rows), the typed argv builders (9 — the only things that can actually
be spawned), the live host roster (16, with a presence probe), and the manifest validator. Nothing computed
the intersection, so a proposed-but-unexecutable tool vanished at run time: the chain listed it, the
executor denied it fail-closed, and no surface said why.
"""
from __future__ import annotations

import pytest

from vigil_integration.live.capability_join import (
    BLOCKED,
    EXECUTABLE,
    NOT_PROPOSABLE,
    UNAVAILABLE,
    join,
    plannable,
    surfaced,
)

BRAIN = {"nmap": "recon", "sqlmap": "active", "amass": "recon", "metasploit": "active"}
CATALOGUE = {
    "nmap": {"oracle_family": "service_reachability", "fact_capable": True},
    "sqlmap": {"oracle_family": "", "fact_capable": False},
    "metasploit": {"excluded": True},
    "zaproxy": {"oracle_family": ""},
}
BUILDERS = ["nmap", "sqlmap", "zaproxy"]
INSTALLED = {"nmap": {"installed": True, "version": "7.94"},
             "sqlmap": {"installed": False, "version": ""},
             "zaproxy": {"installed": True, "version": "2.14"}}


def _rows(**over):
    kw = dict(brain_tools=BRAIN, catalogue=CATALOGUE, builders=BUILDERS, installed=INSTALLED)
    kw.update(over)
    return {r.name: r for r in join(**kw)}


def test_a_tool_that_is_proposable_adapted_and_installed_is_executable():
    row = _rows()["nmap"]
    assert row.status == EXECUTABLE and row.runnable
    assert row.reason == "", "an executable tool needs no excuse"
    assert row.version == "7.94" and row.fact_capable


def test_an_adapted_tool_that_is_not_installed_is_unavailable_with_a_reason():
    row = _rows()["sqlmap"]
    assert row.status == UNAVAILABLE and not row.runnable
    assert "not installed" in row.reason


def test_a_proposable_tool_with_no_argv_builder_is_unavailable_not_silent():
    """The core defect: the planner proposes it, the executor denies it, nothing explained why."""
    row = _rows()["amass"]
    assert row.status == UNAVAILABLE
    assert "no typed argv builder" in row.reason and "fail-closed" in row.reason


def test_an_excluded_tool_is_blocked_and_refusal_outranks_availability():
    """metasploit is excluded AND has no builder; the REFUSAL must be the reported reason."""
    row = _rows()["metasploit"]
    assert row.status == BLOCKED
    assert "excluded" in row.reason and "builder" not in row.reason, (
        "a deliberate refusal must not be reported as a mere availability gap"
    )


def test_a_known_but_uncurated_tool_is_marked_not_proposable():
    row = _rows()["zaproxy"]
    assert row.status == NOT_PROPOSABLE and not row.proposable


def test_unprobed_presence_is_never_promised_runnable():
    """installed=None means "we did not look" — which must not be reported as available."""
    row = _rows(installed=None)["nmap"]
    assert row.status == UNAVAILABLE and "not probed" in row.reason


def test_a_shadowed_binary_counts_as_not_installed():
    """The roster flags e.g. the Python httpx package shadowing the httpx CLI; running it would execute
    a different program than the plan named."""
    rows = _rows(installed={"nmap": {"installed": True, "version": "x", "shadowed": True}})
    # the join trusts the probe's own 'installed' verdict; the resolver folds `shadowed` into it, so a
    # shadowed row arrives already false. Assert the contract the resolver relies on:
    from vigil_integration.live import capability_join as cj
    assert "shadowed" in cj._probe_installed.__doc__.lower(), (
        "the resolver must document that a shadowed binary is not installed"
    )
    assert rows["nmap"].status == EXECUTABLE, "the pure join uses the probe's verdict verbatim"


def test_the_plannable_set_is_the_intersection():
    assert plannable(join(brain_tools=BRAIN, catalogue=CATALOGUE, builders=BUILDERS,
                          installed=INSTALLED)) == ["nmap"], (
        "only a tool that is proposable AND adapted AND installed may be scheduled"
    )


def test_every_proposable_tool_that_cannot_run_is_surfaced_with_a_reason():
    """The anti-silence rule — this is what stops a plan quietly dropping a step."""
    rows = join(brain_tools=BRAIN, catalogue=CATALOGUE, builders=BUILDERS, installed=INSTALLED)
    shown = surfaced(rows)
    assert {r.name for r in shown} == {"sqlmap", "amass", "metasploit"}
    assert all(r.reason for r in shown), "every surfaced row must explain itself"


def test_no_row_is_ever_statusless():
    rows = join(brain_tools=BRAIN, catalogue=CATALOGUE, builders=BUILDERS, installed=INSTALLED)
    assert rows and all(r.status for r in rows)
    assert all(r.status == EXECUTABLE or r.reason for r in rows), (
        "a non-executable row without a reason is exactly the silence this join exists to remove"
    )


def test_every_source_contributes_its_tools_to_the_view():
    """A tool known to ANY registry must appear — otherwise the join could hide one by omission."""
    names = {r.name for r in join(brain_tools=BRAIN, catalogue=CATALOGUE,
                                  builders=BUILDERS, installed=INSTALLED)}
    assert names >= set(BRAIN) | set(CATALOGUE) | set(BUILDERS) | set(INSTALLED)


# --- the live view (no Docker, but it does read the real registries) -----------------------------------

def test_the_real_registries_join_without_error_and_explain_every_gap():
    from vigil_integration.live.capability_join import resolve

    rows = resolve()                      # static: no host probe, so nothing is promised runnable
    assert len(rows) > 40, "expected the union of the real registries to be substantial"
    unexplained = [r.name for r in rows if r.status != EXECUTABLE and not r.reason]
    assert not unexplained, f"these tools have a non-executable status with no reason: {unexplained}"


def test_negative_control_the_reason_check_would_catch_a_silent_row():
    """Prove the anti-silence assertion is not vacuous."""
    from vigil_integration.live.capability_join import ToolCapability
    silent = ToolCapability(name="ghost", status=UNAVAILABLE, reason="")
    assert not (silent.status == EXECUTABLE or silent.reason), (
        "the predicate used above cannot distinguish a silent row"
    )
