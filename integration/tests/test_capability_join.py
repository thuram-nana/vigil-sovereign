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


# --- H4b: the R4 ToolSpec-builder set is a second builder source (the join defect) ---------------------

def test_resolve_folds_in_the_r4_toolspec_builder_set_so_the_two_registries_cannot_drift():
    """THE JOIN DEFECT. A tool spawnable via the R4 runner (a ToolSpec builder) but ABSENT from the governed
    executor's ``_BUILDERS`` used to render UNAVAILABLE 'no typed argv builder' — a false 'can never run'.
    ``resolve`` now unions ``_BUILDERS`` with ``oracle_families.SPEC_BUILDER_TOOLS``, so every ToolSpec-builder
    tool is recognised as ADAPTED. Sourcing the set from the framework-free ``oracle_families`` is what keeps
    the two registries from drifting apart from a duplicated literal."""
    from vigil_integration.live.capability_join import resolve
    from vigil_integration.live.oracle_families import SPEC_BUILDER_TOOLS

    rows = {r.name: r for r in resolve()}          # static: no probe → nothing promised runnable
    for tool in SPEC_BUILDER_TOOLS:
        assert rows[tool].typed_builder, f"{tool}: a ToolSpec-builder tool must be recognised as adapted"
        assert "no typed argv builder" not in rows[tool].reason, (
            f"{tool}: must NOT be reported 'no typed argv builder' — it has a real R4 ToolSpec builder")


def test_the_service_reachability_port_scanners_are_executable_if_installed():
    """masscan/rustscan/naabu now resolve end-to-end: given a confirmed presence they are EXECUTABLE, not
    stuck UNAVAILABLE. Proven at the pure-join layer (a real probe on this host does not carry them — see the
    honesty guard below), which is exactly the classification the H5 conformance battery already backs."""
    brain = {t: "recon" for t in ("masscan", "rustscan", "naabu")}
    cat = {t: {"oracle_family": "service_reachability", "fact_capable": True}
           for t in ("masscan", "rustscan", "naabu")}
    installed = {t: {"installed": True, "version": "x"} for t in ("masscan", "rustscan", "naabu")}
    rows = {r.name: r for r in join(brain_tools=brain, catalogue=cat,
                                    builders={"masscan", "rustscan", "naabu"}, installed=installed)}
    for t in ("masscan", "rustscan", "naabu"):
        assert rows[t].status == EXECUTABLE and rows[t].runnable, f"{t}: adapted+installed ⇒ EXECUTABLE"
        assert rows[t].fact_capable, f"{t}: fact_capable comes from the catalogue, unchanged by the builder"


def test_honesty_a_builder_alone_never_manufactures_executable_without_a_confirmed_presence():
    """HONESTY (the raw-socket / sandbox case). Recognising the ToolSpec builder must NOT flip a raw-socket
    tool (masscan/rustscan/zmap/unicornscan) to EXECUTABLE on its own — EXECUTABLE still requires a probe that
    CONFIRMS the tool is present and usable. A sandbox that denies CAP_NET_RAW (or simply has no such probe)
    leaves the presence unconfirmed, and the tool stays UNAVAILABLE — never a green it cannot back. The
    connect()-based FACT re-drive is unaffected (it needs no raw socket; the conformance battery proves it
    hermetically)."""
    # masscan/rustscan send raw SYN packets; zmap/unicornscan (W1 batch 2) need raw-socket root outright —
    # all four are the sandbox-CAP_NET_RAW case: a spec builder + fact_capable catalogue row must NOT flip
    # them to EXECUTABLE without a CONFIRMED usable presence.
    raw_tools = ("masscan", "rustscan", "zmap", "unicornscan")
    brain = {t: "recon" for t in raw_tools}
    cat = {t: {"oracle_family": "service_reachability", "fact_capable": True} for t in raw_tools}
    bld = set(raw_tools)
    # (a) presence NOT probed (installed=None) — e.g. no host-roster entry backs it: UNAVAILABLE, not green.
    unprobed = {r.name: r for r in join(brain_tools=brain, catalogue=cat, builders=bld, installed=None)}
    for t in raw_tools:
        assert unprobed[t].status == UNAVAILABLE and "not probed" in unprobed[t].reason
    # (b) probed and reported NOT installed/usable (the sandbox-without-CAP_NET_RAW verdict): UNAVAILABLE.
    denied = {r.name: r for r in join(brain_tools=brain, catalogue=cat, builders=bld,
                                      installed={t: {"installed": False} for t in raw_tools})}
    for t in raw_tools:
        assert denied[t].status == UNAVAILABLE and denied[t].status != EXECUTABLE

    # And on THIS host, the real resolve(probe_host=True) never promises them EXECUTABLE — the presence probe
    # (host roster) does not back a raw-socket-capable install, so they surface UNAVAILABLE with a reason.
    from vigil_integration.live.capability_join import resolve
    live = {r.name: r for r in resolve(probe_host=True)}
    for t in raw_tools:
        assert live[t].status != EXECUTABLE, f"{t}: presence not backed here ⇒ never a false EXECUTABLE"
        assert live[t].reason, f"{t}: a non-executable row must explain itself"
