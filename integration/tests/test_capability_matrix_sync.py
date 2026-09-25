"""H4 CI sync-check — the tool catalogue stays HONEST: nothing the planner can propose silently disappears.

The measured defect (Part II / H4 of the STRIX+HEXSTRIKE plan): what VIGIL knows about a tool is scattered
across registries that share no key. The brain (``brains/hexstrike_brain.py::_TOOL_DANGER``) proposes a set of
tools; the capability matrix (``docs/capability-matrix/hexstrike.json``) documents another; the typed argv
builders (``live/executor.py::_BUILDERS``) are the only tools that can actually be spawned. A tool the planner
proposes but VIGIL cannot execute used to just VANISH at run time — the chain listed it, the executor denied it
fail-closed (``executor.py`` ``_deny``), and no committed surface said why.

This suite is the sync-check the plan requires (H4 / release-gate item 4: "every planned tool is either
executable or explicitly UNAVAILABLE/BLOCKED with a reason"). It FAILS if any brain-proposable tool is neither
in the matrix nor marked excluded-with-a-reason, and it pins the honest bucket counts so a future edit that
re-opens the silent gap goes RED.

SOVEREIGN-SAFE (runs in the P5 ``integration two-env boundary`` required job): every import here is
stdlib-only (``hexstrike_brain``), vigil_core+stdlib (``tool_manifest``), or a function-local join
(``capability_join``/``executor`` — resolved via ``vigil_gateway`` on PYTHONPATH, NOT ``framework``). It does
NOT skip-import the offense engine, so no offense-leg run-list entry is required (the
test_ci_framework_tests_run_in_offense_leg guard does not implicate this file).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from vigil_integration.brains.hexstrike_brain import _TOOL_DANGER
from vigil_integration.live.executor import _BUILDERS
from vigil_integration.live.capability_join import (
    BLOCKED,
    EXECUTABLE,
    NOT_PROPOSABLE,
    UNAVAILABLE,
    join,
    resolve,
)
from vigil_integration.live.tool_manifest import (
    ToolManifest,
    load_manifests,
    validate_all,
    validate_capability_sync,
)

_MATRIX = Path(__file__).resolve().parents[2] / "docs" / "capability-matrix" / "hexstrike.json"


def _proposable() -> dict[str, str]:
    """The planner's catalogue: name -> danger class, from the brain's guardrail whitelist. A tool is
    proposable iff it is a key of ``_TOOL_DANGER`` (``create_attack_chain`` and ``select_optimal_tools`` both
    drop any tool not in this map), so this IS the authoritative proposable set."""
    return {name: getattr(d, "value", str(d)) for name, d in _TOOL_DANGER.items()}


def _manifests() -> list[ToolManifest]:
    return load_manifests(_MATRIX)


def _by_name() -> dict[str, ToolManifest]:
    return {m.name: m for m in _manifests()}


# --- the core sync-check: coverage + honesty ----------------------------------------------------------

def test_every_brain_proposable_tool_is_present_in_the_matrix():
    """THE check: a tool the brain can propose must have a matrix row — never silently missing. Before the
    H4 backfill, 18 of the 36 proposable tools had no row at all (the chain listed them, the executor denied
    them, and nothing explained why)."""
    proposable = set(_proposable())
    catalogued = {m.name for m in _manifests()}
    missing = sorted(proposable - catalogued)
    assert not missing, (
        "these tools are PROPOSABLE by the brain but ABSENT from docs/capability-matrix/hexstrike.json, so a "
        "plan can drop them silently. Add a row for each (excluded-with-reason, or LEAD-only with a reason in "
        f"notes): {missing}"
    )


def test_the_committed_matrix_passes_the_cross_registry_sync_invariant():
    """The same rule via the validator that OWNS it (``tool_manifest.validate_capability_sync``): every
    proposable tool is present AND carries a reason."""
    errs = validate_capability_sync(_TOOL_DANGER.keys(), _manifests())
    assert not errs, "capability-matrix sync violations:\n  " + "\n  ".join(errs)


def test_the_committed_matrix_is_internally_valid_after_the_backfill():
    """The backfilled rows must be HONEST under every per-row invariant (excluded ⇒ ¬fact_capable,
    fact_capable ⇒ oracle_family, offense name backstop, and non-fact_capable ⇒ a REASON in notes). A row
    added to pass the coverage check must not overclaim to do so."""
    errs = validate_all(_manifests())
    assert not errs, "capability matrix invariant violations:\n  " + "\n  ".join(errs)


def test_the_backfill_did_not_fake_fact_capability():
    """The pinned fact_capable set is exactly the tools with a shipped runner-owned re-drive that PASSED the
    conformance battery — never a faked claim. The H4 backfill added LEAD-only/UNAVAILABLE rows only; the H5
    reuse (masscan/rustscan/naabu) and its W1 batch-2 promotion (zmap/unicornscan) each earned their FACT via
    live.conformance.run_toolspec_conformance over VIGIL's own gated handshake, not by editing this pin."""
    fact = {m.name for m in _manifests() if m.fact_capable}
    assert fact == {"nmap", "sslscan", "masscan", "rustscan", "naabu", "zmap", "unicornscan"}, (
        f"unexpected fact_capable set after backfill: {fact}"
    )


# --- tie the matrix data to the runtime view: nothing renders statusless/reasonless -------------------

def test_no_proposable_tool_is_dropped_from_the_joined_capability_view():
    """Every proposable tool must appear in the join with a status that is EXECUTABLE or carries a reason —
    and never NOT_PROPOSABLE (which would mean the join disagrees the planner can propose it)."""
    rows = {r.name: r for r in resolve()}          # static: no host probe, so nothing is promised runnable
    for name in _proposable():
        assert name in rows, f"{name} is proposable but absent from the joined capability view"
        r = rows[name]
        assert r.proposable, f"{name}: the join does not consider a proposable tool proposable"
        assert r.status != NOT_PROPOSABLE, f"{name}: proposable tool classified NOT_PROPOSABLE"
        assert r.status == EXECUTABLE or r.reason, (
            f"{name}: status {r.status} with no reason — exactly the silence this check exists to remove"
        )


def test_a_proposable_but_excluded_tool_is_blocked_with_a_reason_not_silent():
    """sqlmap is BOTH proposable (brain vulnerability_assessment playbook) AND excluded (VIGIL owns SQLi
    confirmation via its own gated re-drive, never sqlmap). That is the allowed "OR excluded-with-a-reason"
    branch: it stays in the matrix, excluded, with a reason, and the join renders it BLOCKED — surfaced, not
    dropped. (The brain proposing an excluded tool is a known, harmless inefficiency: the step is refused
    with a visible reason rather than run.)"""
    m = _by_name()["sqlmap"]
    assert m.excluded and not m.fact_capable and m.notes.strip()
    row = {r.name: r for r in resolve()}["sqlmap"]
    assert row.status == BLOCKED and "excluded" in row.reason


def test_previously_missing_tools_including_two_adapted_ones_are_now_catalogued():
    """Regression guard on the exact backfill. ffuf and nikto are the sharp cases: they HAVE a typed argv
    builder (they are adapted and executable-if-installed) yet were absent from the matrix — an adapted tool
    disappearing is the worst form of the silent gap. All 18 must now be present."""
    catalogued = {m.name for m in _manifests()}
    backfilled = {
        "amass", "arjun", "arp-scan", "autorecon", "dalfox", "dirsearch", "enum4linux-ng", "feroxbuster",
        "ffuf", "gau", "jaeles", "nbtscan", "nikto", "paramspider", "smbmap", "waybackurls", "wpscan", "x8",
    }
    assert backfilled <= catalogued, f"still missing: {sorted(backfilled - catalogued)}"
    for adapted in ("ffuf", "nikto"):
        assert adapted in _BUILDERS, f"{adapted} was expected to have a typed argv builder"
        assert not _by_name()[adapted].fact_capable, f"{adapted}: adapted, but its output is LEAD-only"


# --- the honest bucket counts the sync-check reports (and pins) ---------------------------------------

def test_the_bucket_counts_are_the_measured_honest_numbers():
    """Report + pin: how the 38 proposable tools classify. 'Adapted' = has a typed executor argv builder (the
    only thing the GOVERNED executor can spawn); 'BLOCKED' = excluded-with-reason; the rest are UNAVAILABLE
    with a reason (no typed executor builder). NOTE: the SERVICE_REACHABILITY port scanners
    (masscan/rustscan/naabu and the W1 batch-2 zmap/unicornscan) are driven by a runner-owned ToolSpec builder
    on the R4 runner path — NOT the governed executor's _BUILDERS — so they sit in the no_builder bucket here
    even though capability_join renders them EXECUTABLE-if-installed. Every proposable tool carries a reason."""
    proposable = set(_proposable())
    by = _by_name()
    excluded = {n for n in proposable if by[n].excluded}
    adapted = proposable & set(_BUILDERS)                     # has a typed executor argv builder
    adapted_runnable = adapted - excluded                    # would run once installed
    no_builder = proposable - set(_BUILDERS)                 # no typed executor builder (R4-runner tools land here)

    assert len(proposable) == 38, len(proposable)
    assert excluded == {"sqlmap"}, excluded
    assert adapted == {"ffuf", "httpx", "nikto", "nmap", "nuclei", "sqlmap"}, adapted
    assert adapted_runnable == {"ffuf", "httpx", "nikto", "nmap", "nuclei"}, adapted_runnable
    assert len(no_builder) == 32, len(no_builder)

    # Every proposable tool is rendered (present + reason) — the anti-silence guarantee, at the data layer.
    assert validate_capability_sync(proposable, _manifests()) == []
    for n in proposable:
        assert by[n].notes.strip(), f"{n}: rendered without a reason"


# --- negative controls: prove the checks are not vacuous ----------------------------------------------

def test_sync_invariant_flags_a_proposable_tool_absent_from_the_matrix():
    """If a proposable tool has NO matrix row, the validator must object with 'ABSENT' — otherwise the whole
    check is vacuous."""
    errs = validate_capability_sync(["ghosttool"], _manifests())
    assert any("ghosttool" in e and "ABSENT" in e for e in errs), errs


def test_sync_invariant_flags_a_matrix_row_rendered_without_a_reason():
    """A proposable tool present in the matrix but with empty notes is 'rendered without a reason' — a silent
    row by another route — and must be flagged."""
    reasonless = ToolManifest(name="quietscan", category="recon", network_effect="connects-out")
    errs = validate_capability_sync(["quietscan"], [reasonless])
    assert any("quietscan" in e and "WITHOUT a reason" in e for e in errs), errs
    # and with a reason present, the sync invariant is satisfied
    with_reason = ToolManifest(name="quietscan", category="recon", network_effect="connects-out",
                               notes="LEAD-only proposer; no argv builder yet — UNAVAILABLE until adapted")
    assert validate_capability_sync(["quietscan"], [with_reason]) == []


def test_negative_control_the_coverage_predicate_would_catch_a_dropped_tool():
    """Prove the set-difference in the coverage test is not vacuous: deleting any real row makes it fail."""
    proposable = set(_proposable())
    catalogued = {m.name for m in _manifests()}
    assert proposable <= catalogued                      # holds on the committed matrix
    victim = next(iter(proposable))
    assert not (proposable <= (catalogued - {victim})), (
        "removing a proposable tool from the matrix must break coverage"
    )


def test_negative_control_the_join_reason_check_would_catch_a_silent_row():
    """The join synthesizes a reason for every non-EXECUTABLE row; a bare synthetic proposable tool with no
    matrix row and no builder must still surface UNAVAILABLE WITH a reason — never silent."""
    rows = {r.name: r for r in join(brain_tools={"phantom": "recon"}, catalogue={}, builders=[])}
    r = rows["phantom"]
    assert r.status == UNAVAILABLE and r.reason, "a proposable tool with no adapter must be UNAVAILABLE-with-reason"
