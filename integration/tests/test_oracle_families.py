"""H7 — integrate discovery tools by SHARED ORACLE FAMILY, not per tool.

SOVEREIGN-SAFE (runs in the P5 ``integration two-env boundary`` required job): every import here is
stdlib-only (``hexstrike_brain``) or vigil_core+stdlib (``oracle_families`` / ``tool_manifest``). It does
NOT import the offense engine, so no offense-leg run-list entry is required (the
``test_ci_framework_tests_run_in_offense_leg`` guard does not implicate this file).

The three load-bearing checks the H7 slice must prove:
  1. a family ROUTES its member tools to its ONE VIGIL verifier (and every discovery tool routes somewhere);
  2. scanner VOTING raises PRIORITY but produces a LEAD, NEVER a FACT (the negative control — even a
     unanimous, FACT-capable family cannot vote a FACT into existence);
  3. an existing FACT-capable family still mints ONLY via its own runner re-drive, which is DEFAULT-OFF /
     flag-gated — routing and voting never mint.
"""
from __future__ import annotations

from pathlib import Path

from vigil_integration.brains.hexstrike_brain import _TOOL_DANGER
from vigil_integration.live import oracle_families as of
from vigil_integration.live.oracle_families import (
    FamilyVote,
    ToolObservation,
    family_for,
    fuse,
    oracle_mapped_tools,
    raised_priority,
    route,
    validate_family_routing,
    verifier_for,
)
from vigil_integration.live.tool_manifest import ToolManifest, load_manifests

_MATRIX = Path(__file__).resolve().parents[2] / "docs" / "capability-matrix" / "hexstrike.json"


# --- registry integrity -------------------------------------------------------------------------------

def test_the_family_registry_is_internally_sound():
    """No family name is duplicated and no tool is claimed by two families — routing must be unambiguous
    (a tool feeds exactly one shared verifier). Building the index would already raise on a violation; this
    pins the property and the family set."""
    names = [f.name for f in of.families()]
    assert len(names) == len(set(names)), f"duplicate family name: {names}"
    seen: dict[str, str] = {}
    for f in of.families():
        assert f.verifier, f"{f.name}: a family must name a verifier"
        for t in f.tools:
            assert t not in seen, f"{t!r} claimed by both {seen[t]!r} and {f.name!r}"
            seen[t] = f.name
    assert set(names) == {
        "network_discovery", "web_discovery", "scanners", "injection", "tls",
        "source", "posture", "secrets", "browser",
    }, names


# --- (1) a family routes to its verifier --------------------------------------------------------------

def test_each_family_routes_its_members_to_its_one_verifier():
    """THE routing check: every member tool of a family resolves to that family's single verifier — the
    per-tool mapping is replaced by a by-family one."""
    for fam in of.families():
        for tool in fam.tools:
            assert family_for(tool) is fam, f"{tool}: family_for disagrees with membership"
            assert verifier_for(tool) == fam.verifier, f"{tool}: routed to the wrong verifier"


def test_the_named_families_map_the_task_tools_to_the_expected_verifiers():
    """The families the H7 spec names, mapped to their shared VIGIL verifier."""
    cases = {
        "nmap": ("network_discovery", "SERVICE_REACHABILITY"),
        "naabu": ("network_discovery", "SERVICE_REACHABILITY"),
        "rustscan": ("network_discovery", "SERVICE_REACHABILITY"),
        "httpx": ("web_discovery", "ACHIEVED_STATE"),
        "katana": ("web_discovery", "ACHIEVED_STATE"),
        "ffuf": ("web_discovery", "ACHIEVED_STATE"),
        "gobuster": ("web_discovery", "ACHIEVED_STATE"),
        "nuclei": ("scanners", "bug_class"),
        "nikto": ("scanners", "bug_class"),
        "dalfox": ("injection", "DIFFERENTIAL_RESPONSE"),
        "arjun": ("injection", "DIFFERENTIAL_RESPONSE"),
        "sslscan": ("tls", "TLS_WEAKNESS"),
        "trivy": ("posture", "posture"),
        "kube-bench": ("posture", "posture"),
    }
    for tool, (fam, verifier) in cases.items():
        assert family_for(tool).name == fam, f"{tool}: wrong family"
        assert verifier_for(tool) == verifier, f"{tool}: wrong verifier"


def test_a_pure_offense_tool_routes_to_no_family():
    """An EXCLUDED offense/credential binary is not a discovery proposer — it feeds no shared verifier, so
    routing returns None (and route() emits a LEAD-only decision)."""
    for tool in ("metasploit", "hydra", "pwntools", "john"):
        assert family_for(tool) is None, f"{tool} should not route to a discovery family"
    r = route("metasploit")
    assert r.family == "" and r.verdict == "LEAD" and r.mint_via_redrive is False


def test_every_non_excluded_proposable_tool_routes_to_a_family():
    """No planner-proposable discovery tool is silently un-routed — the by-family generalisation of the H4
    'nothing disappears' rule. Excluded tools (sqlmap) are exempt: they route nowhere by design."""
    by = {m.name: m for m in load_manifests(_MATRIX)}
    unrouted = sorted(
        t for t in _TOOL_DANGER
        if family_for(t) is None and not (t in by and by[t].excluded)
    )
    assert not unrouted, f"proposable non-excluded tools with no oracle family: {unrouted}"


def test_the_family_registry_agrees_with_the_capability_matrix():
    """The family registry must not contradict the committed matrix: every non-excluded catalogued tool
    routes to a family, and every fact_capable row belongs to a fact_capable family whose verifier matches
    the row's oracle_family."""
    errs = validate_family_routing(load_manifests(_MATRIX))
    assert not errs, "family-routing violations:\n  " + "\n  ".join(errs)


# --- (2) scanner voting: raised-priority LEAD, NEVER a FACT (negative control) -------------------------

def test_scanner_voting_raises_priority_but_stays_a_lead():
    """Three scanners agree on the same web bug at the same URL. Their agreement raises the lead's priority
    (numerically lower), but the fused verdict is a LEAD — a say-so is not evidence, N say-sos are still a
    LEAD (the authority ladder: scanner report → LEAD only)."""
    obs = [
        ToolObservation("nuclei", "https://t/login#sqli", base_priority=6),
        ToolObservation("nikto", "https://t/login#sqli", base_priority=8),
        ToolObservation("jaeles", "https://t/login#sqli", base_priority=9),
    ]
    votes = fuse(obs)
    assert len(votes) == 1, votes
    v = votes[0]
    assert v.family == "scanners" and v.verifier == "bug_class"
    assert v.agreeing_tools == ("jaeles", "nikto", "nuclei")
    assert v.verdict == "LEAD" and v.is_fact is False
    # base 6 (the most urgent proposer), raised by (3 agreeing - 1) = 2 → priority 4
    assert v.priority == 4, v.priority
    # and a LONE proposer gets no raise
    solo = fuse([ToolObservation("nuclei", "https://t/x#xss", base_priority=6)])
    assert solo[0].priority == 6 and solo[0].agreement == 1


def test_voting_across_a_FACT_capable_family_still_never_mints_a_fact():
    """THE negative control: even the FACT-capable network-discovery family — four scanners UNANIMOUS on the
    same host — votes only a raised-priority LEAD. Agreement is never evidence; only VIGIL's own re-drive
    mints. If a future change let a count of agreeing tools compose into a FACT, this goes red."""
    host = "10.0.0.5"
    obs = [ToolObservation(t, host, base_priority=5)
           for t in ("nmap", "masscan", "rustscan", "naabu")]
    votes = fuse(obs)
    assert len(votes) == 1
    v = votes[0]
    assert v.family == "network_discovery" and v.verifier == "SERVICE_REACHABILITY"
    assert v.agreement == 4
    assert v.verdict == "LEAD" and v.is_fact is False, "a vote across a FACT-capable family MUST stay a LEAD"
    assert v.priority == max(1, 5 - 3)  # raised by 3 additional agreeing tools


def test_every_fuse_output_is_structurally_a_lead():
    """The structural guarantee: no input can make ``fuse`` emit a non-LEAD. Sweep single, agreeing, and
    cross-family observations — every FamilyVote is a LEAD and reports is_fact False."""
    obs = [
        ToolObservation("nmap", "h1", 1), ToolObservation("masscan", "h1", 2),   # network, agree
        ToolObservation("httpx", "u1", 3),                                        # web, solo
        ToolObservation("nuclei", "u1#xss", 4), ToolObservation("nikto", "u1#xss", 4),  # scanners, agree
        ToolObservation("metasploit", "h1", 1),                                   # no family → dropped
    ]
    votes = fuse(obs)
    assert all(isinstance(v, FamilyVote) for v in votes)
    assert all(v.verdict == "LEAD" and v.is_fact is False for v in votes)
    # the no-family tool did not create a vote
    assert all("metasploit" not in v.agreeing_tools for v in votes)
    # cross-family observations never fuse into one vote
    fams = {v.family for v in votes}
    assert fams == {"network_discovery", "web_discovery", "scanners"}, fams


def test_priority_raise_is_bounded_and_deterministic():
    """raised_priority lowers by one per additional agreeing tool, floored at 1, and never below."""
    assert raised_priority(5, 1) == 5      # lone proposer: unchanged
    assert raised_priority(5, 3) == 3      # +2 agreement
    assert raised_priority(2, 10) == 1     # floored at 1, never 0/negative
    assert raised_priority(1, 1) == 1


# --- (3) a FACT-capable family mints only via its own re-drive, DEFAULT-OFF / flag-gated ---------------

def test_routing_emits_leads_by_default_even_for_a_fact_capable_family():
    """With the DEFAULT-OFF flag unset, routing a FACT-capable family's tool emits a LEAD and marks the
    runner re-drive NOT eligible — routing never mints. This is 'emit LEADs by default'."""
    r = route("nmap", env={})   # empty env → VIGIL_FAMILY_REDRIVE unset
    assert r.fact_capable_family is True, "network_discovery is a FACT-capable family"
    assert r.verdict == "LEAD"
    assert r.mint_via_redrive is False, "the runner re-drive must be DEFAULT-OFF (flag unset)"


def test_the_redrive_path_is_flag_gated_and_off_by_default():
    """The flag gates ONLY eligibility of the SEPARATE runner re-drive; the routing verdict is a LEAD either
    way. Off by default; a truthy VIGIL_FAMILY_REDRIVE makes a FACT-capable family's re-drive ELIGIBLE — but
    the FACT is still minted by that gated re-drive, never by routing (verdict stays LEAD)."""
    assert of.redrive_flag_enabled(env={}) is False
    assert of.redrive_flag_enabled(env={"VIGIL_FAMILY_REDRIVE": ""}) is False
    assert of.redrive_flag_enabled(env={"VIGIL_FAMILY_REDRIVE": "1"}) is True
    on = route("nmap", env={"VIGIL_FAMILY_REDRIVE": "1"})
    assert on.mint_via_redrive is True and on.verdict == "LEAD"
    off = route("nmap", redrive_enabled=False)
    assert off.mint_via_redrive is False and off.verdict == "LEAD"


def test_a_lead_only_family_is_never_mint_eligible_even_with_the_flag_on():
    """A LEAD-only family (scanners, injection, posture, source, secrets, browser) never becomes
    mint-eligible — the flag cannot promote a family whose verifier VIGIL cannot mint from."""
    for tool in ("nuclei", "dalfox", "trivy", "gdb"):
        on = route(tool, env={"VIGIL_FAMILY_REDRIVE": "1"})
        assert on.fact_capable_family is False, f"{tool}: its family should be LEAD-only"
        assert on.mint_via_redrive is False, f"{tool}: a LEAD-only family must never be mint-eligible"
        assert on.verdict == "LEAD"


def test_oracle_mapped_derivation_is_a_family_property_not_a_flat_list():
    """The body's FACT-capable set is DERIVED from the family registry: exactly the spec-builder tools whose
    FAMILY is FACT-capable. This is the wiring that replaces the hand-kept flat frozenset."""
    spec_builders = {"nmap", "sslscan", "masscan", "rustscan", "naabu"}
    assert oracle_mapped_tools(spec_builders) == {"nmap", "sslscan", "masscan", "rustscan", "naabu"}
    # a spec-builder tool in a LEAD-only family is NOT fact-capable (a builder alone does not make a FACT)
    assert oracle_mapped_tools({"nuclei"}) == frozenset()
    # a FACT-capable family member with NO spec builder is excluded from the DERIVED set, because it is not
    # in the spec-builder input: subfinder is in the FACT-capable network-discovery family, yet the body's
    # derivation over the real spec-builder set does not make it mint-capable (it has no runner re-drive).
    assert family_for("subfinder").name == "network_discovery"    # a FACT-capable family
    assert "subfinder" not in oracle_mapped_tools(spec_builders)   # but not in the derived set (no builder)
    # the filter is on family fact-capability: only when a tool is BOTH a spec builder AND in a FACT-capable
    # family is it mapped — the two conditions the body composes.
    assert oracle_mapped_tools({"subfinder"}) == {"subfinder"}     # if it HAD a builder, its family qualifies


# --- negative controls: prove the checks are not vacuous ----------------------------------------------

def test_validate_family_routing_flags_a_fact_capable_row_pointing_at_a_lead_only_family():
    """A synthetic matrix row marked fact_capable whose tool lives in a LEAD-only family must be flagged —
    the matrix may not outrun the family registry."""
    row = ToolManifest(name="nuclei", category="active-assessment", oracle_family="bug_class",
                       fact_capable=True, notes="x")
    errs = validate_family_routing([row])
    assert any("nuclei" in e and "LEAD-only" in e for e in errs), errs


def test_validate_family_routing_flags_a_non_excluded_tool_with_no_family():
    """A catalogued, non-excluded tool that routes to no family is the per-tool-scatter defect — flagged."""
    row = ToolManifest(name="ghostscan", category="recon", network_effect="connects-out", notes="x")
    errs = validate_family_routing([row])
    assert any("ghostscan" in e and "NO oracle family" in e for e in errs), errs


def test_validate_family_routing_flags_a_verifier_mismatch():
    """A fact_capable row whose oracle_family disagrees with its family's verifier is flagged (the two
    registries must name the same minting verifier)."""
    row = ToolManifest(name="nmap", category="active-assessment", oracle_family="TLS_WEAKNESS",
                       fact_capable=True, notes="x")
    errs = validate_family_routing([row])
    assert any("nmap" in e and "disagree" in e for e in errs), errs
