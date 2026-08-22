"""H4b-A — the brain proposal serialiser can annotate each step with its CAPABILITY status.

``proposal_document`` gained an optional ``capabilities`` map so the Brain-decision panel can render WHY a
proposed tool is executable / blocked / unavailable, instead of the plan quietly carrying a step that can
never run. The annotation is a straight lookup over the caller's own data (from ``live.capability_join``) —
the serialiser stays PURE (it probes no host and computes no status), and the default (no map) is
BYTE-IDENTICAL to before.

This is the pure/stdlib acceptance for that serialiser: it drives a REAL comprehensive-web chain from the
brain, computes real capability rows with ``capability_join.join`` over the committed catalogue + the brain
danger table + an INJECTED installed map (so the join is deterministic, host-independent), and asserts the
annotation discriminates (BLOCKED vs EXECUTABLE), is non-vacuous, and is silent-free.
"""
from __future__ import annotations

import pytest

# join() itself is pure stdlib, but computing the real builder set imports the executor, which imports the
# gateway package; skip cleanly if it is not on the path. In CI this test runs in the P5 "integration
# two-env boundary" leg, whose PYTHONPATH includes `gateway`, so vigil_gateway is importable and this test
# is NOT skipped there (verified) -- it is not a framework/offense-leg test.
pytest.importorskip("vigil_gateway")

from vigil_integration.brains.hexstrike_brain import (
    HexstrikeBrain,
    TargetType,
    _TOOL_DANGER,
    proposal_document,
)
from vigil_integration.live.capability_join import _load_catalogue, join


def _real_chain():
    brain = HexstrikeBrain()
    profile = brain.analyze_target("http://127.0.0.1/")
    assert profile.target_type is TargetType.WEB_APPLICATION
    chain = brain.create_attack_chain(profile, "comprehensive")
    return profile, chain.steps


def _caps(*, installed):
    """Real capability rows folded to the {tool -> {status, reason}} map proposal_document consumes."""
    from vigil_integration.live.executor import _BUILDERS

    brain_tools = {name: d.value for name, d in _TOOL_DANGER.items()}
    rows = join(brain_tools=brain_tools, catalogue=_load_catalogue(),
                builders=list(_BUILDERS), installed=installed)
    return {r.name: {"status": r.status, "reason": r.reason} for r in rows}


def _by_tool(doc):
    return {s["tool"]: s for s in doc["steps"]}


def test_excluded_tool_step_is_annotated_blocked_with_reason():
    profile, steps = _real_chain()
    caps = _caps(installed={"nmap": {"installed": True, "version": "7.94"}})
    doc = proposal_document(profile, steps, capabilities=caps)
    steps_by_tool = _by_tool(doc)
    assert "sqlmap" in steps_by_tool, "the comprehensive web chain should include sqlmap"
    cap = steps_by_tool["sqlmap"]["capability"]
    assert cap["status"] == "BLOCKED", cap
    assert "excluded" in cap["reason"], cap


def test_available_tool_step_is_executable_not_unavailable_discriminates():
    """A tool that is proposable, adapted (has a typed builder) AND injected-installed is EXECUTABLE — the
    annotation is not a constant BLOCKED/UNAVAILABLE stamp."""
    profile, steps = _real_chain()
    caps = _caps(installed={"nmap": {"installed": True, "version": "7.94"}})
    doc = proposal_document(profile, steps, capabilities=caps)
    steps_by_tool = _by_tool(doc)
    assert "nmap" in steps_by_tool
    cap = steps_by_tool["nmap"]["capability"]
    assert cap["status"] == "EXECUTABLE", cap
    assert cap["status"] != "UNAVAILABLE"
    # discrimination: at least two distinct statuses across the annotated chain
    statuses = {s["capability"]["status"] for s in doc["steps"]}
    assert len(statuses) > 1, statuses


def test_default_none_leaves_output_byte_identical_non_vacuous():
    """No capabilities map ⇒ NOT ONE step carries a 'capability' key (byte-identical to before H4b-A)."""
    profile, steps = _real_chain()
    doc = proposal_document(profile, steps)
    assert doc["steps"], "the chain must be non-empty or this control is vacuous"
    assert all("capability" not in s for s in doc["steps"]), \
        "capabilities=None must add no annotation anywhere"


def test_a_tool_absent_from_the_map_is_annotated_capability_unknown():
    """Pin the fallback: a proposed step whose tool the map omits is stamped UNAVAILABLE/'capability
    unknown' — never silently left un-annotated when annotation was requested."""
    profile, steps = _real_chain()
    # a deliberately partial map: annotate only nmap, omit every other tool in the chain
    partial = {"nmap": {"status": "EXECUTABLE", "reason": ""}}
    doc = proposal_document(profile, steps, capabilities=partial)
    steps_by_tool = _by_tool(doc)
    # the omitted tools fall back to the pinned unknown annotation
    absent = [t for t in steps_by_tool if t != "nmap"]
    assert absent, "chain should contain tools other than nmap"
    for t in absent:
        cap = steps_by_tool[t]["capability"]
        assert cap == {"status": "UNAVAILABLE", "reason": "capability unknown"}, (t, cap)
    # and the one present tool keeps its real annotation
    assert steps_by_tool["nmap"]["capability"] == {"status": "EXECUTABLE", "reason": ""}


def test_anti_silence_every_step_annotated_every_non_executable_explained():
    profile, steps = _real_chain()
    caps = _caps(installed={"nmap": {"installed": True, "version": "7.94"}})
    doc = proposal_document(profile, steps, capabilities=caps)
    for s in doc["steps"]:
        cap = s["capability"]
        assert cap["status"], ("statusless step", s)
        if cap["status"] != "EXECUTABLE":
            assert cap["reason"], ("a non-executable step with no reason is the silence this removes", s)
