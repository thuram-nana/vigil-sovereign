"""H8 — turn an executed tool's raw output into LEADs, so a brain-driven run stops finding nothing.

THE DEFECT. On ``vigil engage --brain hexstrike`` the engine executed tools and produced **zero facts and
zero leads**, by construction:

    BrainThink.__call__      builds an LLMDecision and never sets ``output_analysis``   (it has no LLM)
    live/engine.py           intake_result(raw, decision.output_analysis, …)            → None
    agent/react.py           ``if analysis is None: return IntakeResult(facts, leads)`` → both empty

So nmap XML, nuclei JSONL and httpx JSONL were hashed into the signed ExecRecord, posted to the spine as a
byte count, and DISCARDED. A test even asserted ``report.fact_count == 0`` as intended behaviour.

``output_analysis`` was designed for the LLM's inline claims. A deterministic planner has none — but the
tool's own output is structured, and VIGIL already ships parsers for it. This derives the analysis from the
BYTES instead of from a model.

WHY THIS CANNOT MINT A FACT — three independent reasons, none of them a promise:

  1. ``exploit_succeeded`` is set to False, so ``intake_result`` never fires the oracle from this path.
  2. ``react._finding_from_claim`` hard-codes ``status="lead"``; a claim cannot describe itself as a fact.
  3. The programme's load-bearing rule stands: re-deriving a verdict over PRODUCER-SUPPLIED bytes proves
     internal consistency, not reality. A FACT needs a VIGIL-owned live capture, which is the separate
     re-drive path (``run_external_tool``'s ``Redrive`` → ``verdict.admit()``), not this one.

So this closes "0 leads" — deliberately not "0 facts". Promoting any of these leads is the re-drive work.
"""
from __future__ import annotations

from typing import Any, Callable, Optional

from ..agent.state import OutputAnalysis

#: Tool name -> the key under which framework's parser registry files its parser.
#: ``zaproxy`` is the roster/builder name; the parser registry files it as ``zap``.
_PARSER_ALIASES = {"zaproxy": "zap"}

#: Tools whose output this module deliberately does NOT parse here.
#: nmap already has a runner-owned re-drive (capture_handshake -> SERVICE_REACHABILITY) that produces a
#: real FACT; routing it through here as well would add a weaker duplicate claim for the same observation.
_NOT_PARSED_HERE = {"nmap"}


def _parser_for(tool_name: str) -> Optional[Callable[[str], list]]:
    """The framework parser for this tool, or None. Import is function-local (FATAL-2 hygiene)."""
    name = _PARSER_ALIASES.get(tool_name, tool_name)
    if not name or name in _NOT_PARSED_HERE:
        return None
    try:
        from framework.v2.imports.parsers import _PARSERS
    except Exception:  # noqa: BLE001 — no offense engine on this path ⇒ no parser-derived leads
        return None
    entry = _PARSERS.get(name)
    if entry is None:
        return None
    # The registry files each parser as a (function, label) pair.
    fn = entry[0] if isinstance(entry, tuple) else entry
    return fn if callable(fn) else None


def _claim(finding: Any, tool_name: str) -> dict:
    """One parsed finding as a PROPOSAL dict shaped for ``react._finding_from_claim``."""
    bug_class = str(getattr(finding, "bug_class", "") or "")
    location = str(getattr(finding, "location", "") or "")
    host = str(getattr(finding, "host", "") or "")
    where = location or host
    return {
        "ref": f"{tool_name}:{bug_class or 'finding'}:{where}" if where else f"{tool_name}:{bug_class}",
        "bug_class": bug_class,
        "title": f"{bug_class or 'finding'} reported by {tool_name}" + (f" at {where}" if where else ""),
        "severity": str(getattr(finding, "severity", "") or ""),
    }


def analysis_from_tool_output(tool_name: str, raw: str) -> Optional[OutputAnalysis]:
    """Derive PROPOSED findings from a tool's own output. Returns None when nothing can be derived.

    Never raises: a parser that chokes on unexpected bytes yields no leads rather than sinking the run.
    """
    if not tool_name or not raw:
        return None
    parser = _parser_for(tool_name)
    if parser is None:
        return None
    try:
        parsed = parser(raw) or []
    except Exception:  # noqa: BLE001 — a malformed tool output is not a reason to fail the engagement
        return None
    claims = [_claim(f, tool_name) for f in parsed]
    if not claims:
        return None
    return OutputAnalysis(
        # NEVER True from a parser: this is exactly the assertion the oracle exists to check, and nothing
        # here observed an exploit — only that a tool said something about the target.
        exploit_succeeded=False,
        new_information_gained=True,
        verdict="new_info",
        findings=claims,
        notes=(f"{len(claims)} proposal(s) parsed from {tool_name} output by a VIGIL parser. Every one is "
               f"a LEAD: a tool's say-so is not evidence, and promotion requires a VIGIL-owned re-drive."),
    )
