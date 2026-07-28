"""
knowledge_engine.deeplearn — FIND / DETECT / PREVENT deep-learn for a vulnerability lead (K3).

Everything produced here is ADVISORY, never a fact:

  * FIND / PREVENT  → markdown SKILLS (no tier/authority; SkillLoader-loadable) written under
    ``knowledge/skills/{find,prevent}/<id>.md``. A skill is guidance, it authorises nothing.
  * DETECT          → resolves the vuln's bug_class onto an EXISTING deterministic ``OracleKind`` via the
    canonical ``verify.verifier.BUG_CLASS_ORACLES``. When the substrate can already adjudicate the class,
    the detect skill names those existing kinds (advisory). When it cannot, K3 drafts a GATED
    ``improve.ImprovementProposal`` for a REAL deterministic oracle — authorize≠apply, it never touches
    the tree, and it is NEVER a soft/LLM oracle and NEVER an invented kind.

K3 does NOT prove the vuln exists, arm any exploit, fire an oracle, or mint a fact — only a fired oracle
mints a FACT. It also does NOT bump the calibrated MLS Beta priors: those are "recorded after-the-fact,
never invented" (memory/priors.py), and a learned-about vuln is not a test outcome — injecting one would
pollute the calibrated priors. Ranking stays with the advisory skills/leads (retrieve.py).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

# Curated CWE → canonical bug_class. Only CWEs that map CLEANLY onto a class the deterministic oracle
# vocabulary can adjudicate are listed; anything else falls through to the gated-proposal path (honest:
# we do not force a shaky mapping just to claim coverage).
_CWE_TO_BUGCLASS = {
    "CWE-89": "sqli", "CWE-564": "sqli",
    "CWE-78": "command_injection", "CWE-77": "command_injection",
    "CWE-79": "xss", "CWE-94": "rce", "CWE-434": "rce",
    "CWE-918": "ssrf", "CWE-611": "xxe", "CWE-776": "xxe",
    "CWE-502": "deserialization", "CWE-90": "ldap_injection", "CWE-643": "xpath_injection",
    "CWE-1336": "ssti", "CWE-917": "el_injection",
    "CWE-639": "idor", "CWE-862": "broken_access_control", "CWE-285": "authorization",
    "CWE-863": "authorization", "CWE-287": "auth_bypass", "CWE-306": "auth_bypass",
    "CWE-601": "open_redirect", "CWE-943": "nosqli",
}
_ID_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$")


@dataclass(frozen=True)
class DetectResolution:
    """How DETECT was resolved for a vuln. ``mapped`` → the bug_class maps onto ``oracle_kinds`` (existing
    deterministic kinds that CAN adjudicate the class — advisory, not a claim the vuln is present). Else a
    gated DRAFT proposal was authored (``proposal_id`` set) for a real oracle."""

    bug_class: str
    mapped: bool
    oracle_kinds: list          # existing OracleKind VALUES (empty when unmapped)
    proposal_id: str | None     # a drafted improve.ImprovementProposal id (when unmapped), else None


@dataclass(frozen=True)
class DeepLearnResult:
    vuln_id: str
    find_skill: str
    detect_skill: str
    prevent_skill: str
    detect: DetectResolution
    skill_ref: str              # the id-linkage back to the lead (no new node kind; convention-based)


def _safe_id(vuln_id: str) -> str:
    vid = str(vuln_id or "").strip()
    if not _ID_OK.match(vid):
        raise ValueError(f"unsafe vuln id for a skill filename: {vuln_id!r}")
    return vid


def _bug_class_of(vuln_lead: dict) -> str:
    """Best-effort canonical bug_class for a vuln lead: an explicit ``bug_class`` hint wins, else the first
    mappable CWE. Empty when nothing maps (→ the gated-proposal path)."""
    hint = str(vuln_lead.get("bug_class") or "").strip()
    if hint:
        return hint
    for cwe in vuln_lead.get("cwes") or []:
        key = str(cwe or "").strip().upper()
        if key in _CWE_TO_BUGCLASS:
            return _CWE_TO_BUGCLASS[key]
    return ""


def _resolve_detect(vuln_lead: dict, *, now: datetime, proposals_out: list | None) -> DetectResolution:
    from ..verify.verifier import BUG_CLASS_ORACLES, is_known_bug_class, normalize_bug_class

    bc = _bug_class_of(vuln_lead)
    if bc and is_known_bug_class(bc):
        key = normalize_bug_class(bc)
        kinds = BUG_CLASS_ORACLES.get(key, ())
        # defense-in-depth: EVERY kind must be a real OracleKind — `_coerce_oracle_kind` raises PluginError
        # on an invented kind, so K3 can never emit a detect mapping onto a non-existent oracle.
        from ..plugins.registry import _coerce_oracle_kind
        validated = [_coerce_oracle_kind(k).value for k in kinds]
        return DetectResolution(bug_class=key, mapped=bool(validated), oracle_kinds=validated,
                                proposal_id=None)
    # unknown / unmappable class → a GATED draft proposal for a REAL deterministic oracle (authorize≠apply).
    proposal = _draft_oracle_proposal(vuln_lead, bc, now=now)
    if proposals_out is not None:
        proposals_out.append(proposal)
    return DetectResolution(bug_class=bc, mapped=False, oracle_kinds=[], proposal_id=proposal.id)


def _draft_oracle_proposal(vuln_lead: dict, bug_class: str, *, now: datetime):
    """A DRAFT improve.ImprovementProposal proposing a REAL deterministic oracle for a class the substrate
    cannot yet adjudicate. Described-only (empty patch); status DRAFT. It authorises nothing and is never
    a soft/LLM oracle — merge_gate.evaluate_merge (capability + eval + m-of-n approvals) is the separate,
    human-applied gate, and it never touches the tree."""
    from ..improve.models import ImprovementProposal, ProposedChange

    vid = str(vuln_lead.get("id") or vuln_lead.get("vuln_id") or "").strip()
    label = bug_class or "unclassified"
    change = ProposedChange(
        target_artifact=f"oracle:{label}", change_type="add_technique",
        summary=(f"Propose a real DETERMINISTIC oracle for bug class {label!r} (surfaced by {vid}). "
                 f"It must confirm over data a real target produced — never a soft/LLM oracle."),
        patch="")
    return ImprovementProposal(
        id=f"detect-oracle-{_safe_id(vid)}", title=f"DETECT oracle for {label} ({vid})",
        rationale=(f"The vuln-intel lead {vid} names bug class {label!r}, which the deterministic oracle "
                   f"substrate cannot yet adjudicate. Draft a real oracle (gated: authorise≠apply)."),
        gap_ids=[], change=change, created_at=now)


def _frontmatter(*, skill_id: str, name: str, description: str, category: str) -> str:
    # scalar frontmatter the SkillLoader parses (id/name/description/category); no tier/authority key.
    return (f"---\nid: {skill_id}\nname: {name}\ndescription: {description}\ncategory: {category}\n---\n")


def _write_skill(dir_path: Path, vuln_id: str, category: str, name: str, description: str, body: str) -> Path:
    dir_path.mkdir(parents=True, exist_ok=True)
    path = dir_path / f"{_safe_id(vuln_id)}.md"
    content = _frontmatter(skill_id=f"{category}-{_safe_id(vuln_id)}", name=name,
                           description=description, category=category) + body
    path.write_text(content, encoding="utf-8")
    return path


def _find_body(vuln_lead: dict, detect: DetectResolution) -> str:
    vid = vuln_lead.get("id") or vuln_lead.get("vuln_id")
    sev = vuln_lead.get("severity") or "unknown"
    ek = "yes (CISA KEV)" if vuln_lead.get("exploit_known") else "no"
    return (f"# FIND — {vid}\n\n"
            f"- Advisory guidance to LOCATE the surface {vid} affects. This is a LEAD, not a finding: "
            f"confirming the vuln requires a fired oracle over real target data.\n"
            f"- Severity: {sev}. Known-exploited: {ek}. Bug class: {detect.bug_class or 'unclassified'}.\n"
            f"- Look for the affected product/version in scope; enumerate the reachable entry points; "
            f"map inputs that reach the vulnerable code path.\n")


def _detect_body(vuln_lead: dict, detect: DetectResolution) -> str:
    vid = vuln_lead.get("id") or vuln_lead.get("vuln_id")
    if detect.mapped:
        kinds = ", ".join(detect.oracle_kinds)
        return (f"# DETECT — {vid}\n\n"
                f"- Bug class `{detect.bug_class}` is adjudicable by the EXISTING deterministic oracle "
                f"kind(s): **{kinds}**. A fact is minted only when such an oracle FIRES over data a real "
                f"target produced — this skill points at the oracle, it does not itself confirm anything.\n")
    return (f"# DETECT — {vid}\n\n"
            f"- Bug class `{detect.bug_class or 'unclassified'}` is NOT yet adjudicable by the deterministic "
            f"substrate. A gated proposal (`{detect.proposal_id}`) was drafted for a REAL oracle "
            f"(authorise≠apply; never a soft/LLM oracle). Until such an oracle exists and fires, any signal "
            f"here stays a LEAD.\n")


def _prevent_body(vuln_lead: dict, detect: DetectResolution) -> str:
    vid = vuln_lead.get("id") or vuln_lead.get("vuln_id")
    return (f"# PREVENT — {vid}\n\n"
            f"- Advisory remediation guidance for bug class `{detect.bug_class or 'unclassified'}`. "
            f"Patch/upgrade the affected component; apply input validation / output encoding / least "
            f"privilege appropriate to the class; add the detection oracle above to catch regressions.\n"
            f"- This is guidance, not a guarantee: it authorises no change and confirms no fix.\n")


def deep_learn(vuln_lead: dict, *, skills_dir: Path, now: datetime,
               proposals_out: list | None = None) -> DeepLearnResult:
    """Deep-learn one vulnerability lead into FIND / DETECT / PREVENT advisory skills + a DETECT resolution.

    Writes three markdown skills under ``skills_dir/{find,detect,prevent}/<id>.md`` and resolves DETECT onto
    an existing oracle kind or a gated draft proposal (appended to ``proposals_out`` when supplied). ``now``
    is injected (no wallclock in the core), so a given lead deep-learns deterministically. Returns a
    ``DeepLearnResult``; mints no fact and mutates no store — the skill_ref is the id-linkage convention.
    """
    vuln_id = _safe_id(str(vuln_lead.get("id") or vuln_lead.get("vuln_id") or ""))
    detect = _resolve_detect(vuln_lead, now=now, proposals_out=proposals_out)
    find_p = _write_skill(skills_dir / "find", vuln_id, "find", f"Find {vuln_id}",
                          f"Advisory: locate the surface {vuln_id} affects (a lead).", _find_body(vuln_lead, detect))
    detect_p = _write_skill(skills_dir / "detect", vuln_id, "detect", f"Detect {vuln_id}",
                            f"Advisory: which existing oracle adjudicates {vuln_id}'s class.",
                            _detect_body(vuln_lead, detect))
    prevent_p = _write_skill(skills_dir / "prevent", vuln_id, "prevent", f"Prevent {vuln_id}",
                             f"Advisory: remediation for {vuln_id}'s class.", _prevent_body(vuln_lead, detect))
    return DeepLearnResult(vuln_id=vuln_id, find_skill=str(find_p), detect_skill=str(detect_p),
                           prevent_skill=str(prevent_p), detect=detect,
                           skill_ref=f"advisory:skill:{vuln_id}")
