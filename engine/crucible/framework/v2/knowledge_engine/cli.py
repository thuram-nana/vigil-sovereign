"""
knowledge_engine.cli — ``python3 -m framework.v2 knowledge <subcommand>``.

  draft   --slug S [--json]                    rank the vuln leads into a propose-to-learn queue (read-only)
  learn   --slug S (--vuln CVE-… | --all)      deep-learn FIND/DETECT/PREVENT advisory skills for a vuln
                                               [--skills-dir DIR]   (default: repo knowledge/skills/)
  skills  [--query Q] [--skills-dir DIR]        retrieve the advisory skillset (skills + CATALOG operators)

Everything here is ADVISORY. `draft` and `learn` mint no facts, fire no oracle, and touch no graph; DETECT
maps only onto EXISTING oracle kinds or drafts a gated proposal (never invents a kind). A learn run under a
`--slug` whose kill-switch is tripped refuses before doing anything.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# repo root = …/knowledge_engine/cli.py → parents: [0]=knowledge_engine [1]=v2 [2]=framework [3]=crucible
# [4]=engine [5]=<repo root>. The committed knowledge/ folder lives at the repo root (K6 syncs it to GitHub).
_REPO_ROOT = Path(__file__).resolve().parents[5]
_DEFAULT_SKILLS = _REPO_ROOT / "knowledge" / "skills"


def _emit(obj) -> int:
    print(json.dumps(obj, indent=2, default=str))
    return 0


def _vuln_leads(slug: str) -> list[dict]:
    """The VULNERABILITY leads for an engagement (mirrors console.api.vulnintel_data's read) — id, severity,
    cvss, exploit_known, cwes. Read-only over the durable intel store."""
    from ..intel.models import IntelSourceKind
    from ..intel.store import IntelStore
    from ..memory.store import Store
    from ..worldmodel.models import NodeKind

    istore = IntelStore(Store())
    obs = istore.observations(engagement_slug=slug) or []
    leads: dict[str, dict] = {}
    for o in obs:
        if (o.source_kind is IntelSourceKind.VULN_DB and o.relation is None
                and o.subject.kind is NodeKind.VULNERABILITY):
            a = o.attrs or {}
            leads[o.subject.node_id] = {
                "id": o.subject.key, "severity": a.get("severity"), "cvss": a.get("cvss"),
                "exploit_known": bool(a.get("exploit_known")), "cwes": a.get("cwes") or [],
                "bug_class": a.get("bug_class"), "summary": a.get("summary")}
    return list(leads.values())


def _draft(args: argparse.Namespace) -> int:
    from .proposals import draft_proposals
    proposals = [p.to_dict() for p in draft_proposals(_vuln_leads(args.slug))]
    out = {"slug": args.slug, "proposals": proposals if args.json else len(proposals),
           "doctrine": "A proposal authorises nothing; accepting one (owner-signed) authorises LEARNING, "
                       "never a fact."}
    return _emit(out)


def _learn(args: argparse.Namespace) -> int:
    from .deeplearn import deep_learn

    if args.slug:
        from ..authority.killswitch import KillSwitch
        if KillSwitch(args.slug).is_tripped():
            print(f"refused: kill-switch tripped for engagement {args.slug!r}", file=sys.stderr)
            return 3

    leads = _vuln_leads(args.slug)
    if args.vuln:
        want = args.vuln.strip().upper()
        leads = [v for v in leads if str(v.get("id", "")).upper() == want]
        if not leads:
            print(f"error: no vulnerability lead {args.vuln!r} for {args.slug!r}", file=sys.stderr)
            return 2
    elif not args.all:
        print("usage: knowledge learn --slug S (--vuln CVE-… | --all)", file=sys.stderr)
        return 2

    skills_dir = Path(args.skills_dir) if args.skills_dir else _DEFAULT_SKILLS
    now = datetime.now(timezone.utc)
    proposals: list = []
    learned = []
    for lead in leads:
        try:
            r = deep_learn(lead, skills_dir=skills_dir, now=now, proposals_out=proposals)
        except ValueError as e:            # unsafe id etc. — skip that lead, keep going
            learned.append({"id": lead.get("id"), "error": str(e)})
            continue
        learned.append({"id": r.vuln_id, "detect_mapped": r.detect.mapped,
                        "oracle_kinds": r.detect.oracle_kinds, "detect_proposal": r.detect.proposal_id,
                        "skills": {"find": r.find_skill, "detect": r.detect_skill, "prevent": r.prevent_skill}})
    out = {"slug": args.slug, "skills_dir": str(skills_dir), "learned": learned,
           "drafted_oracle_proposals": [p.id for p in proposals],
           "doctrine": "Advisory skills/leads only — DETECT maps onto EXISTING oracle kinds or a gated "
                       "proposal; nothing is a fact, nothing is applied, no oracle fired."}
    return _emit(out)


def _skills(args: argparse.Namespace) -> int:
    from .retrieve import retrieve_skillset
    skills_dir = Path(args.skills_dir) if args.skills_dir else _DEFAULT_SKILLS
    return _emit(retrieve_skillset(args.query, skills_dir=skills_dir))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m framework.v2 knowledge",
        description="Knowledge Engine — propose, deep-learn (find/detect/prevent), and retrieve. Advisory.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("draft", help="rank the vuln leads into a propose-to-learn queue (read-only)")
    p.add_argument("--slug", required=True)
    p.add_argument("--json", action="store_true", help="emit the full proposal list, not just the count")
    p.set_defaults(fn=_draft)

    p = sub.add_parser("learn", help="deep-learn FIND/DETECT/PREVENT advisory skills for a vuln")
    p.add_argument("--slug", required=True, help="engagement slug (kill-switch honored)")
    p.add_argument("--vuln", default="", help="a single CVE/advisory id to learn")
    p.add_argument("--all", action="store_true", help="learn every vuln lead for the slug")
    p.add_argument("--skills-dir", default="", dest="skills_dir",
                   help="skills output dir (default: repo knowledge/skills/)")
    p.set_defaults(fn=_learn)

    p = sub.add_parser("skills", help="retrieve the advisory skillset (skills + CATALOG operators)")
    p.add_argument("--query", default="", help="match skills by id/name/desc and operators by technique ref")
    p.add_argument("--skills-dir", default="", dest="skills_dir")
    p.set_defaults(fn=_skills)

    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
