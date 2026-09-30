"""
agents.spine_certs — export a LIVE engage's oracle-confirmed FACTs off the ``.blackboard``
event spine as the SAME offline-re-verifiable certificate bundle the scanner/proof paths
produce.

A ``scan``/proof run writes ``reverifiable.json`` — the raw ScanReport dump whose
``active_findings`` each retain their deterministic ``oracle_context`` — and
``python3 -m framework.v2 verify`` re-runs the pure oracle over that retained evidence,
offline, with no target. A LIVE ``engage`` run, by contrast, mirrors its findings onto the
append-only blackboard spine as ``finding`` events (see ``engage._spine_finding_payload``);
those carry the same ``oracle_context`` / ``verified_by_oracle`` provenance but were, until
now, only readable AS spine rows — never emitted as the portable, re-verifiable bundle a
client or CI re-checks offline. This module closes that gap.

THE NON-LAUNDERING GATE (the whole point):

  * A spine ``finding`` event is exported into ``active_findings`` ONLY when it is a real
    per-engagement FACT: ``verified_by_oracle is True`` AND it retains a non-empty
    ``oracle_context``. A LEAD — a passive-hygiene finding, a demoted active
    (``verified_by_oracle False`` because its live grounding was not ``fact``), an
    ``llm_advisory`` verdict, anything without a certificate — is NEVER emitted as a fact.
    It may be listed in a SEPARATE ``leads`` section (explicitly not re-verifiable), so a
    demotion is not a disappearance, but it can never acquire a re-verifiable cert it did
    not earn.
  * The verifier remains the sole authority. The export CARRIES the producer's claim
    (``bug_class`` / ``confirmed_by`` / ``confidence``) verbatim; whether the fact is real
    is decided by ``framework.v2 verify`` re-firing the pure oracle over the retained
    ``oracle_context``. A tampered ``oracle_context`` — a flipped byte — does NOT reproduce
    and is rejected there, exactly as for a scanner cert. So even a spine that lied
    (``verified_by_oracle True`` over bogus evidence) cannot manufacture a passing cert.

DETERMINISM: rows are sorted by a stable identity (``finding_slug``, ``bug_class``,
``confirmed_by``), never by the volatile spine row id or post order, so two exports of the
same engagement's current view are byte-identical.

ADDITIVE: nothing on the default ``engage``/``scan``/``benchmark`` path imports this module;
it is invoked explicitly (``python3 -m framework.v2 spine-cert <slug>``) or programmatically.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from ..common import logging as v2log
from .blackboard import Blackboard, open_blackboard

_log = v2log.get_logger(__name__)

# The bundle schema — distinct from the scanner's raw ScanReport dump so a consumer can tell
# a spine-sourced cert bundle from a scan-sourced one, while both re-verify through the
# IDENTICAL ``verify.reverify.reverify_document`` path (both key their findings under
# ``active_findings``).
SPINE_CERT_SCHEMA = "vigil-spine-reverifiable/1"


def _is_fact_finding(payload: dict[str, Any]) -> bool:
    """A spine ``finding`` payload is an oracle-confirmed FACT — eligible to be exported as a
    re-verifiable cert — ONLY when the engagement itself recorded it as one: an oracle fired
    (``verified_by_oracle``) AND a certificate was retained (a non-empty ``oracle_context``).

    This is the anti-laundering gate. It keys on the RECORDED per-engagement verdict, not on
    the mere presence of a certificate: a demoted active finding retains its ``oracle_context``
    but carries ``verified_by_oracle=False`` (its live grounding was not ``fact``), and it must
    stay a LEAD in the export — never re-promoted just because a byte-blob is attached."""
    if not isinstance(payload, dict):
        return False
    if not payload.get("verified_by_oracle"):
        return False
    oc = payload.get("oracle_context")
    return isinstance(oc, dict) and bool(oc)


def spine_finding_to_reverifiable(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Map ONE spine ``FindingPayload`` dict to an ``AuditFinding``-shaped finding the
    re-verifier consumes, or ``None`` when the payload is not an oracle-confirmed FACT.

    The field mapping bridges the two vocabularies: the spine finding names the oracle that
    fired ``oracle_kind`` (mirrored from ``AuditFinding.confirmed_by``), while the re-verifier
    checks a finding's ``confirmed_by`` claim against what the oracle re-derives. Everything
    else (``bug_class`` for the binding check, ``confidence`` for the claim, ``oracle_context``
    for the re-execution, ``finding_slug`` as the reference) carries straight across."""
    if not _is_fact_finding(payload):
        return None
    return {
        # the reference the re-verifier prints and keys tamper detection on
        "check_id": str(payload.get("finding_slug") or payload.get("bug_class") or "finding"),
        "finding_slug": str(payload.get("finding_slug") or ""),
        "bug_class": str(payload.get("bug_class") or ""),
        # the CLAIM the re-verifier checks for tampering (spine names it oracle_kind)
        "confirmed_by": payload.get("oracle_kind"),
        "confidence": payload.get("confidence"),
        # the retained certificate the pure oracle re-fires over
        "oracle_context": payload.get("oracle_context"),
    }


def _lead_row(payload: dict[str, Any]) -> dict[str, Any]:
    """A minimal, EXPLICITLY-not-re-verifiable summary of a spine finding that is a LEAD, so a
    demotion is a disclosure rather than a silent drop. Carries NO ``oracle_context`` (a lead
    has no cert to re-run) — a consumer cannot mistake it for a fact."""
    return {
        "finding_slug": str(payload.get("finding_slug") or ""),
        "bug_class": str(payload.get("bug_class") or ""),
        "title": str(payload.get("title") or ""),
        "severity": str(payload.get("severity") or ""),
        "verified_by_oracle": bool(payload.get("verified_by_oracle")),
        "has_oracle_context": isinstance(payload.get("oracle_context"), dict)
        and bool(payload.get("oracle_context")),
        "critique_status": str(payload.get("critique_status") or ""),
    }


def export_reverifiable_from_spine(
    bb: Blackboard,
    engagement: str | int,
    *,
    include_leads: bool = True,
) -> dict[str, Any]:
    """Build the offline-re-verifiable cert bundle for one engagement's CURRENT spine view.

    Reads the append-only spine's ``finding`` events (superseded rows excluded, so the bundle
    reflects the current view), promotes each oracle-confirmed FACT into ``active_findings``
    (the key ``verify.reverify`` re-runs), and — when ``include_leads`` — lists the rest under
    ``leads`` as explicitly not-re-verifiable. Read-only over the spine; deterministic bytes.

    The returned document is consumable by ``framework.v2 verify`` exactly like a scanner's
    ``reverifiable.json``: every fact carries its retained ``oracle_context``, and a tampered
    context is rejected by the re-verifier."""
    slug = engagement if isinstance(engagement, str) else str(engagement)
    rows = bb.replay(engagement=engagement, kinds=["finding"])

    facts: list[dict[str, Any]] = []
    leads: list[dict[str, Any]] = []
    for r in rows:
        payload = r.payload if isinstance(r.payload, dict) else {}
        finding = spine_finding_to_reverifiable(payload)
        if finding is not None:
            facts.append(finding)
        elif include_leads:
            leads.append(_lead_row(payload))

    # Stable identity sort — NEVER the volatile spine row id / post order — so two exports of
    # the same current view are byte-identical.
    facts.sort(key=lambda f: (f.get("finding_slug") or "", f.get("bug_class") or "",
                              str(f.get("confirmed_by") or ""), f.get("check_id") or ""))
    leads.sort(key=lambda f: (f.get("finding_slug") or "", f.get("bug_class") or ""))

    doc: dict[str, Any] = {
        "schema": SPINE_CERT_SCHEMA,
        "tool": "CRUCIBLE",
        "source": "spine",
        "engagement": slug,
        # the re-verifier's key — identical to a scanner ScanReport dump, so the SAME
        # `verify` path re-runs it with no special-casing.
        "active_findings": facts,
    }
    if include_leads:
        doc["leads"] = leads
    return doc


def write_reverifiable_from_spine(
    bb: Blackboard,
    engagement: str | int,
    path: str | Path,
    *,
    include_leads: bool = True,
    indent: int | None = 2,
) -> Path:
    """Write the bundle to ``path`` as deterministic JSON (owner-only via the process umask).
    Returns the path written."""
    doc = export_reverifiable_from_spine(bb, engagement, include_leads=include_leads)
    p = Path(path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(doc, indent=indent, sort_keys=True, ensure_ascii=False),
                 encoding="utf-8")
    return p


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m framework.v2 spine-cert",
        description=(
            "Export a live engage's oracle-confirmed FACTs off the .blackboard spine as an "
            "offline-re-verifiable certificate bundle (the same shape `verify` re-runs). "
            "LEADs are listed separately and never emitted as re-verifiable facts."),
    )
    parser.add_argument("engagement", help="The engagement slug whose spine facts to export.")
    parser.add_argument("--out", metavar="PATH", default=None,
                        help="Write the bundle here (JSON). Default: stdout.")
    parser.add_argument("--no-leads", action="store_true",
                        help="Omit the (non-re-verifiable) leads section.")
    parser.add_argument("--db", metavar="PATH", default=None,
                        help="Blackboard store path (default: the framework's .blackboard store).")
    args = parser.parse_args(argv)

    db_path = Path(args.db) if args.db else None
    bb = open_blackboard(db_path=db_path)
    try:
        try:
            bb.engagement_id(args.engagement, create=False)
        except Exception:
            print(f"error: no engagement {args.engagement!r} on the spine", file=sys.stderr)
            return 2
        if args.out:
            p = write_reverifiable_from_spine(
                bb, args.engagement, args.out, include_leads=not args.no_leads)
            doc = export_reverifiable_from_spine(
                bb, args.engagement, include_leads=not args.no_leads)
            print(f"wrote {len(doc['active_findings'])} re-verifiable fact(s) to {p}")
            print(f"re-verify offline with: python3 -m framework.v2 verify {p}")
        else:
            doc = export_reverifiable_from_spine(
                bb, args.engagement, include_leads=not args.no_leads)
            print(json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False))
    finally:
        bb.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
