"""
verify.reverify — independent, offline re-verification of a finding's certificate.

This mechanizes "prove-don't-guess". Every confirmed finding retains the exact
evidence the oracle adjudicated as a serialized `FindingContext` (its
`oracle_context`). Because the oracle functions are pure and deterministic, that
certificate can be re-checked by ANYONE, offline, with no target and no trust in
the tool that produced it: reconstruct the context, re-run the pure oracle, and
confirm the recomputed verdict reproduces the claim byte-for-byte.

A finding whose retained evidence no longer re-confirms — or re-confirms with a
different oracle/confidence than it claimed — is flagged as tampered or spurious.
Run in CI over an engagement's findings, this turns the whole system's output
into independently re-executable proofs.

    python3 -m framework.v2 verify <findings-or-report.json>

Exit 0 iff every finding's certificate reproduces (and matches its claim); 2 if
any does not.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from .adapter import FindingContext
from .confirmation import confirm_finding
from .verifier import OracleVerifier

_CLAIM_EPS = 1e-6


class ReverifyResult(BaseModel):
    """The verdict of re-running the pure oracle over one retained certificate."""

    model_config = ConfigDict(extra="forbid")

    finding_ref: str
    reproduced: bool                      # did the pure oracle re-fire over the retained evidence?
    confirmed_by: str | None = None
    confidence: float = 0.0
    matches_claim: bool | None = None     # None when the finding made no claim to compare against
    note: str = ""

    @property
    def ok(self) -> bool:
        """The certificate is sound: it re-confirms and matches whatever it claimed."""
        return self.reproduced and self.matches_claim is not False


def reverify_context(
    oracle_context: dict,
    *,
    bug_class: str,
    claimed_confirmed_by: str | None = None,
    claimed_confidence: float | None = None,
    ref: str = "finding",
    verifier: OracleVerifier | None = None,
) -> ReverifyResult:
    """Re-run the deterministic oracle over a retained FindingContext dict."""
    verifier = verifier or OracleVerifier()
    has_claim = claimed_confirmed_by is not None or claimed_confidence is not None

    try:
        ctx = FindingContext.model_validate(oracle_context)
    except Exception as e:
        return ReverifyResult(
            finding_ref=ref, reproduced=False,
            matches_claim=False if has_claim else None,
            note=f"unparseable oracle_context: {e}",
        )

    # BINDING: the retained evidence adjudicates its OWN bug_class. `confirm_finding`
    # re-derives the class from the context (the requested `bug_class` only fills in when
    # the context has none), so a caller asking to re-verify a DIFFERENT class than the
    # evidence proves would otherwise be silently re-fired under the evidence's own class —
    # letting a finding whose bug_class was flipped (e.g. sqli evidence relabelled 'rce')
    # re-confirm as the flipped class. Refuse the mismatch here, at the re-execution
    # boundary, so the requested class is actually load-bearing.
    evidence_class = str(ctx.to_verifier_context().get("bug_class") or "")
    if bug_class and evidence_class and bug_class != evidence_class:
        return ReverifyResult(
            finding_ref=ref, reproduced=False, matches_claim=False,
            note=f"requested bug_class {bug_class!r} does not match the evidence's own "
                 f"{evidence_class!r} — the retained proof adjudicates a different class",
        )

    confirmed = confirm_finding(
        finding={"bug_class": bug_class}, context=ctx, verifier=verifier,
    )
    if confirmed is None:
        return ReverifyResult(
            finding_ref=ref, reproduced=False,
            matches_claim=False if has_claim else None,
            note="retained evidence does NOT re-confirm (altered, or never confirmed)",
        )

    kind = confirmed.confirmed_by
    kind_str = getattr(kind, "value", None) or str(kind)
    matches: bool | None = None
    if has_claim:
        ok_kind = claimed_confirmed_by is None or str(claimed_confirmed_by) == kind_str
        ok_conf = claimed_confidence is None or abs(float(claimed_confidence) - confirmed.confidence) <= _CLAIM_EPS
        matches = ok_kind and ok_conf

    note = "re-confirmed from retained evidence"
    if matches is False:
        note += "; DIFFERS from the claimed certificate (tampered?)"
    return ReverifyResult(
        finding_ref=ref, reproduced=True, confirmed_by=kind_str,
        confidence=confirmed.confidence, matches_claim=matches, note=note,
    )


def reverify_finding(finding: dict, *, ref: str | None = None) -> ReverifyResult:
    """Re-verify one serialized finding (AuditFinding / ConfirmedFinding-shaped:
    a dict with `bug_class` + `oracle_context`, optionally a claimed
    `confirmed_by`/`confidence` to check for tampering)."""
    bug_class = str(finding.get("bug_class", ""))
    r = ref or str(finding.get("check_id") or finding.get("finding_slug") or bug_class or "finding")
    oc = finding.get("oracle_context")
    if not isinstance(oc, dict) or not oc:
        has_claim = bool(finding.get("confirmed_by") or finding.get("confidence"))
        return ReverifyResult(
            finding_ref=r, reproduced=False,
            matches_claim=False if has_claim else None,
            note="finding carries no oracle_context to re-verify",
        )
    return reverify_context(
        oc, bug_class=bug_class,
        claimed_confirmed_by=finding.get("confirmed_by"),
        claimed_confidence=finding.get("confidence"),
        ref=r,
    )


def reverify_document(doc: dict) -> list[ReverifyResult]:
    """Re-verify a serialized ScanReport (its `active_findings`) or a single
    finding document."""
    findings = doc.get("active_findings")
    if isinstance(findings, list):
        return [reverify_finding(f, ref=str(i)) for i, f in enumerate(findings)]
    return [reverify_finding(doc)]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m framework.v2 verify",
        description="Independently re-verify finding certificates offline (prove-don't-guess).",
    )
    parser.add_argument("path", help="A findings/report JSON file (a ScanReport or a single finding).")
    args = parser.parse_args(argv)

    p = Path(args.path)
    if not p.is_file():
        print(f"error: no file at {p}")
        return 2
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"error: cannot read {p}: {e}")
        return 2

    results = reverify_document(doc)
    ok = 0
    for r in results:
        mark = "OK " if r.ok else "BAD"
        claim = "" if r.matches_claim is None else (" matches-claim" if r.matches_claim else " CLAIM-MISMATCH")
        print(f"  [{mark}] {r.finding_ref}: {r.confirmed_by or '-'} conf={r.confidence:.3f}{claim} — {r.note}")
        ok += 1 if r.ok else 0
    total = len(results)
    print(f"re-verified {ok}/{total} certificate(s) reproduced" + (" and matched their claims" if ok == total else ""))
    return 0 if (total > 0 and ok == total) else 2
