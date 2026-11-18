"""retest_reproof — the customer RETEST live re-proof WIRE CONTRACT shared across the two planes (C1b).

The sovereign provisioner (``sigil.ui.provision.retest``) reserves an owner-signed ``CreditLaunchLease`` for
one finding's re-verification and publishes a small JSON re-proof TICKET to a dedicated ``retest-reproof`` seam
directory; the keyless offense trigger (``vigil_integration.jobs.retest_reproof``) reads it, re-fires THAT
finding's proof against the org's verified host under the lease, and writes an inert OUTCOME to the
``retest-outcomes`` seam. The sovereign consumes the outcome to drive its existing verdict mapping (fixed /
still-vulnerable / refused). Both planes agree on the field names + verdict values HERE, so the contract has a
single source of truth and cannot drift. Pure stdlib — no framework / no I/O / no keys; importable in either venv.

The ticket is an UNTRUSTED trigger: its AUTHORITY is the owner-signed ``lease`` it carries. The keyless offense
worker re-verifies that lease owner-pinned and binds it to the org's VERIFIED authority host/tenant/window
BEFORE any traffic, so a forged ticket (a wrong host, another tenant's finding) sends nothing. The outcome is
likewise inert: the sovereign re-checks its identity (slug / finding_ref / digest / nonce) matches the ticket it
issued and only EVER marks a finding fixed on the exact token :data:`CLEARED`.
"""
from __future__ import annotations

from typing import Any

#: The seam sub-directory the re-proof tickets live in (sovereign -> offense). SEPARATE from the launch
#: credit-launch-lease seam (so a retest lease never clobbers an in-flight launch's lease for the same slug)
#: and from the redpen-actions seam.
RETEST_REPROOF_SEAM_SUBDIR = "retest-reproof"
#: The seam sub-directory the inert outcomes come back on (offense -> sovereign).
RETEST_OUTCOME_SEAM_SUBDIR = "retest-outcomes"

#: The four verdict tokens an outcome may carry. Only :data:`CLEARED` ever marks a finding fixed, and it is
#: earned ONLY by a DECISIVE re-fire (the proof completed every required run and never fired — R5
#: ``refire_reproduction`` positive evidence). Silence / timeout / an unavailable sandbox / no re-fireable proof
#: are :data:`INCONCLUSIVE`; a lease that will not verify is :data:`UNAVAILABLE`. Neither is ever read as a fix.
CLEARED = "cleared"
STILL_PRESENT = "still_present"
INCONCLUSIVE = "inconclusive"
UNAVAILABLE = "unavailable"
_VERDICTS = (CLEARED, STILL_PRESENT, INCONCLUSIVE, UNAVAILABLE)


def retest_reproof_ticket(*, slug: str, host: str, org_id: str, finding_ref: str, nonce: str,
                          lease: Any, oracle_context_digest: str = "", bug_class: str = "",
                          repo: str = "") -> dict:
    """Build a validated re-proof ticket dict (the published seam payload). Fail-closed ``ValueError`` on an
    empty slug / host / org_id / finding_ref / nonce, or a missing owner-signed ``lease`` (the ticket's whole
    authority). ``lease`` is the ``SignedCreditLaunchLease`` as a JSON dict (exactly what
    ``LaunchGate.reserve_retest`` returns). ``repo`` is an inert carrier for the ``SecurityJob`` (defaults to the
    host). The finding identity (``slug`` + ``finding_ref`` + ``oracle_context_digest``) names the ONE proof the
    offense worker re-fires; the digest may be "" (both sides agree on "")."""
    s, h, o, ref, n = (str(slug or ""), str(host or ""), str(org_id or ""), str(finding_ref or ""), str(nonce or ""))
    if not s or not h or not o or not ref or not n:
        raise ValueError("a retest re-proof ticket requires a non-empty slug, host, org_id, finding_ref and nonce")
    if not isinstance(lease, dict) or not lease:
        raise ValueError("a retest re-proof ticket requires the owner-signed lease (its authority)")
    return {
        "slug": s, "host": h, "org_id": o, "finding_ref": ref, "nonce": n,
        "oracle_context_digest": str(oracle_context_digest or ""), "bug_class": str(bug_class or ""),
        "repo": str(repo or "") or h, "lease": lease,
    }


def retest_reproof_outcome(*, slug: str, finding_ref: str, nonce: str, verdict: str,
                           oracle_context_digest: str = "", reason: str = "", consumed_mc: int = 0) -> dict:
    """Build a validated re-proof outcome dict (the inert result the offense worker writes). Fail-closed
    ``ValueError`` on an empty slug / finding_ref / nonce or an unknown verdict (must be one of
    :data:`CLEARED` / :data:`STILL_PRESENT` / :data:`INCONCLUSIVE` / :data:`UNAVAILABLE`). ``consumed_mc`` is the
    metered model use in milli-credits (0 for a deterministic, model-free re-fire). Carries NO amount, price or
    model name — the sovereign never shows it; it is advisory and money-doctrine clean."""
    s, ref, n = (str(slug or ""), str(finding_ref or ""), str(nonce or ""))
    if not s or not ref or not n:
        raise ValueError("a retest re-proof outcome requires a non-empty slug, finding_ref and nonce")
    v = str(verdict or "")
    if v not in _VERDICTS:
        raise ValueError(f"retest verdict must be one of {_VERDICTS}")
    try:
        mc = int(consumed_mc)
    except (TypeError, ValueError):
        mc = 0
    return {
        "slug": s, "finding_ref": ref, "nonce": n, "verdict": v,
        "oracle_context_digest": str(oracle_context_digest or ""), "reason": str(reason or ""),
        "consumed_mc": max(0, mc),
    }


def ticket_identity(ticket: "dict[str, Any]") -> "tuple[str, str, str, str]":
    """The identity a ticket/outcome is correlated by: ``(slug, finding_ref, oracle_context_digest, nonce)``.
    Total — a non-dict or missing field reads as "" (so a malformed record never matches a real one)."""
    t = ticket if isinstance(ticket, dict) else {}
    return (str(t.get("slug") or ""), str(t.get("finding_ref") or ""),
            str(t.get("oracle_context_digest") or ""), str(t.get("nonce") or ""))


__all__ = [
    "RETEST_REPROOF_SEAM_SUBDIR", "RETEST_OUTCOME_SEAM_SUBDIR",
    "CLEARED", "STILL_PRESENT", "INCONCLUSIVE", "UNAVAILABLE",
    "retest_reproof_ticket", "retest_reproof_outcome", "ticket_identity",
]
