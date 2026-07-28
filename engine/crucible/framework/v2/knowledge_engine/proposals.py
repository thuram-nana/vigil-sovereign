"""
knowledge_engine.proposals — the deterministic "propose-to-learn" drafter (K2).

Given the K1 VULNERABILITY leads for an engagement, rank them into a propose queue: known-exploited
first, then higher severity / CVSS, then id (stable). This is PURE and READ-ONLY:

  * a proposal AUTHORIZES NOTHING — it is a ranked suggestion the owner may ACCEPT. Acceptance (K2b,
    owner-signed) authorizes LEARNING (K3), never fact-minting.
  * the underlying leads stay intel-tier; drafting never promotes a lead, mints a fact, fires an oracle,
    or touches the graph/gate.
  * deterministic ordering (no wallclock/rng) so the same leads always draft the same queue.
"""

from __future__ import annotations

from dataclasses import dataclass

# severity string → rank (higher = more urgent); anything unknown sorts last.
_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _sev_rank(sev) -> int:
    return _SEV_ORDER.get(str(sev or "").strip().lower(), 0)


@dataclass(frozen=True)
class LearnProposal:
    """One ranked suggestion to deep-learn a vulnerability. ``status`` is always ``"proposed"`` here —
    it becomes owner-authorized only through the sovereign ACCEPT (K2b), never in this module."""

    vuln_id: str
    rank: int
    exploit_known: bool
    severity: str
    cvss: float | None
    rationale: str
    status: str = "proposed"

    def to_dict(self) -> dict:
        return {"vuln_id": self.vuln_id, "rank": self.rank, "exploit_known": self.exploit_known,
                "severity": self.severity, "cvss": self.cvss, "rationale": self.rationale,
                "status": self.status}


def draft_proposals(vuln_leads, *, limit: int = 50) -> list[LearnProposal]:
    """Rank VULNERABILITY leads (``vulnintel_data``-shaped dicts) into a deterministic propose queue.

    Order: known-exploited first, then higher severity, then higher CVSS, then id (stable tiebreak). A
    lead with no id is skipped. Read-only; returns at most ``limit`` proposals. Nothing is minted or
    promoted — every returned proposal is ``status="proposed"`` until the owner accepts it.
    """
    leads = [v for v in vuln_leads if str(v.get("id") or "").strip()]
    ranked = sorted(
        leads,
        key=lambda v: (
            0 if v.get("exploit_known") else 1,       # known-exploited first
            -_sev_rank(v.get("severity")),            # higher severity first
            -(v.get("cvss") or 0.0),                  # higher CVSS first
            str(v.get("id")),                         # stable, deterministic tiebreak
        ),
    )
    out: list[LearnProposal] = []
    for i, v in enumerate(ranked[: max(0, int(limit))], start=1):
        ek = bool(v.get("exploit_known"))
        sev = str(v.get("severity") or "")
        parts = []
        if ek:
            parts.append("known-exploited (CISA KEV)")
        if sev:
            parts.append(f"severity {sev}")
        parts.append("propose deep-learn (find/detect/prevent) — advisory, owner-gated")
        out.append(LearnProposal(vuln_id=str(v.get("id")), rank=i, exploit_known=ek, severity=sev,
                                 cvss=v.get("cvss"), rationale="; ".join(parts)))
    return out
