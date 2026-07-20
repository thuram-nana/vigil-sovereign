"""ARCHIVIST (SIGIL §4.2) — memory: the world model. Ingest, consolidate, keep the graph true.
Ceiling A1 (deletion of source records is A3 and effectively never). Phase 3 formalizes the
Phase-0 consolidation as this agent: it runs the ARCHIVIST pass and emits a `finding` summarizing
what it promoted. The gate/veracity discipline lives in `sigil.consolidate` (already reviewed)."""
from __future__ import annotations

from typing import Optional

from .base import Agent, AgentResult, Proposal, Tier


class Archivist(Agent):
    name = "ARCHIVIST"
    mandate = "the world model: ingest, consolidate nightly, keep the graph true"
    ceiling = Tier.A1

    def run(self, provider=None, *, since_seq: Optional[int] = None, sign: bool = False) -> AgentResult:
        from ..consolidate import run_consolidation
        from ..consolidate.extract import HeuristicProvider
        rep = run_consolidation(provider or HeuristicProvider(), store=self.store,
                                since_seq=since_seq, sign=sign, save_cursor=False)
        summary = (f"consolidation: {rep.grounded} facts promoted, {rep.ungrounded} demoted, "
                   f"{rep.contradictions} contradictions, over {rep.records_fed} records")
        finding = {
            "summary": summary,
            "grounded": rep.grounded, "ungrounded": rep.ungrounded,
            "contradictions": rep.contradictions, "window": [rep.window_from, rep.window_to],
        }
        res = self._dispatch([Proposal("finding", finding, Tier.A1)])
        res.notes.append(summary)
        return res
