"""WebResearcher (Phase 8, WS-E E-iv/v) — the grounded research orchestrator, a SCHOLAR subclass
(name="SCHOLAR", ceiling A1, so budgets/kill/mesh wiring apply unchanged). `research_web`: crawl
PUBLIC sources via the scope-gated VOI Frontier → persist each fetched page as a cited `web_page`
spine record (the seqs become the `window_seqs`) → synthesize claims (each citing a page seq + a
verbatim quote) → pass EVERY claim through the identical demote-only `consolidate.gate.admit` (re-fetch
the cited record, ground the verbatim quote, reject citations outside the fetched window) → compose a
cited `report` whose served content is the BYTE-VERBATIM span (the model's paraphrase is advisory).
Scraped knowledge becomes tamper-evident, provenance-linked, recallable memory — never a fabrication."""
from __future__ import annotations

from typing import List, Optional

from ..agents.base import Proposal, Tier
from ..agents.scholar import Scholar
from ..consolidate.gate import admit
from ..consolidate.models import CandidateFact
from .frontier import Frontier
from .scope import ScrapeScope


class WebResearcher(Scholar):
    def _persist_page(self, page) -> int:
        return self.store.append(kind="web_page", source="web", actor=self.name, payload={
            "url": page.url, "http_status": page.status, "content_hash": page.content_hash,
            "robots_allowed": True, "depth": page.depth,
            "text": page.text[:20000],        # EXACTLY what the synthesizer sees == what the gate re-checks
        })

    def research_web(self, question: str, seeds: List[str], scope: ScrapeScope, *,
                     synthesizer=None, frontier: Optional[Frontier] = None):
        fr = frontier or Frontier(scope)
        pages = fr.crawl(question, seeds)
        seq_by_url = {p.url: self._persist_page(p) for p in pages}
        window = set(seq_by_url.values())

        docs = {str(seq_by_url[p.url]): p.text[:20000] for p in pages}
        claims = (synthesizer or self._default_synth()).synthesize(question, docs)

        grounded, advisory = [], []
        for c in claims:
            try:
                seq = int(c.get("source"))
            except (TypeError, ValueError):
                advisory.append({"claim": c.get("claim", ""), "reason": "citation not a page seq"})
                continue
            cand = CandidateFact(kind="web_claim", subject=(c.get("claim", "")[:60] or "claim"),
                                 statement=str(c.get("claim", "")), quote=str(c.get("quote", "")),
                                 source_seqs=[seq], model_confidence=float(c.get("confidence", 0.5) or 0.5),
                                 extractor="web")
            v = admit(cand, window, self.store)
            if v.grounded:
                grounded.append({"span": v.text, "seqs": v.verified_seqs,
                                 "url": next((u for u, s in seq_by_url.items() if s in v.verified_seqs), "")})
            else:
                advisory.append({"claim": str(c.get("claim", "")), "reason": v.reason})

        text = self._compose(question, grounded, advisory, pages, fr.skips)
        res = self._dispatch([Proposal("report", {
            "signal": "web.research", "subject": question, "text": text,
            "pages_fetched": len(pages), "grounded": len(grounded), "advisory": len(advisory),
            "skipped": len(fr.skips), "source": "web",
        }, Tier.A1)])
        res.notes.append(f"web-researched '{question[:50]}': {len(pages)} page(s), "
                         f"{len(grounded)} grounded / {len(advisory)} advisory, {len(fr.skips)} skipped")
        return res

    def _default_synth(self):
        from ..agents.scholar import ClaudeSynthesizer
        return ClaudeSynthesizer()

    @staticmethod
    def _compose(question, grounded, advisory, pages, skips) -> str:
        lines = [f"# SCRIBE web research — {question}", "",
                 f"Pages fetched: {len(pages)}. Grounded claims: {len(grounded)}. "
                 f"Advisory (ungrounded): {len(advisory)}. Skipped: {len(skips)}.", ""]
        if grounded:
            lines.append("## Grounded (verbatim source span · the authoritative evidence)")
            for g in grounded:
                lines.append(f"- \"{g['span'][:240]}\"")
                lines.append(f"    — cites spine seq(s) {g['seqs']}  ·  {g['url']}")
        if advisory:
            lines.append("\n## Advisory (the model asserted these but NO verbatim page span backs them — NOT relied upon)")
            for a in advisory:
                lines.append(f"- {a['claim'][:120]}  ({a['reason']})")
        if skips:
            lines.append(f"\n## Skipped ({len(skips)}) — robots/scope/cap/error, honestly recorded")
            for url, why in skips[:12]:
                lines.append(f"- [{why}] {url}")
        return "\n".join(lines)
