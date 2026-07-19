"""SCHOLAR (SIGIL §4.5) — research & analysis: long-horizon research, sourced synthesis. Ceiling
A1 (research never touches external state). Its focus is EPISTEMICS: every claim carries a
source and a verbatim quote, confidence is explicit, and a claim that does NOT verify against its
cited source is DEMOTED (not asserted) — the same serve-the-quote gate that governs the
consolidation, reused here. The output is a `report` record grounded in real sources, so future
recall of the research is cited and honest, not confident. The synthesizer is pluggable
(`ClaudeSynthesizer` via `claude -p`, or a deterministic double)."""
from __future__ import annotations

import json
import logging
import re
import subprocess
from typing import Dict, List, Optional, Protocol, runtime_checkable

from ..config import claude_bin as _resolve_claude_bin
from ..consolidate.gate import salient   # reuse the veracity tokenizer
from .base import Agent, AgentResult, Proposal, Tier
from .sources import read_source

_log = logging.getLogger(__name__)
_WS = re.compile(r"\s+")
_MIN_QUOTE_SALIENT = 2


def _norm(t: str) -> str:
    return _WS.sub(" ", (t or "")).strip().lower()


def grounds_in_source(quote: str, source_text: str) -> bool:
    """A claim's quote must be verbatim in the cited source AND specific (≥2 salient tokens) —
    exactly the serve-the-quote discipline, applied to research sources."""
    q = _norm(quote)
    if not q or len(salient(quote)) < _MIN_QUOTE_SALIENT:
        return False
    return q in _norm(source_text)


@runtime_checkable
class Synthesizer(Protocol):
    def synthesize(self, question: str, docs: Dict[str, str]) -> List[dict]: ...  # [{claim,source,quote,confidence}]


class ClaudeSynthesizer:
    """`claude -p` over the sources → JSON claims, each citing a source ref + a verbatim quote."""
    def __init__(self, claude_bin: str | None = None,
                 model: str = "claude-haiku-4-5-20251001", timeout: int = 180):
        self.claude_bin = claude_bin or _resolve_claude_bin()
        self.model, self.timeout = model, timeout

    def synthesize(self, question: str, docs: Dict[str, str]) -> List[dict]:
        rendered = "\n\n".join(f"[SOURCE {ref}]\n{text[:4000]}" for ref, text in docs.items())
        prompt = (
            "You are a research analyst. Answer the QUESTION using ONLY the SOURCES. For every claim, "
            "cite the exact source ref and copy a VERBATIM quote from it that supports the claim; if a "
            "source does not support a claim, do not make it. If sources DISAGREE, report both. Return "
            'ONLY a JSON array: [{"claim":"...","source":"<ref>","quote":"<verbatim>","confidence":<0..1>}].'
            f"\n\nQUESTION: {question}\n\nSOURCES:\n{rendered}\n"
        )
        try:
            proc = subprocess.run([self.claude_bin, "-p", prompt, "--model", self.model],
                                  capture_output=True, text=True, timeout=self.timeout)
        except (subprocess.SubprocessError, OSError) as e:
            _log.warning("SCHOLAR synthesizer subprocess failed: %s", e)
            return []
        m = re.search(r"\[.*\]", proc.stdout, re.S)
        if not m:
            return []
        try:
            items = json.loads(m.group(0))
        except json.JSONDecodeError:
            return []
        out = []
        for it in items if isinstance(items, list) else []:
            if isinstance(it, dict) and it.get("claim") and it.get("source"):
                out.append({"claim": str(it["claim"]), "source": str(it["source"]),
                            "quote": str(it.get("quote", "")), "confidence": float(it.get("confidence", 0.5) or 0.5)})
        return out


def compose_report(question: str, graded: List[dict], sources: List[str]) -> str:
    grounded = [g for g in graded if g["grounded"]]
    lines = [f"# SCHOLAR research — {question}", "",
             f"Sources consulted: {len(sources)}. Claims: {len(graded)} "
             f"({len(grounded)} source-verified, {len(graded) - len(grounded)} unverified).", ""]
    if grounded:
        # SERVE THE QUOTE, not the model's claim: the authoritative content is the verbatim source
        # span (which is what actually verified). The model's claim is advisory ONLY — a fabricated
        # claim paired with a real quote must NOT be presented as a source-verified fact.
        lines.append("## Source-verified spans (the authoritative evidence, verbatim)")
        for g in sorted(grounded, key=lambda x: -x["confidence"]):
            lines.append(f"- \"{g['quote'][:200]}\"")
            lines.append(f"    — {g['source']}  ·  model's reading (ADVISORY, not verified): "
                         f"{g['claim'][:120]}  [{g['confidence']:.0%}]")
    ungrounded = [g for g in graded if not g["grounded"]]
    if ungrounded:
        lines.append("\n## Unverified (the model asserted these but no verbatim source span backs them — NOT relied upon)")
        for g in ungrounded:
            lines.append(f"- {g['claim'][:120]}  (claimed source {g['source']})")
    return "\n".join(lines)


class Scholar(Agent):
    name = "SCHOLAR"
    mandate = "sourced research; claims carry sources + confidence; disagreement reported, not averaged"
    ceiling = Tier.A1

    def run(self, question: str, sources: List[str], *, synthesizer: Optional[Synthesizer] = None) -> AgentResult:  # type: ignore[override]  # SIGIL agents take domain-specific run() inputs; base run is an abstract placeholder
        docs = {ref: read_source(ref) for ref in sources}
        claims = (synthesizer or ClaudeSynthesizer()).synthesize(question, docs)
        graded = [{**c, "grounded": grounds_in_source(c.get("quote", ""), docs.get(c["source"], ""))}
                  for c in claims]
        text = compose_report(question, graded, sources)
        g = sum(1 for x in graded if x["grounded"])
        res = self._dispatch([Proposal("report", {
            "subject": question, "text": text, "sources": sources,
            "claims": len(graded), "grounded": g}, Tier.A1)])
        res.notes.append(f"researched '{question[:50]}' over {len(sources)} source(s): "
                         f"{g}/{len(graded)} claims source-verified")
        return res
