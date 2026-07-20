"""The veracity gate — SIGIL's demote-only admission choke point (ported from
veracity/firewall.py's re-execute-don't-string-trust discipline).

The gate grounds the QUOTE, and the quote — the verbatim record span — is what becomes the
served fact. The model's free-text `statement` is NEVER the authoritative content (a
red-team re-check proved a token-subset check over the statement is not entailment: an
extractor can drop a negation or reorder words to invert meaning while staying a token
subset). By certifying and serving the verbatim quote instead, a fabricated or inverted
statement can never be presented as a grounded fact — the owner only ever sees their own words.

A candidate GROUNDS iff:
  1. it cites ≥1 seq, every cited seq is inside the exact window fed to the extractor;
  2. its `quote` is verbatim in ≥1 cited record re-fetched from the spine (never the model's copy);
  3. the quote is SPECIFIC — it carries ≥2 salient (non-stopword) tokens, Unicode-aware, so a
     trivial common substring grounds nothing.

The gate can only ever DEMOTE; the model's confidence never enters. Anything that fails is
recorded honestly as commentary, never as a fact and never dropped."""
from __future__ import annotations

import re

from ..spine.store import SpineStore
from .grounding import UNGROUNDED, ground_tag
from .models import CandidateFact, GateVerdict

_WS = re.compile(r"\s+")
# Unicode-aware: a token starts with a word char (letter/digit, any script) and may carry
# internal separators (dates 2026-07-20, versions v1.2, paths a/b). \w is Unicode by default.
_TOKEN = re.compile(r"[^\W_][\w'./-]*", re.UNICODE)

_STOPWORDS = frozenset({
    "the", "and", "for", "with", "that", "this", "have", "has", "had", "was", "were", "are",
    "will", "would", "should", "could", "can", "but", "you", "your", "our", "their",
    "from", "into", "out", "about", "then", "than", "them", "they", "there", "here",
    "what", "when", "where", "which", "who", "how", "all", "any", "some", "get", "got", "let",
    "let's", "lets", "actually", "just", "now", "today", "yesterday", "tomorrow", "really",
    "very", "more", "most", "much", "many", "also", "like", "want", "need", "going", "gonna",
})

MIN_QUOTE_SALIENT = 2      # a quote below this is too trivial to ground a claim


def _norm(text: str) -> str:
    return _WS.sub(" ", (text or "")).strip().lower()


def salient(text: str) -> set[str]:
    """Unicode-aware salient tokens: ≥3 chars, not a stopword, punctuation-trimmed."""
    out: set[str] = set()
    for t in _TOKEN.findall((text or "").casefold()):
        t = t.strip("._/-'")
        if len(t) >= 3 and t not in _STOPWORDS:
            out.add(t)
    return out


def _real_span(quote: str, record_text: str) -> str | None:
    """Return the BYTE-verbatim span of `record_text` that `quote` matches (tolerant of
    whitespace/case differences in the model's copy), so the SERVED fact is the record's own
    bytes, not the model's transcription. None if not found."""
    words = quote.split()
    if not words:
        return None
    pat = r"\s+".join(re.escape(w) for w in words)
    m = re.search(pat, record_text, re.IGNORECASE)
    return m.group(0) if m else None


def admit(cand: CandidateFact, window_seqs: set[int], store: SpineStore) -> GateVerdict:
    """Re-execute the candidate's citation(s) and ground the VERBATIM QUOTE(s). A contradiction
    must verify ≥2 DISTINCT records (evidence from both sides); every other kind needs ≥1. The
    served `text` is the record's own byte-verbatim span(s). Any failure → UNGROUNDED."""
    if not cand.source_seqs:
        return GateVerdict(False, UNGROUNDED, [], "cites no source records — cannot ground")

    outside = sorted({s for s in cand.source_seqs if s not in window_seqs})
    if outside:
        return GateVerdict(False, UNGROUNDED, [],
                           f"cites seq(s) outside the fed window {outside} — fabricated citation")

    quotes = [q for q in (cand.quotes or (cand.quote,)) if q and q.strip()]
    if not quotes:
        return GateVerdict(False, UNGROUNDED, [], "no quote to verify")

    verified: set[int] = set()
    spans: list[str] = []
    for qq in quotes:
        if len(salient(qq)) < MIN_QUOTE_SALIENT:
            continue                                          # a trivial quote grounds nothing
        qn = _norm(qq)
        for s in cand.source_seqs:
            rec = store.get(s)
            if rec is not None and s not in verified and qn in _norm(rec.text()):
                verified.add(s)
                spans.append(_real_span(qq, rec.text()) or qq)
                break
    if not verified:
        return GateVerdict(False, UNGROUNDED, [],
                           "no quote is verbatim-and-specific in any cited record — fabricated/trivial quote")

    need = 2 if cand.kind == "contradiction" else 1
    if len(verified) < need:
        return GateVerdict(False, UNGROUNDED, [],
                           f"a {cand.kind} needs ≥{need} distinct records to verbatim-verify — only {len(verified)} did")

    vs = sorted(verified)
    return GateVerdict(True, ground_tag(min(vs)), vs,
                       f"grounded: {len(vs)} verbatim record span(s) at seq(s) {vs}",
                       text=" || ".join(spans))
