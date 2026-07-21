"""
kb.corpus — the governed offensive-corpus RAG (VIGIL-FUSION F12).

A reimplementation of redamon's ``tradecraft_lookup`` (MIT; the curated HackTricks /
PayloadsAllTheThings / CVE-PoC KB exposed as an ``@tool``) as a pure, sovereign retrieval helper. The
port keeps redamon's cost-bounded ranking — a deterministic lexical score (``_jaccard`` +
``0.5 * _substr_overlap``) with an LLM tiebreak spent ONLY on a genuinely ambiguous query (redamon:
``> 5`` candidates AND top score ``< 0.6``) — and inverts every trust assumption:

  * **KB content is a prompt-injection channel.** Every returned section is a page redamon crawled
    from a hostile-controllable source, so EVERY result's body is wrapped in the F1 ``[UNTRUSTED]``
    nonce envelope (``safety.prompt_safety.wrap_untrusted``) before it can reach a Claude prompt. The
    public :class:`LookupResult` has NO raw-content field at all — the only content-bearing attribute
    is the already-framed ``untrusted`` block, so a caller cannot structurally leak raw KB text.
  * **Advisory, never authoritative.** A section read from the corpus is retrieval CONTEXT, never a
    fact and never an authorization. A technique read here still needs the deterministic oracle to
    confirm any resulting finding — nothing in this module promotes anything to a fact or a tier.
  * **Injected, offline.** The corpus source and the LLM tiebreak are INJECTED (the live two-tier
    crawl / SSRF-guarded fetch is deferred); the module runs fully offline over a provided static
    corpus, so it is testable without a network or a live model. The tiebreak may only SELECT among
    already-ranked candidates — it can never inject content or change a score.
  * **Total on malformed input.** Query, resource filter and every corpus entry are attacker- or
    LLM-influenceable; each degrades to "no signal" (an empty result), never a raise.

Determinism note: the ranking DECISION (scores + order + the selected section) is a pure function of
the query and the corpus and touches neither wallclock nor RNG. The ``[UNTRUSTED]`` envelope's
per-call random nonce (from F1) is a presentation boundary applied AFTER selection — it is neither a
spine write nor a decision input, and is exactly the unforgeable-boundary property F1 requires.

Import-clean: pydantic/stdlib + ``safety.prompt_safety`` only (no framework/strix/network).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Optional

from ..safety.prompt_safety import wrap_untrusted, wrap_untrusted_inline

# Ranking / cost-bound constants (mirroring redamon's tradecraft_lookup).
DEFAULT_TOP_K = 5
AMBIGUITY_MIN_CANDIDATES = 5      # redamon: an LLM tiebreak fires only with > 5 candidate sections …
AMBIGUITY_SCORE_CEILING = 0.6     # … AND a top lexical score below 0.6 (otherwise the lexical top wins)
TIEBREAK_POOL = 8                 # how many top candidates the injected tiebreak may choose among
UNTRUSTED_LABEL = "TRADECRAFT"    # the [UNTRUSTED] envelope label for KB sections

_TOKEN_RE = re.compile(r"[a-z0-9]+")


# ---------------------------------------------------------------------------------------------------
# corpus entries (injected, static) — total coercion so a malformed entry is dropped, never fatal
# ---------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class CorpusEntry:
    """One retrievable section of the provided static corpus. ``resource_id`` and ``section_path`` are
    operator/curator structural identifiers (a reference, like a URL); ``title``/``content`` are the
    attacker-controllable body that is NEVER exposed raw — only inside a wrapped :class:`LookupResult`."""

    resource_id: str
    section_path: str
    title: str
    content: str


def _s(v: Any) -> str:
    """Coerce any value to a plain string, totally (``None`` → ``""``)."""
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    try:
        return str(v)
    except Exception:  # noqa: BLE001 — a pathological __str__ must not crash retrieval
        return ""


def _coerce_entry(obj: Any) -> Optional[CorpusEntry]:
    """Turn a provided corpus item (dict or attribute-bearing object) into a :class:`CorpusEntry`,
    fail-soft. Returns ``None`` for anything unusable so a poisoned entry is dropped, not raised."""
    if isinstance(obj, CorpusEntry):
        return obj
    get: Callable[[str], Any]
    if isinstance(obj, dict):
        get = obj.get
    elif obj is not None and any(hasattr(obj, k) for k in ("content", "body", "text", "section_path")):
        get = lambda k: getattr(obj, k, None)  # noqa: E731 — tiny accessor, clearer inline
    else:
        return None
    resource_id = _s(get("resource_id") or get("resource") or get("source"))
    section_path = _s(get("section_path") or get("path") or get("id") or get("url"))
    title = _s(get("title") or get("name") or get("heading"))
    content = _s(get("content") or get("body") or get("text"))
    if not (title or content or section_path):
        return None  # nothing to retrieve → no signal
    return CorpusEntry(resource_id=resource_id, section_path=section_path, title=title, content=content)


def _iter_corpus(corpus: Any) -> list[CorpusEntry]:
    """Materialise an injected corpus (a list/iterable of items, or a zero-arg callable returning one)
    into coerced entries, totally. A callable that raises, or a non-iterable corpus, yields ``[]``."""
    src = corpus
    if callable(corpus):
        try:
            src = corpus()
        except Exception:  # noqa: BLE001 — an injected source error is "no corpus", never a crash
            return []
    if isinstance(src, (str, bytes, dict)) or src is None:
        return []
    try:
        items = list(src)
    except Exception:  # noqa: BLE001
        return []
    out: list[CorpusEntry] = []
    for item in items:
        # _coerce_entry probes attacker-influenceable items (hasattr / .get / truthiness), so an exotic
        # item — a property/`.get`/`__bool__` that raises a non-AttributeError — must be dropped here,
        # never propagated. This is the class-level totality guard for the whole coercion path.
        try:
            entry = _coerce_entry(item)
        except Exception:  # noqa: BLE001 — a poisoned/exotic corpus item is "no signal", never a crash
            continue
        if entry is not None:
            out.append(entry)
    return out


# ---------------------------------------------------------------------------------------------------
# deterministic lexical ranking (pure — no wallclock, no RNG)
# ---------------------------------------------------------------------------------------------------


def _tokens(s: Any) -> set[str]:
    if not isinstance(s, str):
        s = _s(s)
    return set(_TOKEN_RE.findall(s.lower()))


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    union = len(a | b)
    return (len(a & b) / union) if union else 0.0


def _substr_overlap_score(query: str, text: str) -> float:
    """Fraction of the query's distinct tokens that occur as substrings of ``text`` — cheap recall
    that rewards partial/embedded matches the token-set jaccard misses."""
    q = _tokens(query)
    if not q:
        return 0.0
    tl = text.lower() if isinstance(text, str) else _s(text).lower()
    return sum(1 for t in q if t in tl) / len(q)


def _entry_text(e: CorpusEntry) -> str:
    return f"{e.title}\n{e.section_path}\n{e.content}"


def _rank_score(query: str, e: CorpusEntry) -> float:
    """redamon's ``_jaccard + 0.5 * _substr_overlap_score`` — deterministic, bounded, no model call."""
    text = _entry_text(e)
    return _jaccard(_tokens(query), _tokens(text)) + 0.5 * _substr_overlap_score(query, text)


# ---------------------------------------------------------------------------------------------------
# results — the ONLY content-bearing field is the [UNTRUSTED]-framed block
# ---------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class LookupResult:
    """One ranked KB hit. There is deliberately NO raw ``title``/``content`` attribute: the sole
    content-bearing field is ``untrusted`` — the section body already wrapped in the F1 nonce envelope
    — so no code path can hand raw KB text to a prompt unframed. ``resource_id``/``section_path`` are
    structural references (safe to log/route), ``score``/``rank`` are the retrieval metadata."""

    resource_id: str
    section_path: str
    score: float
    rank: int
    untrusted: str   # [UNTRUSTED]-framed body (title + content); the only text safe to place in a prompt


@dataclass(frozen=True)
class LookupResponse:
    """The outcome of a :func:`lookup`. ``results`` are top-ranked hits, each independently framed;
    ``ambiguous`` / ``used_tiebreak`` report whether the injected LLM tiebreak was consulted."""

    query: str
    resource: Optional[str]
    total_candidates: int
    ambiguous: bool
    used_tiebreak: bool
    results: list[LookupResult]

    def prompt_context(self) -> str:
        """Every result's already-framed ``untrusted`` block, concatenated. This is the ONLY thing a
        caller should splice into a Claude prompt — every character of KB body is inside a marker pair."""
        return "\n\n".join(r.untrusted for r in self.results)


def _render_untrusted(e: CorpusEntry, rank: int, score: float) -> LookupResult:
    body = f"[{e.resource_id or 'kb'}] {e.section_path}\n{e.title}\n\n{e.content}".strip()
    return LookupResult(
        resource_id=e.resource_id,
        section_path=e.section_path,
        score=round(score, 6),
        rank=rank,
        untrusted=wrap_untrusted(body, label=UNTRUSTED_LABEL),
    )


# ---------------------------------------------------------------------------------------------------
# the injected LLM tiebreak — SELECTS among ranked candidates, can never inject content
# ---------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class TiebreakCandidate:
    """What the injected tiebreak sees for one candidate: its stable ``index`` plus structural refs and
    an [UNTRUSTED]-framed inline preview (so even the tiebreak model reads KB text as inert DATA)."""

    index: int
    resource_id: str
    section_path: str
    preview: str   # wrap_untrusted_inline of the section body


# tiebreak(query, candidates) -> the chosen candidate index, or None to defer to the lexical order. It
# is consulted ONLY on a genuinely ambiguous query and may return only an index into the candidate list;
# anything else (out of range, wrong type, an exception) falls back to the deterministic lexical top.
TiebreakFn = Callable[[str, "list[TiebreakCandidate]"], Any]


def _apply_tiebreak(query: str, ranked: list[tuple[float, CorpusEntry]],
                    tiebreak: TiebreakFn) -> Optional[int]:
    """Consult the injected tiebreak over the top ``TIEBREAK_POOL`` candidates. Returns a validated
    index into ``ranked`` (0-based) or ``None`` to keep the lexical order. Totally fail-closed: any bad
    return or exception yields ``None`` (deterministic order wins), and the model can only pick an
    already-ranked candidate — it never adds content or alters a score."""
    pool = ranked[:TIEBREAK_POOL]
    candidates = [
        TiebreakCandidate(
            index=i,
            resource_id=e.resource_id,
            section_path=e.section_path,
            preview=wrap_untrusted_inline(f"{e.title} {e.content}"[:400], label=UNTRUSTED_LABEL),
        )
        for i, (_score, e) in enumerate(pool)
    ]
    try:
        choice = tiebreak(query, candidates)
    except Exception:  # noqa: BLE001 — a tiebreak error selects nothing (fall back to lexical order)
        return None
    if isinstance(choice, bool):     # bool is an int subclass — never treat True/False as an index
        return None
    if isinstance(choice, int) and 0 <= choice < len(pool):
        return choice
    return None


# ---------------------------------------------------------------------------------------------------
# the public entry point
# ---------------------------------------------------------------------------------------------------


def lookup(
    query: Any,
    resource: Any = None,
    *,
    corpus: Any,
    tiebreak: Optional[TiebreakFn] = None,
    top_k: int = DEFAULT_TOP_K,
) -> LookupResponse:
    """Rank the provided ``corpus`` against ``query`` and return the top ``top_k`` sections, each body
    wrapped in the F1 ``[UNTRUSTED]`` envelope.

    ``resource`` optionally restricts the search to one ``resource_id`` (case-insensitive). ``corpus``
    is the injected static corpus (a list of entries or a zero-arg callable returning one — the live
    crawl is deferred). ``tiebreak`` is the injected LLM tiebreak, consulted ONLY when the query is
    genuinely ambiguous (``> AMBIGUITY_MIN_CANDIDATES`` candidates AND top score
    ``< AMBIGUITY_SCORE_CEILING``); it may only reorder the already-ranked candidates.

    Total: a malformed query/resource/corpus/entry degrades to an empty response — never a raise. The
    returned sections are advisory retrieval context, not facts and not authorizations."""
    # A non-string query is malformed input → no signal (never coerced into a spurious search).
    if not isinstance(query, str):
        return LookupResponse("", None, 0, False, False, [])
    q = query
    # A resource filter that is present but not a usable string is an ambiguous request → no signal.
    if resource is not None and not (isinstance(resource, str) and resource.strip()):
        return LookupResponse(q, None, 0, False, False, [])
    res_filter = resource.strip().lower() if isinstance(resource, str) else None

    entries = _iter_corpus(corpus)
    if res_filter:
        entries = [e for e in entries if e.resource_id.lower() == res_filter]

    try:
        k = int(top_k)
    except Exception:  # noqa: BLE001
        k = DEFAULT_TOP_K
    if k <= 0:
        k = DEFAULT_TOP_K

    if not q.strip() or not entries:
        return LookupResponse(q, res_filter, len(entries), False, False, [])

    # Deterministic lexical ranking. Ties break by (resource_id, section_path) so the order is stable
    # and reproducible for the SAME corpus regardless of its input order — no wallclock, no RNG. A
    # section with zero lexical overlap is dropped (no signal), never returned as a spurious hit.
    scored = [(s, e) for s, e in ((_rank_score(q, e), e) for e in entries) if s > 0.0]
    scored.sort(key=lambda se: (-se[0], se[1].resource_id, se[1].section_path))
    if not scored:
        return LookupResponse(q, res_filter, len(entries), False, False, [])

    top_score = scored[0][0]
    ambiguous = len(scored) > AMBIGUITY_MIN_CANDIDATES and top_score < AMBIGUITY_SCORE_CEILING
    used_tiebreak = False
    if ambiguous and tiebreak is not None:
        chosen = _apply_tiebreak(q, scored, tiebreak)
        if chosen is not None and chosen != 0:
            picked = scored.pop(chosen)
            scored.insert(0, picked)
            used_tiebreak = True

    results = [_render_untrusted(e, rank=i, score=score)
               for i, (score, e) in enumerate(scored[:k])]
    return LookupResponse(q, res_filter, len(entries), ambiguous, used_tiebreak, results)
