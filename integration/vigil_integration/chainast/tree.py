"""
chainast.tree — the reversible AST + its LOSSLESS byte-identical round-trip (VIGIL-FUSION F7, §5 C6).

``parse`` is a PURE, deterministic, TOTAL projection of a contiguous span of signed spine records into
a typed tree ``ChainAST → ChainSection[] → {Header, BodyPair[]}``; ``render`` flattens it back to the
exact record list in the exact original order. Because the tree only GROUPS the original record
objects (never rewrites them), the round-trip is byte-identical BY CONSTRUCTION:

    to_canonical_bytes(render(parse(records))) == to_canonical_bytes(normalize(records))

— the sovereign re-executability guarantee (anyone re-derives the same bytes from the same span). The
AST is a VIEW; it is never a mutation of the append-only spine.

The parser is total: ANY record sequence — including malformed ones (a mid-chain system message, two
consecutive humans, an orphan tool response with no preceding AI) — is placed losslessly, so render
always reproduces the input. ``validate`` reports the pentagi invariant violations WITHOUT raising, and
``repair`` is an EXPLICIT, non-lossless force-mode transform (it changes bytes on purpose).

Import-clean: pydantic + .model + stdlib only.
"""

from __future__ import annotations

from typing import Any, Optional, Union

from pydantic import BaseModel, Field

from .model import (
    FALLBACK_RESPONSE_CONTENT,
    SUMMARIZATION_TOOL_NAME,
    SUMMARIZED_CONTENT_PREFIX,
    BodyPairType,
    ChainRecord,
    MessageRole,
    Veracity,
    normalize,
    record_bytes,
    record_confirmed,
)


# --- AST node types -----------------------------------------------------------------------------


class Header(BaseModel):
    """A section header: an optional System + an optional Human message that open a turn."""

    system: Optional[ChainRecord] = None
    human: Optional[ChainRecord] = None

    def records(self) -> list[ChainRecord]:
        out: list[ChainRecord] = []
        if self.system is not None:
            out.append(self.system)
        if self.human is not None:
            out.append(self.human)
        return out


class BodyPair(BaseModel):
    """One AI message plus its tool-response messages, typed and veracity-tagged.

    ``ai`` is ``None`` only in a degenerate pair holding orphan tool responses (a malformed chain kept
    lossless). ``pair_type`` and ``veracity`` are DERIVED at parse time and stored; they live on the
    node, never on the records, so they can never perturb the byte-identical round-trip."""

    ai: Optional[ChainRecord] = None
    tool_responses: list[ChainRecord] = Field(default_factory=list)
    pair_type: BodyPairType = BodyPairType.COMPLETION
    veracity: Veracity = Veracity.LEAD

    def records(self) -> list[ChainRecord]:
        out: list[ChainRecord] = []
        if self.ai is not None:
            out.append(self.ai)
        out.extend(self.tool_responses)
        return out

    @property
    def is_fact(self) -> bool:
        """A body-pair is a FACT only when tagged FACT (oracle-confirmed). A SUMMARY/LEAD is never a
        fact — the sovereign guarantee at the context layer."""
        return self.veracity == Veracity.FACT

    @property
    def is_summary(self) -> bool:
        return self.pair_type == BodyPairType.SUMMARIZATION

    def byte_size(self) -> int:
        return sum(len(record_bytes(r)) for r in self.records())

    def seq_span(self) -> tuple[int, int]:
        seqs = [r.seq for r in self.records()]
        return (min(seqs), max(seqs)) if seqs else (0, 0)


class ChainSection(BaseModel):
    """A header plus the body-pairs of one turn."""

    header: Header = Field(default_factory=Header)
    body_pairs: list[BodyPair] = Field(default_factory=list)

    def records(self) -> list[ChainRecord]:
        out = self.header.records()
        for bp in self.body_pairs:
            out.extend(bp.records())
        return out

    def byte_size(self) -> int:
        return sum(len(record_bytes(r)) for r in self.records())


class ChainAST(BaseModel):
    """The root of a reversible reasoning/tool-call AST — a pure typed projection over a span of signed
    spine records. ``records()`` (a.k.a. render) flattens back to the exact original wire order."""

    sections: list[ChainSection] = Field(default_factory=list)

    def records(self) -> list[ChainRecord]:
        return render(self)

    def body_pairs(self) -> list[BodyPair]:
        return [bp for s in self.sections for bp in s.body_pairs]

    def last_body_pair(self) -> Optional[BodyPair]:
        """The most recent AI+tool block — the one compaction must NEVER summarize (it protects the
        Claude extended-thinking signature the provider API requires verbatim)."""
        for s in reversed(self.sections):
            if s.body_pairs:
                return s.body_pairs[-1]
        return None

    def byte_size(self) -> int:
        return sum(s.byte_size() for s in self.sections)


# --- veracity / pair-type derivation ------------------------------------------------------------


def is_summarized(pair: BodyPair) -> bool:
    """Whether a body-pair is an (append-only) summarization block — pentagi's ``containsSummarizedContent``.
    Detected structurally: the AI record carries the synthetic summarization tool call, OR a summary
    citation, OR a tool response marked with the summarized-content prefix. Drives idempotency (a
    re-run of compaction over an already-compacted chain is a no-op) and forces the SUMMARY tag."""
    ai = pair.ai
    if ai is not None:
        if ai.summary_citation is not None:
            return True
        for tc in ai.tool_calls:
            if getattr(tc, "name", "") == SUMMARIZATION_TOOL_NAME:
                return True
    for tr in pair.tool_responses:
        if tr.summary_citation is not None:
            return True
        if isinstance(tr.content, str) and tr.content.startswith(SUMMARIZED_CONTENT_PREFIX):
            return True
    return False


def _classify_pair_type(pair: BodyPair) -> BodyPairType:
    if is_summarized(pair):
        return BodyPairType.SUMMARIZATION
    ai = pair.ai
    has_calls = bool(ai is not None and ai.tool_calls)
    if has_calls or pair.tool_responses:
        return BodyPairType.REQUEST_RESPONSE
    return BodyPairType.COMPLETION


def _classify_veracity(pair: BodyPair, pair_type: BodyPairType) -> Veracity:
    # A summarization pair is ALWAYS SUMMARY and can NEVER be a FACT — even if its records lie about
    # their status (status="fact" + a forged evidence_ref). This is the load-bearing sovereign check:
    # a lossy, non-authoritative summary must never masquerade as an oracle-confirmed fact.
    if pair_type == BodyPairType.SUMMARIZATION:
        return Veracity.SUMMARY
    if any(record_confirmed(r) for r in pair.records()):
        return Veracity.FACT
    return Veracity.LEAD


def _tag_pair(pair: BodyPair) -> BodyPair:
    pair.pair_type = _classify_pair_type(pair)
    pair.veracity = _classify_veracity(pair, pair.pair_type)
    return pair


# --- parse (total, lossless) --------------------------------------------------------------------


def parse(records: Any) -> ChainAST:
    """Project a span of records into a typed ``ChainAST``. Pure, deterministic, TOTAL — never raises.

    Every record is placed into exactly one slot (a section header's system/human, a body-pair's AI, or
    a body-pair's tool responses) strictly in input order, so :func:`render` reproduces the input
    byte-for-byte. A malformed sequence is still projected losslessly: a mid-chain system opens a new
    section, a second human opens a new section, an orphan tool response gets a degenerate ``ai=None``
    pair. Validity is a SEPARATE, non-raising concern (:func:`validate`)."""
    recs = normalize(records)
    ast = ChainAST()
    cur: Optional[ChainSection] = None
    cur_pair: Optional[BodyPair] = None

    def new_section(*, system: Optional[ChainRecord] = None,
                    human: Optional[ChainRecord] = None) -> ChainSection:
        nonlocal cur, cur_pair
        cur = ChainSection(header=Header(system=system, human=human))
        ast.sections.append(cur)
        cur_pair = None
        return cur

    for rec in recs:
        role = rec.role
        if role == MessageRole.SYSTEM:
            # a system message always opens a new section (a mid-chain one is a violation validate
            # flags, but it is still placed losslessly here).
            new_section(system=rec)
        elif role == MessageRole.HUMAN:
            # attach to the current header only if the section is fresh (a system-only header, no human,
            # no body yet); otherwise this human opens the next turn.
            if (cur is not None and cur.header.human is None and not cur.body_pairs):
                cur.header.human = rec
            else:
                new_section(human=rec)
        elif role == MessageRole.AI:
            if cur is None:
                new_section()
            cur_pair = BodyPair(ai=rec)
            cur.body_pairs.append(cur_pair)  # type: ignore[union-attr]
        else:  # MessageRole.TOOL — a tool response
            if cur is None:
                new_section()
            if cur_pair is None:
                cur_pair = BodyPair(ai=None)          # orphan response → degenerate pair (lossless)
                cur.body_pairs.append(cur_pair)       # type: ignore[union-attr]
            cur_pair.tool_responses.append(rec)

    for section in ast.sections:
        for pair in section.body_pairs:
            _tag_pair(pair)
    return ast


def render(ast: ChainAST) -> list[ChainRecord]:
    """Flatten the AST back to the exact original wire order (pentagi ``Messages()``). Total: tolerates
    a hand-built/partial tree. This is the inverse of :func:`parse` — grouping only, never rewriting —
    so ``render(parse(x))`` is byte-identical to ``normalize(x)``."""
    out: list[ChainRecord] = []
    if not isinstance(ast, ChainAST):
        return out
    for section in ast.sections:
        out.extend(section.header.records())
        for pair in section.body_pairs:
            out.extend(pair.records())
    return out


# --- validation (pentagi invariants; total, non-raising) ----------------------------------------


class ValidationReport(BaseModel):
    """The result of :func:`validate` — never an exception. ``ok`` is True iff no invariant was
    violated; ``issues`` enumerates every violation found (for repair/telemetry)."""

    ok: bool = True
    issues: list[str] = Field(default_factory=list)


def validate(chain: Union[ChainAST, Any]) -> ValidationReport:
    """Check pentagi's structural invariants over a chain (an AST or a record list), fail-safe (never
    raises): (1) the chain opens with a system or human message; (2) no mid-chain system message; (3) no
    consecutive human messages; (4) every AI tool call has a matching tool response by id and every tool
    response answers a known call. A total function — it REPORTS problems, it does not throw."""
    recs = render(chain) if isinstance(chain, ChainAST) else normalize(chain)
    issues: list[str] = []
    if recs:
        if recs[0].role not in (MessageRole.SYSTEM, MessageRole.HUMAN):
            issues.append(f"chain must open with a system or human message, not {recs[0].role.value}")
        prev: Optional[MessageRole] = None
        defined_ids: set[str] = set()
        open_calls: dict[str, int] = {}
        for i, r in enumerate(recs):
            if r.role == MessageRole.SYSTEM and i != 0:
                issues.append(f"mid-chain system message at seq {r.seq}")
            if r.role == MessageRole.HUMAN and prev == MessageRole.HUMAN:
                issues.append(f"consecutive human messages at seq {r.seq}")
            if r.role == MessageRole.AI:
                for tc in r.tool_calls:
                    if tc.id:
                        defined_ids.add(tc.id)
                        open_calls[tc.id] = r.seq
            elif r.role == MessageRole.TOOL:
                if not r.tool_call_id:
                    issues.append(f"tool response at seq {r.seq} has no tool_call_id")
                elif r.tool_call_id in open_calls:
                    del open_calls[r.tool_call_id]
                elif r.tool_call_id not in defined_ids:
                    issues.append(f"tool response at seq {r.seq} answers unknown tool_call id "
                                  f"{r.tool_call_id!r}")
            prev = r.role
        for cid in open_calls:
            issues.append(f"tool_call id {cid!r} has no matching tool response")
    return ValidationReport(ok=not issues, issues=issues)


def repair(records: Any) -> list[ChainRecord]:
    """Force-mode repair (pentagi ``NewChainAST(chain, force=true)``): merge consecutive human messages
    and inject a placeholder tool response for every unanswered AI tool call, so the chain becomes
    structurally valid.

    This is an EXPLICIT, NON-LOSSLESS transform — it deliberately changes bytes; the byte-identical
    round-trip guarantee applies to :func:`parse`/:func:`render`, NOT here. Total: never raises. The
    injected placeholder seqs are DERIVED from the answered call's AI seq (``ai_seq`` + a small offset),
    never a wallclock/RNG, so repair stays deterministic and spine-safe."""
    recs = normalize(records)
    merged: list[ChainRecord] = []
    for r in recs:
        if (r.role == MessageRole.HUMAN and merged and merged[-1].role == MessageRole.HUMAN):
            prev = merged[-1]
            joined = prev.content + ("\n" if prev.content and r.content else "") + r.content
            merged[-1] = prev.model_copy(update={"content": joined})
            continue
        merged.append(r)

    answered: set[str] = set()
    for r in merged:
        if r.role == MessageRole.TOOL and r.tool_call_id:
            answered.add(r.tool_call_id)

    out: list[ChainRecord] = []
    for r in merged:
        out.append(r)
        if r.role == MessageRole.AI:
            for off, tc in enumerate(r.tool_calls, start=1):
                if tc.id and tc.id not in answered:
                    answered.add(tc.id)
                    out.append(ChainRecord(seq=r.seq + off, role=MessageRole.TOOL,
                                           tool_call_id=tc.id, name=tc.name,
                                           content=FALLBACK_RESPONSE_CONTENT))
    return out
