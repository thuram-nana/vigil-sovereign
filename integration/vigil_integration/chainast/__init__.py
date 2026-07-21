"""
vigil_integration.chainast — a typed, reversible AST over a reasoning/tool-call chain, with
append-only signature-safe compaction (VIGIL-FUSION F7; pentagi ``pkg/cast``, design-only reimpl, §5 C6).

``model`` is the message leaf + the single canonical byte codec that makes the projection RE-EXECUTABLE.
``tree`` is the reversible AST (``ChainAST → ChainSection[] → {Header, BodyPair[]}``) whose ``parse``/
``render`` round-trip is BYTE-IDENTICAL by construction (grouping only, never rewriting), plus total
validation and an explicit force-mode repair. ``summary`` is APPEND-ONLY Chain-Summary compaction: a new
``Summarization`` record-pair that CITES the ``[start, end]`` RFC-6962 Merkle range it covers (originals
never deleted), hard-preserving the most-recent body-pair (Claude extended-thinking signatures) and
tagging every summary node ``SUMMARY`` — never a FACT. The summarizer LLM is injected and
non-authoritative; nothing here makes anything true or authorizes anything.
"""

from .model import (
    FALLBACK_RESPONSE_CONTENT,
    SUMMARIZATION_KIND,
    SUMMARIZATION_TOOL_NAME,
    SUMMARIZATION_TOOL_QUESTION,
    SUMMARIZED_CONTENT_PREFIX,
    BodyPairType,
    ChainRecord,
    MessageRole,
    SummaryCitation,
    ToolCallSpec,
    Veracity,
    from_canonical_bytes,
    normalize,
    record_bytes,
    record_confirmed,
    to_canonical_bytes,
)
from .summary import (
    CompactionPlan,
    CompactionResult,
    SummarizeHandler,
    SummarizerConfig,
    assemble_compacted,
    compact,
    merkle_root,
    plan_compaction,
)
from .tree import (
    BodyPair,
    ChainAST,
    ChainSection,
    Header,
    ValidationReport,
    is_summarized,
    parse,
    render,
    repair,
    validate,
)

__all__ = [
    # model — leaves + canonical codec + constants
    "MessageRole", "BodyPairType", "Veracity", "ToolCallSpec", "SummaryCitation", "ChainRecord",
    "record_confirmed", "record_bytes", "to_canonical_bytes", "from_canonical_bytes", "normalize",
    "SUMMARIZATION_TOOL_NAME", "SUMMARIZATION_TOOL_QUESTION", "SUMMARIZED_CONTENT_PREFIX",
    "SUMMARIZATION_KIND", "FALLBACK_RESPONSE_CONTENT",
    # tree — reversible AST + round-trip + validation + repair
    "Header", "BodyPair", "ChainSection", "ChainAST", "ValidationReport",
    "parse", "render", "validate", "repair", "is_summarized",
    # summary — append-only compaction + Merkle range citation
    "SummarizerConfig", "CompactionPlan", "CompactionResult", "SummarizeHandler",
    "plan_compaction", "compact", "assemble_compacted", "merkle_root",
]
